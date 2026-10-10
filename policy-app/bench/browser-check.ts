import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import { chromium, type Page } from 'playwright-core';

/**
 * Browser check of Capsule Lab (`npm run browser-check`, LocalNet only). It starts its own demo server and drives the
 * real page in headless Chrome. It covers the whole capsule flow, the operator view, a member outage, phone width and
 * dark mode, and fails on any page error. Screenshots go to browser-shots/ (git-ignored). CHROME_PATH overrides the
 * browser (default: Google Chrome on macOS).
 */
const PORT = Number(process.env.PORT ?? 8798), PAGE = `http://127.0.0.1:${PORT}/`;
const OUT = new URL('../../browser-shots/', import.meta.url).pathname;
mkdirSync(OUT, { recursive: true });
const server = spawn(process.execPath, [new URL('../demo/server.js', import.meta.url).pathname], { env: { ...process.env, PORT: String(PORT) }, stdio: 'ignore' });
await new Promise(r => setTimeout(r, 1500));
const log = (s: string) => console.log(`[${new Date().toISOString().slice(11, 19)}] ${s}`);
const browser = await chromium.launch({ headless: true,
  executablePath: process.env.CHROME_PATH ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
const problems: string[] = [];
const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
const page = await context.newPage();
page.on('pageerror', e => problems.push(`pageerror: ${e.message}`));
let refusals = 0; // The API answers refused actions with 400; the page shows them as toasts.
page.on('console', m => { if (m.type() !== 'error') return; if (/status of 400/.test(m.text())) refusals++; else problems.push(`console: ${m.text()}`); });
const shot = async (name: string, p: Page = page) => { await p.screenshot({ path: `${OUT}${name}.png`, fullPage: true }); log(`screenshot ${name}`); };
const toast = async () => (await page.locator('#toast').isVisible()) ? (await page.locator('#toast').textContent()) : '';
const press = async (selector: string, ms = 1500) => { await page.evaluate(() => { document.getElementById('toast')!.hidden = true; }); await page.click(selector); await wait(ms); return toast(); };
const wait = (ms: number) => new Promise(r => setTimeout(r, ms));
const until = async (what: string, f: () => Promise<boolean>, ms = 300_000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (await f()) return; await wait(1000); }
  throw new Error(`Timed out waiting for ${what}`);
};

try {
  await page.goto(PAGE);
  await shot('1-setup');
  await page.fill('#sMembers', '8');
  await page.fill('#sCommittee', '8');
  await page.fill('#sT', '3');
  await page.click('#start');
  await until('the environment', () => page.locator('#lab').isVisible(), 180_000);
  log(`ready: ${await page.locator('#net').textContent()}`);
  await page.selectOption('#rate', '8');
  await shot('2-ready');

  // Lock once a bucket key is attested and the liveness margin allows it.
  await page.fill('#message', 'a synthetic browser-check secret');
    await until('a lockable bucket key', async () => {
    const t = await press('#lock');
    if (t && !/not attested|Liveness margin/.test(t)) throw new Error(`Unexpected lock error: ${t}`);
    return !t && page.locator('#capsuleBody').isVisible();
  }, 400_000);
  log(`locked: ${await page.locator('#cTitle').textContent()} — ${await page.locator('#cStatus').textContent()}`);
  await shot('3-locked');

  // Wrong wallet, then the recipient once the window opens.
  log(`wrong wallet → toast: ${await press('#wrongWallet')}`);
  await until('the access window', async () => /Open/.test((await page.locator('#cStatus').textContent()) ?? ''));
  const requested = await press('#request');
  log(`request → status: ${await page.locator('#cStatus').textContent()}; toast: ${requested || 'none'}`);

  // A copy under another policy, requested too: holders must refuse it.
  await press('#copy', 2000);
  const copyTitle = await page.locator('#cTitle').textContent();
  log(`copy: ${copyTitle}`);
  await until('the copy opening', async () => /Open/.test((await page.locator('#cStatus').textContent()) ?? ''));
  await page.click('#request');
  await shot('4-requested');

  // Back to the original: open after the next handover.
  await page.locator('#capsules [data-capsule="0"]').click();
  await until('the release', async () => {
    await press('#open');
    return page.locator('#recResult .result').isVisible();
  }, 300_000);
  log(`opened: ${(await page.locator('#recResult pre').textContent())}`);
  await shot('5-opened');
  await page.locator('#capsules button', { hasText: 'copy of' }).click();
  await until('the copy refused', async () => /refused/.test((await page.locator('#cStatus').textContent()) ?? ''), 300_000);
  log(`copy status: ${await page.locator('#cStatus').textContent()}`);

  // Operator view, then a member offline and back.
  await page.check('#god');
  await wait(1500);
  await shot('6-operator');
  await page.locator('#members [data-member="2"]').click();
  await wait(2000);
  log(`member 2: ${await page.locator('#members [data-member="2"]').innerText()}`);
  await page.locator('#members [data-member="2"]').click();
  await wait(2000);
  log(`member 2 again: ${await page.locator('#members [data-member="2"]').innerText()}`);
  log(`history rows: ${await page.locator('#history tr').count()}; first: ${(await page.locator('#history tr').nth(1).innerText()).replace(/\s+/g, ' ')}`);

  // Phone width and dark mode on the same server state.
  const variants = [['7-phone', { viewport: { width: 390, height: 844 }, isMobile: true }], ['8-dark', { viewport: { width: 1280, height: 900 }, colorScheme: 'dark' }]] as const;
  for (const [name, options] of variants) {
    const c = await browser.newContext(options), p = await c.newPage();
    p.on('pageerror', e => problems.push(`${name} pageerror: ${e.message}`));
    await p.goto(PAGE);
    await p.waitForSelector('#lab:not([hidden])');
    await wait(1500);
    const overflow = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    log(`${name}: horizontal overflow ${overflow}px`);
    if (overflow > 0) problems.push(`${name}: page scrolls sideways by ${overflow}px`);
    await shot(name, p);
    await c.close();
  }
} catch (e) {
  problems.push(`check: ${e instanceof Error ? e.message : String(e)}`);
  await shot('error').catch(() => {});
} finally {
  await browser.close();
  log(`${refusals} refused API calls shown as toasts`);
  log(problems.length ? `PROBLEMS:\n${problems.join('\n')}` : 'no page errors');
  server.kill();
  process.exitCode = problems.length ? 1 : 0;
}
