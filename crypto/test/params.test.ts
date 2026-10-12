import assert from 'node:assert/strict';
import { test } from 'node:test';
import { exactBound, paperBound } from '../src/params.js';

test('the paper bounds reproduce the §3.2 table (k1 = 64, k2 = k3 = 128) within 2%', () => {
  for (const [f, C] of [[0.05, 889], [0.10, 1556], [0.20, 7759]] as const) {
    const b = paperBound(f, 64, 128, 128)!;
    assert.ok(Math.abs(b.C - C) <= C * 0.02, `f = ${f}: ${b.C} vs ${C}`);
  }
  assert.equal(paperBound(0.30, 64, 128, 128), undefined); // The paper's "impossible" column (f ≥ 1 − √0.5).
});

test('exact tails give smaller committees than the paper bounds and grow with redraws and f', () => {
  assert.deepEqual(exactBound(0.05, 64, 128, 128), { C: 489, t: 197 });
  assert.deepEqual(exactBound(0.05, 0, 40, 40), { C: 120, t: 44 });
  assert.ok(exactBound(0.05, 0, 64, 64).C < exactBound(0.05, 64, 64, 64).C);
  assert.ok(exactBound(0.05, 0, 64, 64).C < exactBound(0.10, 0, 64, 64).C);
});

test('packed epochs: unpacking ℓ buckets needs t + ℓ − 1 honest seats, which costs a few seats of committee size', () => {
  const plain = exactBound(0.05, 0, 40, 40), packed = exactBound(0.05, 0, 40, 40, 3);
  assert.ok(packed.C > plain.C && packed.C <= plain.C + 8, `${packed.C} vs ${plain.C}`);
  assert.ok(packed.t >= plain.t);
});
