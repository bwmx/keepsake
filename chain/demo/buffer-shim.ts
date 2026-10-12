// Browsers have no Buffer; the shared modules use it. esbuild injects this into the client bundle.
import { Buffer } from 'buffer';

// The polyfill lacks Node's 'base64url' encoding, which the shared modules use: translate it to and from base64.
const from = Buffer.from, toString = Buffer.prototype.toString;
const toBase64 = (s: string) => s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=');
Buffer.from = function (value: unknown, encoding?: unknown, length?: unknown) {
  const call = from as (...a: unknown[]) => Buffer;
  if (encoding === 'base64url' && typeof value === 'string') return call.call(Buffer, toBase64(value), 'base64');
  return call.call(Buffer, value, encoding, length);
} as typeof Buffer.from;
Buffer.prototype.toString = function (this: Buffer, encoding?: string, start?: number, end?: number) {
  if (encoding === 'base64url') return toString.call(this, 'base64', start, end).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return toString.call(this, encoding as BufferEncoding, start, end);
};

export { Buffer };
