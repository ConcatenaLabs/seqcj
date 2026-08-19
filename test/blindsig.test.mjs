// The credential scheme is the whole privacy claim, so it is tested for both halves of what it
// promises: a credential the coordinator issued verifies, and nothing else does.
import test from 'node:test';
import assert from 'node:assert/strict';
import { newRoundKey, signBlinded } from '../rsakey.mjs';
import { blind, unblind, verify, fdh, mgf1, modPow, modInv, fromHex, toHex, bytesToBig } from '../blindsig.mjs';

const KEY = newRoundKey(2048);

test('a blinded nonce round-trips into a verifiable credential', async () => {
  const kept = await blind(KEY.pub);
  const blindedSig = signBlinded(KEY, kept.blinded);
  const cred = await unblind(KEY.pub, blindedSig, kept);
  assert.equal(await verify(KEY.pub, cred), true);
  assert.equal(cred.nonce, toHex(kept.nonce));
});

test('the coordinator never sees the nonce it signs', async () => {
  // The blinded message must be independent of the nonce: blinding the SAME nonce twice must produce
  // two unrelated ciphertexts, otherwise the coordinator could recognise a repeat.
  const nonce = new Uint8Array(32).fill(7);
  const a = await blind(KEY.pub, nonce);
  const b = await blind(KEY.pub, nonce);
  assert.notEqual(a.blinded, b.blinded);
  // and neither reveals the nonce
  assert.ok(!a.blinded.includes('0707070707'));
});

test('a forged signature does not verify', async () => {
  const kept = await blind(KEY.pub);
  const cred = await unblind(KEY.pub, signBlinded(KEY, kept.blinded), kept);
  // flip a byte of the signature
  const bad = { ...cred, sig: (cred.sig.slice(0, -2) + (cred.sig.endsWith('00') ? '01' : '00')) };
  assert.equal(await verify(KEY.pub, bad), false);
  // present the signature against a different nonce
  assert.equal(await verify(KEY.pub, { nonce: toHex(new Uint8Array(32).fill(9)), sig: cred.sig }), false);
  // a signature from another round's key is worthless in this one
  const other = newRoundKey(2048);
  const kept2 = await blind(other.pub);
  const cred2 = await unblind(other.pub, signBlinded(other, kept2.blinded), kept2);
  assert.equal(await verify(KEY.pub, cred2), false);
});

test('unblinding rejects a coordinator that answers with garbage', async () => {
  const kept = await blind(KEY.pub);
  const junk = 'ab'.repeat(KEY.klen);
  await assert.rejects(() => unblind(KEY.pub, junk, kept), /invalid blind signature/);
});

test('the full-domain hash fills the modulus and is deterministic', async () => {
  const nonce = new Uint8Array(32).fill(3);
  const a = await fdh(nonce, 256), b = await fdh(nonce, 256);
  assert.equal(a, b);
  // 255 bytes of MGF1 output: below 2^2040, so always below a 2048-bit modulus, and not a short hash
  // sitting in the low bytes (which is what makes textbook RSA forgeable).
  assert.ok(a < (1n << 2040n));
  assert.ok(a > (1n << 2000n), 'the image should occupy the full domain, not the low 32 bytes');
  const m = await mgf1(nonce, 70);
  assert.equal(m.length, 70);
  assert.notDeepEqual(m.slice(0, 32), m.slice(32, 64));   // MGF1 counter actually advances
});

test('arithmetic helpers agree with the reference implementation', () => {
  assert.equal(modPow(4n, 13n, 497n), 445n);              // RFC-style test vector
  assert.equal(modInv(3n, 11n), 4n);
  assert.throws(() => modInv(4n, 8n), /not invertible/);
  assert.equal(bytesToBig(fromHex('0102')), 258n);
  assert.equal(toHex(fromHex('00ff10')), '00ff10');
});
