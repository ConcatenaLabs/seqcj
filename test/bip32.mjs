// Just enough BIP32/BIP39 to act as a wallet in a test.
//
// The wasm signer derives its own keys from the recovery phrase, so a test that exercises it has to
// derive the SAME key independently to produce the round's ownership proof — otherwise the test
// would be asking the thing under test to vouch for itself. Node has HMAC, PBKDF2 and secp256k1
// public-key derivation; the only arithmetic left is the child-key addition, which is a BigInt add
// modulo the curve order.
//
// Test-only. The browser wallet uses the vendored `btc.js` (scure) for this, and Seqognito uses the
// same code path.

import { createHmac, pbkdf2Sync, createPrivateKey, createPublicKey } from 'node:crypto';

const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SEC1_PREFIX = Buffer.from('302e0201010420', 'hex');
const SEC1_SUFFIX = Buffer.from('a00706052b8104000a', 'hex');

/// A node:crypto private key object for a raw 32-byte secp256k1 scalar.
export function keyObject(raw) {
  return createPrivateKey({ key: Buffer.concat([SEC1_PREFIX, raw, SEC1_SUFFIX]), format: 'der', type: 'sec1' });
}

/// The compressed public key of a raw scalar.
export function compressedPubkey(raw) {
  const jwk = createPublicKey(keyObject(raw)).export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url'), y = Buffer.from(jwk.y, 'base64url');
  return Buffer.concat([Buffer.of(y[31] % 2 ? 3 : 2), x]);
}

const big = (b) => BigInt('0x' + b.toString('hex'));
const to32 = (x) => Buffer.from(x.toString(16).padStart(64, '0'), 'hex');

export function seedFromMnemonic(phrase, passphrase = '') {
  return pbkdf2Sync(phrase.normalize('NFKD'), 'mnemonic' + passphrase.normalize('NFKD'), 2048, 64, 'sha512');
}

export function masterKey(seed) {
  const I = createHmac('sha512', 'Bitcoin seed').update(seed).digest();
  return { key: I.subarray(0, 32), chainCode: I.subarray(32) };
}

function ckd({ key, chainCode }, index) {
  const idx = Buffer.alloc(4);
  idx.writeUInt32BE(index >>> 0);
  const data = index >= 0x80000000
    ? Buffer.concat([Buffer.of(0), key, idx])
    : Buffer.concat([compressedPubkey(key), idx]);
  const I = createHmac('sha512', chainCode).update(data).digest();
  const child = (big(I.subarray(0, 32)) + big(key)) % N;
  if (child === 0n) throw new Error('invalid child key (astronomically unlikely)');
  return { key: to32(child), chainCode: I.subarray(32) };
}

/// Derive a path like "m/84'/1'/0'/0/3" from a recovery phrase.
export function derive(phrase, path) {
  let node = masterKey(seedFromMnemonic(phrase));
  for (const part of path.split('/').slice(1)) {
    const hardened = part.endsWith("'") || part.endsWith('h');
    const n = parseInt(hardened ? part.slice(0, -1) : part, 10);
    node = ckd(node, hardened ? n + 0x80000000 : n);
  }
  return node;
}
