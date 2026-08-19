// The coordinator's half of the blind-signature scheme: key generation and the raw RSA private
// operation. Node-only (blindsig.mjs, which the browser also runs, deliberately contains no secret
// arithmetic).
//
// The private op goes through OpenSSL with RSA_NO_PADDING rather than a hand-rolled modPow. That is
// not a convenience: OpenSSL's RSA implementation blinds the exponentiation internally and runs in
// constant time, so the signing key is not leaked to whoever can measure how long a round takes to
// answer. A textbook square-and-multiply over the secret exponent would be.
//
// PADDING. RSA_NO_PADDING is exactly what a blind signature needs — the message the coordinator
// receives is already a blinded full-domain hash, and any padding scheme would destroy the
// multiplicative structure the unblinding depends on. It is safe HERE because the value being signed
// is FDH(nonce) * r^e: the client can never steer the coordinator into signing a structured message,
// and every signature the coordinator issues is worth exactly one denomination by construction.

import { generateKeyPairSync, privateDecrypt, constants } from 'node:crypto';

// A fresh keypair per (round, lane). Rotation per round is what stops a credential minted in one
// round from being spent in another, and what stops a credential for a small denomination from being
// presented against a large one — the key IS the binding.
export function newRoundKey(modulusLength = 2048) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength });
  const jwk = publicKey.export({ format: 'jwk' });
  const n = Buffer.from(jwk.n, 'base64url');
  const e = Buffer.from(jwk.e, 'base64url');
  return {
    priv: privateKey,
    klen: n.length,
    pub: { n: n.toString('hex'), e: e.toString('hex') },
  };
}

// Sign one blinded message. Rejects anything that is not a canonical klen-byte integer below the
// modulus: OpenSSL would refuse it anyway, and a clear error is better than a 500 from deep inside
// the crypto layer.
export function signBlinded(key, blindedHex) {
  const buf = Buffer.from(String(blindedHex || ''), 'hex');
  if (buf.length !== key.klen) throw new Error(`blinded message must be ${key.klen} bytes`);
  const n = BigInt('0x' + key.pub.n);
  const m = BigInt('0x' + (buf.toString('hex') || '0'));
  if (m <= 1n || m >= n) throw new Error('blinded message out of range');
  return privateDecrypt({ key: key.priv, padding: constants.RSA_NO_PADDING }, buf).toString('hex');
}
