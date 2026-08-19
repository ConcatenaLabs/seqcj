// RSA blind signatures (Chaum), the credential primitive that makes a CoinJoin round unlinkable.
//
// WHY THIS EXISTS. In a round the coordinator must be convinced of two things that, taken together,
// it must NOT be able to connect:
//
//   1. "this participant registered inputs worth k denominations"      (input registration)
//   2. "this output is owed one denomination"                          (output registration)
//
// If the same identity asserted both, the coordinator would know which output belongs to which input
// and the mix would buy nothing. So (1) is paid for in blind signatures: the participant sends a
// BLINDED random nonce, the coordinator signs it without seeing it, and later — on a separate
// connection, in a separate phase — presents the UNBLINDED (nonce, signature) pair as an anonymous
// bearer credential. The coordinator can verify the credential is one it issued, and cannot tell
// WHICH issuance it came from. This is Wasabi 1.0 / ZeroLink's scheme, unchanged; the interesting
// part on Sequentia is what the transaction then looks like (see coordinator.mjs).
//
// SCHEME. Textbook RSA-FDH blind signatures:
//   client       m = FDH(nonce);  r <- random, gcd(r,n)=1;  blinded = m * r^e mod n
//   coordinator  s_blinded = blinded^d mod n                (it learns nothing: r masks m perfectly)
//   client       s = s_blinded * r^-1 mod n                 (a valid signature on m)
//   verifier     s^e == FDH(nonce) mod n
//
// One RSA keypair per (round, lane) means a credential cannot be replayed into another round or
// moved to a lane with a larger denomination — the binding is the key itself, not a field anyone
// could forge. Each nonce is single-use; the coordinator keeps the spent set for the round's life.
//
// FDH = MGF1-SHA256 truncated to (keylen - 1) bytes, so the image is uniform in [0, 2^(8(k-1))) and
// therefore always < n. A plain "hash into the low 32 bytes" would be forgeable (small-exponent /
// multiplicative attacks); full-domain hashing is what the security proof needs.
//
// THIS FILE IS ISOMORPHIC. No imports, no node: builtins, no globals beyond WebCrypto's SHA-256 —
// the coordinator and the browser wallet run the identical code. The coordinator's private half
// (the d exponent) is never here: it uses OpenSSL through node:crypto (coordinator.mjs), so no
// hand-rolled arithmetic ever touches the secret exponent.

const enc = new TextEncoder();

// ---- small helpers ----------------------------------------------------------
export function bytesToBig(b) {
  let x = 0n;
  for (const v of b) x = (x << 8n) | BigInt(v);
  return x;
}
export function bigToBytes(x, len) {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  if (x !== 0n) throw new Error('integer does not fit in ' + len + ' bytes');
  return out;
}
export const toHex = (b) => [...b].map((v) => v.toString(16).padStart(2, '0')).join('');
export function fromHex(h) {
  const s = String(h || '').replace(/^0x/, '');
  if (s.length % 2) throw new Error('odd-length hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(b)) throw new Error('bad hex');
    out[i] = b;
  }
  return out;
}

async function sha256(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(d);
}

// modular exponentiation, square-and-multiply. Only ever called with the PUBLIC exponent (e, and
// e = 65537 in practice), so no secret drives the exponent path. The blinding factor r is secret but
// only enters as a base, where the multiplication sequence is fixed by e.
export function modPow(base, exp, mod) {
  let result = 1n, b = base % mod, e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

// modular inverse via the extended Euclidean algorithm; throws when not invertible (which for a
// random r < n of an RSA modulus means we hit a factor — retry with a fresh r).
export function modInv(a, m) {
  let [old_r, r] = [((a % m) + m) % m, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error('not invertible');
  return ((old_s % m) + m) % m;
}

// ---- full-domain hash -------------------------------------------------------
// MGF1-SHA256(seed) truncated to (klen-1) bytes, per PKCS#1's mask generation function. `klen` is
// the modulus length in bytes; the result is strictly below 2^(8*(klen-1)) <= n.
export async function mgf1(seed, outLen) {
  const out = new Uint8Array(outLen);
  let off = 0;
  for (let counter = 0; off < outLen; counter++) {
    const c = new Uint8Array(seed.length + 4);
    c.set(seed, 0);
    c[seed.length] = (counter >>> 24) & 0xff;
    c[seed.length + 1] = (counter >>> 16) & 0xff;
    c[seed.length + 2] = (counter >>> 8) & 0xff;
    c[seed.length + 3] = counter & 0xff;
    const h = await sha256(c);
    const take = Math.min(h.length, outLen - off);
    out.set(h.subarray(0, take), off);
    off += take;
  }
  return out;
}

// The message the signature actually covers. Domain-separated so a signature issued by a seqcj
// coordinator can never be reinterpreted as a signature over something else that happens to share a
// modulus.
export async function fdh(nonce, klen) {
  const seed = new Uint8Array(enc.encode('seqcj-credential-v1|').length + nonce.length);
  seed.set(enc.encode('seqcj-credential-v1|'), 0);
  seed.set(nonce, enc.encode('seqcj-credential-v1|').length);
  return bytesToBig(await mgf1(seed, klen - 1));
}

// ---- the client half --------------------------------------------------------
export function randomNonce() {
  const n = new Uint8Array(32);
  crypto.getRandomValues(n);
  return n;
}

// Blind a fresh nonce under the round key. Returns what to send (`blinded`) and what to keep
// (`nonce`, `factor`) — the kept half is what turns the coordinator's answer into a credential, and
// it must never leave the client before the output-registration phase.
export async function blind(pub, nonce = randomNonce()) {
  const n = BigInt('0x' + pub.n), e = BigInt('0x' + pub.e);
  const klen = fromHex(pub.n).length;
  const m = await fdh(nonce, klen);
  for (let attempt = 0; attempt < 8; attempt++) {
    const rb = new Uint8Array(klen);
    crypto.getRandomValues(rb);
    rb[0] &= 0x7f;                       // keep r < n without a rejection loop biased at the top
    const r = bytesToBig(rb) % n;
    if (r < 2n) continue;
    let rinv;
    try { rinv = modInv(r, n); } catch { continue; }
    const blinded = (m * modPow(r, e, n)) % n;
    return { nonce, factor: rinv, blinded: toHex(bigToBytes(blinded, klen)), klen };
  }
  throw new Error('could not draw a usable blinding factor');
}

// Turn the coordinator's blinded signature into the real one, and check it before trusting it — a
// coordinator that returns garbage here must be caught NOW, while the failure is still merely a
// failed registration rather than an output we cannot claim later.
export async function unblind(pub, blindedSigHex, kept) {
  const n = BigInt('0x' + pub.n), e = BigInt('0x' + pub.e);
  const klen = fromHex(pub.n).length;
  const sb = bytesToBig(fromHex(blindedSigHex));
  const s = (sb * kept.factor) % n;
  const m = await fdh(kept.nonce, klen);
  if (modPow(s, e, n) !== m) throw new Error('coordinator returned an invalid blind signature');
  return { nonce: toHex(kept.nonce), sig: toHex(bigToBytes(s, klen)) };
}

// ---- verification (both sides) ---------------------------------------------
export async function verify(pub, credential) {
  try {
    const n = BigInt('0x' + pub.n), e = BigInt('0x' + pub.e);
    const klen = fromHex(pub.n).length;
    const s = bytesToBig(fromHex(credential.sig));
    if (s <= 1n || s >= n) return false;
    const m = await fdh(fromHex(credential.nonce), klen);
    return modPow(s, e, n) === m;
  } catch { return false; }
}
