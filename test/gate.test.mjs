// The CoinJoin signing gate.
//
// `verifyRoundOutputs` is the only thing standing between a user and signing a transaction built by
// somebody else. Every case below is a way a dishonest — or merely broken — coordinator could get
// less than it promised into the round, and every one of them must end in a refusal rather than a
// signature. Run with: node --test coinjoin.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyRoundOutputs } from '../client.mjs';

const ASSET = 'aa'.repeat(32);
const OTHER = 'bb'.repeat(32);
const DENOM = 1000000000n;
const MIX_A = '0014' + '11'.repeat(20);
const MIX_B = '0014' + '22'.repeat(20);
const CHANGE = '0014' + '33'.repeat(20);

const out = (script, value, asset = ASSET) => ({ scriptPubkey: script, value: String(value), asset });
const base = (mine, change = 498000000n) => ({
  mine, mixScripts: [MIX_A, MIX_B], changeScript: CHANGE, denom: DENOM, change, asset: ASSET,
});

test('a round that pays exactly what it promised is accepted', () => {
  const credited = verifyRoundOutputs(base([
    out(MIX_A, DENOM), out(CHANGE, 498000000n), out(MIX_B, DENOM),   // order is the coordinator's
  ]));
  assert.equal(credited, 2n * DENOM + 498000000n);
});

test('a missing mixed output is refused', () => {
  assert.throws(() => verifyRoundOutputs(base([out(MIX_A, DENOM), out(CHANGE, 498000000n)])),
    /mixed outputs is missing/);
});

test('a short-changed denomination is refused', () => {
  assert.throws(() => verifyRoundOutputs(base([
    out(MIX_A, DENOM), out(MIX_B, DENOM - 1n), out(CHANGE, 498000000n),
  ])), /not the 1000000000 the round promised/);
});

test('a mixed output in the wrong asset is refused', () => {
  // The subtle one: with confidential outputs the asset is hidden too, so "it is the right amount"
  // is not enough — a round could pay the right number of the wrong thing.
  assert.throws(() => verifyRoundOutputs(base([
    out(MIX_A, DENOM), out(MIX_B, DENOM, OTHER), out(CHANGE, 498000000n),
  ])), /wrong asset/);
});

test('missing or altered change is refused', () => {
  assert.throws(() => verifyRoundOutputs(base([out(MIX_A, DENOM), out(MIX_B, DENOM)])),
    /change output is missing/);
  assert.throws(() => verifyRoundOutputs(base([
    out(MIX_A, DENOM), out(MIX_B, DENOM), out(CHANGE, 497999999n),
  ])), /not the 498000000 I registered/);
});

test('an unexpected output of mine is refused', () => {
  // Not free money: an output we did not register means the round is not the one we agreed to, and
  // the extra one is very likely a de-anonymising marker.
  const extra = '0014' + '44'.repeat(20);
  assert.throws(() => verifyRoundOutputs(base([
    out(MIX_A, DENOM), out(MIX_B, DENOM), out(CHANGE, 498000000n), out(extra, 5n),
  ])), /output of mine I did not register/);
});

test('the same address paid twice is refused', () => {
  assert.throws(() => verifyRoundOutputs(base([
    out(MIX_A, DENOM), out(MIX_A, DENOM), out(MIX_B, DENOM), out(CHANGE, 498000000n),
  ])), /same address of mine twice/);
});

test('change owed but never registered is refused', () => {
  assert.throws(() => verifyRoundOutputs({
    mine: [out(MIX_A, DENOM), out(MIX_B, DENOM)],
    mixScripts: [MIX_A, MIX_B], changeScript: null, denom: DENOM, change: 1n, asset: ASSET,
  }), /no change address was registered/);
});

test('an exact registration needs no change output', () => {
  const credited = verifyRoundOutputs({
    mine: [out(MIX_A, DENOM)], mixScripts: [MIX_A], changeScript: null, denom: DENOM, change: 0n, asset: ASSET,
  });
  assert.equal(credited, DENOM);
});

test('script comparison is case-insensitive but exact otherwise', () => {
  const credited = verifyRoundOutputs({
    mine: [out(MIX_A.toUpperCase(), DENOM)], mixScripts: [MIX_A], changeScript: null,
    denom: DENOM, change: 0n, asset: ASSET,
  });
  assert.equal(credited, DENOM);
  assert.throws(() => verifyRoundOutputs({
    mine: [out('0014' + '11'.repeat(19) + '12', DENOM)], mixScripts: [MIX_A], changeScript: null,
    denom: DENOM, change: 0n, asset: ASSET,
  }), /missing from the round/);
});
