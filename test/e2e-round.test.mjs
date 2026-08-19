// End-to-end: three independent participants mix one asset through a live coordinator against a
// live Sequentia node, and the resulting confidential CoinJoin is accepted by real consensus.
//
// This is the test that matters. It exercises the exact protocol module the browser wallet runs
// (../client.mjs), the exact coordinator that will run on the server (../coordinator.mjs), and the
// real validation code — no mocks anywhere in the path. What it proves:
//
//   * a participant can register coins, receive blind signatures, and redeem them anonymously
//   * the assembled transaction balances, blinds every non-fee output, and is accepted
//   * each participant can unblind exactly its own outputs, and the amounts are the ones promised
//   * the chain shows commitments — the denominations and the change are not on it
//
// It needs a sequentiad binary; without one it skips rather than pretending to pass.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, sign as ecSign, createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startNode, setupChain, makeParticipant, mine, findDaemon, GASSET, wifToPrivateKey } from './regtest.mjs';
import { runRound } from '../client.mjs';

const DAEMON = findDaemon();

// A participant's private key, rebuilt from the wallet's WIF as a SEC1 DER EC key so node:crypto can
// sign with it. The browser wallet does the equivalent from its seed.
function keyFromWif(wif) {
  const raw = wifToPrivateKey(wif);
  const der = Buffer.concat([Buffer.from('302e0201010420', 'hex'), raw, Buffer.from('a00706052b8104000a', 'hex')]);
  return createPrivateKey({ key: der, format: 'der', type: 'sec1' });
}

// Everything the protocol client needs from "a wallet", implemented against one node wallet.
function makeHooks(rpc, wallet, base, asset, log) {
  const post = async (path, body) => {
    const res = await fetch(base + path, body
      ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
      : { method: 'GET' });
    const j = await res.json();
    if (!res.ok || j.ok === false) throw new Error(j.error || ('HTTP ' + res.status));
    return j;
  };
  return {
    fetchJson: post,
    sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 300))),
    onStatus: (phase, detail) => log && log(wallet, phase, detail),

    async selectInputs({ asset: a }) {
      const utxos = await rpc('listunspent', [1, 9999999], wallet);
      const mine_ = utxos.filter((u) => u.asset === a && u.amountblinder === '0'.repeat(64));
      return { inputs: mine_.map((u) => ({ txid: u.txid, vout: u.vout, atoms: BigInt(Math.round(u.amount * 1e8)), address: u.address })) };
    },

    async proveOwnership(message, input) {
      const info = await rpc('getaddressinfo', [input.address], wallet);
      const wif = await rpc('dumpprivkey', [input.address], wallet);
      const sig = ecSign('sha256', Buffer.from(message), keyFromWif(wif));
      return { pubkey: info.pubkey, sig: sig.toString('hex') };
    },

    freshAddress: () => rpc('getnewaddress', ['', 'blech32'], wallet),

    // THE GATE. Unblind the coordinator's transaction with this wallet's own blinding key and check
    // that what it pays US is what the round promised — before a signature exists. A coordinator that
    // shorted an output, or paid it to someone else, is caught here and the round simply never
    // completes. (The browser wallet does the same check through lwk_wasm; see coinjoin.js.)
    async verifyAndSign(txHex, ctx) {
      const un = await rpc('unblindrawtransaction', [txHex], wallet);
      const dec = await rpc('decoderawtransaction', [un.hex]);
      const mineScripts = new Map();
      for (const a of [...ctx.mixAddresses, ...(ctx.changeAddress ? [ctx.changeAddress] : [])]) {
        const v = await rpc('validateaddress', [a]);
        mineScripts.set(v.scriptPubKey, a);
      }
      let credited = 0n, found = 0;
      for (const o of dec.vout) {
        if (!o.scriptPubKey || !mineScripts.has(o.scriptPubKey.hex)) continue;
        assert.equal(o.asset, ctx.lane.asset, 'an output paying me is in the wrong asset');
        credited += BigInt(Math.round(o.value * 1e8));
        found++;
      }
      assert.equal(found, mineScripts.size, 'not every output I registered is in the transaction');
      assert.equal(credited, ctx.expectedCredit, 'the transaction does not pay me what the round promised');
      // My own inputs must be there, and no coin of mine that I did not register.
      const outpoints = new Set(dec.vin.map((v) => v.txid + ':' + v.vout));
      for (const i of ctx.inputs) assert.ok(outpoints.has(i.txid + ':' + i.vout), 'my input is missing');
      const signed = await rpc('signrawtransactionwithwallet', [txHex], wallet);
      return signed.hex;
    },
  };
}

test('three participants mix an asset into one confidential CoinJoin', { skip: DAEMON ? false : 'no sequentiad binary', timeout: 300000 }, async (t) => {
  const node = await startNode();
  const cfgDir = mkdtempSync(join(tmpdir(), 'seqcj-cfg-'));
  let coordinator;
  t.after(async () => {
    try { coordinator?.stop(); } catch {}
    await node.stop();
    rmSync(cfgDir, { recursive: true, force: true });
  });

  const { asset } = await setupChain(node.rpc);

  // Fund three participants. Different shapes on purpose: one coin, two coins, one large coin.
  const parts = [
    await makeParticipant(node.rpc, 'p0', { asset, amounts: ['25'] }),
    await makeParticipant(node.rpc, 'p1', { asset, amounts: ['15', '10'] }),
    await makeParticipant(node.rpc, 'p2', { asset, amounts: ['30'] }),
  ];
  await mine(node.rpc, 1);

  // The coordinator: one lane, 10 units per denomination, 0.02 coordination fee, network fee paid by
  // the coordinator in the chain's other asset — a participant mixing this asset never touches it.
  const port = node.port + 700;
  const cfgPath = join(cfgDir, 'config.json');
  writeFileSync(cfgPath, JSON.stringify({
    seq: { rpc: node.url, wallet: 'coord' },
    http: { host: '127.0.0.1', port },
    fee_asset: GASSET,
    fee_rate_atoms_per_vb: 2,
    lanes: [{ asset, denom_atoms: '1000000000', coord_fee_atoms: '1000000', label: 'MIX 10' }],
    round: { input_ms: 4000, output_ms: 20000, sign_ms: 60000, min_participants: 2, max_participants: 3, max_credentials: 4 },
  }, null, 2));
  process.env.SEQCJ_CONFIG = cfgPath;
  process.env.SEQCJ_STATE = join(cfgDir, 'state.json');
  coordinator = await import('../coordinator.mjs');
  coordinator.start();
  await new Promise((r) => setTimeout(r, 1500));           // first tick opens a round

  const base = `http://127.0.0.1:${port}`;
  const results = await Promise.all(parts.map((p) =>
    runRound({ hooks: makeHooks(node.rpc, p.name, base, asset), assetId: asset })));

  // ---- one transaction, and it is the same one for everybody ----------------
  const txid = results[0].txid;
  assert.ok(txid, 'the round produced no transaction');
  for (const r of results) assert.equal(r.txid, txid, 'participants ended up in different transactions');
  assert.deepEqual(results.map((r) => r.denominations), [2, 2, 2]);

  // ---- what the chain can see ----------------------------------------------
  const raw = await node.rpc('getrawtransaction', [txid, true]);
  const explicit = raw.vout.filter((o) => o.value !== undefined);
  assert.equal(explicit.length, 1, 'the only explicit output should be the fee');
  assert.equal(explicit[0].asset, GASSET, 'the fee is paid in the coordinator-funded asset');
  assert.ok(raw.vout.length >= 10, 'expected at least 9 blinded outputs plus the fee');
  for (const o of raw.vout) {
    if (o.value !== undefined) continue;
    assert.ok(o.valuecommitment, 'a non-fee output was left unblinded');
    assert.ok(o.assetcommitment, 'a non-fee output leaks its asset');
  }
  // Four participants' worth of inputs (three mixers plus the coordinator's fee coin).
  assert.equal(raw.vin.length, 5, 'expected 4 participant inputs and 1 coordinator fee input');

  // ---- what each participant can see ---------------------------------------
  await mine(node.rpc, 1);
  for (const [i, p] of parts.entries()) {
    const bal = await node.rpc('getbalance', [], p.name);
    const held = BigInt(Math.round((bal[asset] ?? 0) * 1e8));
    const funded = i === 2 ? 3000000000n : 2500000000n;
    assert.equal(held, funded - 2n * 1000000n, `${p.name} should hold its stake less two coordination fees`);
    const utxos = await node.rpc('listunspent', [1, 9999999], p.name);
    const fromRound = utxos.filter((u) => u.txid === txid);
    assert.equal(fromRound.length, 3, `${p.name} should own two denominations and one change output`);
    for (const u of fromRound) {
      assert.notEqual(u.amountblinder, '0'.repeat(64), 'a coinjoin output was not blinded');
      assert.equal(u.asset, asset);
    }
    assert.equal(fromRound.filter((u) => Math.round(u.amount * 1e8) === 1000000000).length, 2,
      `${p.name} should have exactly two outputs of the round denomination`);
  }

  // ---- the coordinator's own books -----------------------------------------
  const status = await (await fetch(base + '/status')).json();
  assert.equal(status.recent[0].txid, txid);
  assert.equal(status.recent[0].participants, 3);
});
