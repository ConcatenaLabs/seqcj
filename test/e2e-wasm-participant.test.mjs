// The BROWSER's path through a round, proven against a real node.
//
// The other end-to-end test drives participants that sign through the node's own wallet. This one
// drives a participant that does what the browser wallet actually does:
//
//   * derives its keys from a recovery phrase with lwk (wasm),
//   * hands out blinded addresses from its own SLIP-77 blinding key,
//   * unblinds the coordinator's transaction with `coinjoinUnblindOutputs` to check what it is owed,
//   * signs its own inputs with `coinjoinSignInputs` — the Elements segwit-v0 sighash implemented in
//     Rust for exactly this.
//
// If the wasm sighash were wrong in any detail, the round would assemble and then be rejected. So
// "the transaction was accepted" IS the assertion. It needs the built wasm package
// (`wasm-pack build --target web --release` in SWK/lwk_wasm); without it the test skips.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { createHash, sign as ecSign } from 'node:crypto';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { startNode, setupChain, makeParticipant, mine, findDaemon, GASSET, wifToPrivateKey } from './regtest.mjs';
import { derive, compressedPubkey, keyObject } from './bip32.mjs';
import { runRound } from '../client.mjs';

const PKG = process.env.LWK_WASM_PKG || join(homedir(), 'SWK', 'lwk_wasm', 'pkg');
const HAVE_WASM = existsSync(join(PKG, 'lwk_wasm.js')) && existsSync(join(PKG, 'lwk_wasm_bg.wasm'));
const DAEMON = findDaemon();
const SKIP = !DAEMON ? 'no sequentiad binary' : (!HAVE_WASM ? 'no built lwk_wasm package' : false);

// A throwaway wallet. Test-only, and worth nothing: it exists for eleven blocks on a regtest chain
// that is deleted when the test ends.
const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const hash160 = (b) => createHash('ripemd160').update(createHash('sha256').update(b).digest()).digest();

test('the wallet wasm path signs a round the node accepts', { skip: SKIP, timeout: 300000 }, async (t) => {
  const wasm = await import(join(PKG, 'lwk_wasm.js'));
  await wasm.default({ module_or_path: readFileSync(join(PKG, 'lwk_wasm_bg.wasm')) });

  const node = await startNode();
  const cfgDir = mkdtempSync(join(tmpdir(), 'seqcj-wasm-'));
  let coordinator;
  t.after(async () => {
    try { coordinator?.stop(); } catch {}
    await node.stop();
    rmSync(cfgDir, { recursive: true, force: true });
  });
  const { asset } = await setupChain(node.rpc);

  // ---- the browser wallet ---------------------------------------------------
  const network = wasm.Network.regtestDefault();
  const signer = new wasm.Signer(new wasm.Mnemonic(PHRASE), network);
  const descriptor = signer.wpkhSlip77Descriptor();
  const wollet = new wasm.Wollet(network, descriptor);
  const addressAt = (i) => wollet.address(i).address();

  // The wallet's own derivation, reproduced independently. If these disagree the rest of the test is
  // meaningless, so it is asserted first.
  const funding = addressAt(0).toUnconfidential().toString();
  const key0 = derive(PHRASE, "m/84'/1'/0'/0/0");
  const spk0 = '0014' + hash160(compressedPubkey(key0.key)).toString('hex');
  const v = await node.rpc('validateaddress', [funding]);
  assert.equal(v.scriptPubKey, spk0, 'independent derivation disagrees with the wallet');

  // ---- fund it --------------------------------------------------------------
  const fundTxid = await node.rpc('sendtoaddress',
    { address: funding, amount: '25.02', assetlabel: asset, fee_asset_label: GASSET }, 'coord');
  await mine(node.rpc, 1);
  const fundTx = await node.rpc('getrawtransaction', [fundTxid, true]);
  const vout = fundTx.vout.findIndex((o) => o.scriptPubKey?.hex === spk0);
  assert.ok(vout >= 0, 'funding output not found');
  const myCoin = { txid: fundTxid, vout, atoms: 2502000000n, asset, spkHex: spk0, chain: 0, index: 0 };

  // A second participant, so the round has the two it requires. This one signs through the node.
  const p1 = await makeParticipant(node.rpc, 'p1', { asset, amounts: ['20.02'] });
  await mine(node.rpc, 1);

  // ---- the coordinator ------------------------------------------------------
  const port = node.port + 800;
  const cfgPath = join(cfgDir, 'config.json');
  writeFileSync(cfgPath, JSON.stringify({
    seq: { rpc: node.url, wallet: 'coord' },
    http: { host: '127.0.0.1', port },
    fee_asset: GASSET, fee_rate_atoms_per_vb: 2,
    lanes: [{ asset, denom_atoms: '1000000000', coord_fee_atoms: '1000000', label: 'MIX 10' }],
    round: { input_ms: 4000, output_ms: 20000, sign_ms: 60000, min_participants: 2, max_participants: 2, max_credentials: 4 },
  }, null, 2));
  process.env.SEQCJ_CONFIG = cfgPath;
  process.env.SEQCJ_STATE = join(cfgDir, 'state.json');
  coordinator = await import('../coordinator.mjs');
  coordinator.start();
  await new Promise((r) => setTimeout(r, 1500));
  const base = `http://127.0.0.1:${port}`;

  const post = async (path, body) => {
    const res = await fetch(base + path, body
      ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
      : { method: 'GET' });
    const j = await res.json();
    if (!res.ok || j.ok === false) throw new Error(j.error || ('HTTP ' + res.status));
    return j;
  };

  // ---- the browser participant's hooks --------------------------------------
  let nextIndex = 1;                       // index 0 holds the coin; outputs go to fresh ones
  let verified = null;
  const wasmHooks = {
    fetchJson: post,
    sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 300))),
    selectInputs: async () => ({ inputs: [myCoin] }),
    proveOwnership: async (message, input) => {
      const k = derive(PHRASE, `m/84'/1'/0'/${input.chain}/${input.index}`);
      return {
        pubkey: compressedPubkey(k.key).toString('hex'),
        sig: ecSign('sha256', Buffer.from(message), keyObject(k.key)).toString('hex'),
      };
    },
    freshAddress: async () => addressAt(nextIndex++).toString(),   // confidential, never reused
    verifyAndSign: async (txHex, ctx) => {
      // Exactly what coinjoin.js does: unblind with our own key, check every output we registered,
      // and only then sign.
      const mine = wasm.coinjoinUnblindOutputs(txHex, descriptor);
      const want = new Map();
      for (const a of ctx.mixAddresses) want.set(new wasm.Address(a).scriptPubkey().toString().toLowerCase(), ctx.denom);
      if (ctx.changeAddress) want.set(new wasm.Address(ctx.changeAddress).scriptPubkey().toString().toLowerCase(), ctx.change);
      assert.equal(mine.length, want.size, 'the wallet unblinded a different number of outputs than it registered');
      for (const o of mine) {
        const expect = want.get(String(o.scriptPubkey).toLowerCase());
        assert.ok(expect !== undefined, 'an output unblinded that I never registered');
        assert.equal(BigInt(o.value), BigInt(expect), 'an output of mine is not the promised amount');
        assert.equal(o.asset, asset, 'an output of mine is in the wrong asset');
      }
      verified = mine;
      return wasm.coinjoinSignInputs({
        txHex, mnemonic: PHRASE,
        inputs: [{ txid: myCoin.txid, vout: myCoin.vout, value: String(myCoin.atoms), spkHex: myCoin.spkHex, chain: 0, index: 0 }],
      }, network);
    },
  };

  // The node-wallet participant (same shape as the other end-to-end test).
  const nodeHooks = {
    fetchJson: post,
    sleep: (ms) => new Promise((r) => setTimeout(r, Math.min(ms, 300))),
    selectInputs: async ({ asset: a }) => {
      const utxos = await node.rpc('listunspent', [1, 9999999], 'p1');
      return { inputs: utxos.filter((u) => u.asset === a).map((u) => ({ txid: u.txid, vout: u.vout, atoms: BigInt(Math.round(u.amount * 1e8)), address: u.address })) };
    },
    proveOwnership: async (message, input) => {
      const info = await node.rpc('getaddressinfo', [input.address], 'p1');
      const raw = wifToPrivateKey(await node.rpc('dumpprivkey', [input.address], 'p1'));
      return { pubkey: info.pubkey, sig: ecSign('sha256', Buffer.from(message), keyObject(raw)).toString('hex') };
    },
    freshAddress: () => node.rpc('getnewaddress', ['', 'blech32'], 'p1'),
    verifyAndSign: async (txHex) => (await node.rpc('signrawtransactionwithwallet', [txHex], 'p1')).hex,
  };

  const [a, b] = await Promise.all([
    runRound({ hooks: wasmHooks, assetId: asset }),
    runRound({ hooks: nodeHooks, assetId: asset }),
  ]);

  // ---- the node is the judge ------------------------------------------------
  assert.equal(a.txid, b.txid);
  const raw = await node.rpc('getrawtransaction', [a.txid, true]);
  assert.ok(raw.txid, 'the round was never broadcast — the wasm signature did not verify');
  assert.equal(a.denominations, 2);
  assert.ok(verified && verified.length === 3, 'the wallet should have unblinded two denominations and its change');
  assert.equal(verified.filter((o) => BigInt(o.value) === 1000000000n).length, 2);
  assert.equal(verified.filter((o) => BigInt(o.value) === 500000000n).length, 1, 'the change should come back blinded');
  // and it is confirmable, not merely relayable
  await mine(node.rpc, 1);
  const conf = await node.rpc('getrawtransaction', [a.txid, true]);
  assert.ok(conf.confirmations >= 1, 'the round did not confirm');
});
