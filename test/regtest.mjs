// A throwaway Sequentia regtest network for the end-to-end test: one daemon, one asset, and as many
// participant wallets as the test asks for. Everything lives in a temp directory that is deleted
// with the test.
//
// This is a REAL node running the real consensus and policy code — the point of the end-to-end test
// is that a coinjoin round is accepted by the same validation that will judge it on the testnet, not
// by a mock that agrees with us.

import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';

export const GASSET = 'b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23';

export function findDaemon() {
  const candidates = [
    process.env.SEQUENTIAD,
    join(homedir(), 'Sequentia', 'src', 'sequentiad'),
    join(homedir(), 'Sequentia', 'src', 'elementsd'),
  ].filter(Boolean);
  return candidates.find((p) => existsSync(p)) || null;
}

export function makeRpc(url) {
  return async (method, params = [], wallet) => {
    const u = new URL(url);
    const auth = 'Basic ' + Buffer.from(decodeURIComponent(u.username) + ':' + decodeURIComponent(u.password)).toString('base64');
    u.username = ''; u.password = '';
    const base = u.toString().replace(/\/$/, '') + (wallet ? '/wallet/' + encodeURIComponent(wallet) : '');
    const res = await fetch(base, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: auth },
      body: JSON.stringify({ jsonrpc: '1.0', id: 'test', method, params }),
      signal: AbortSignal.timeout(120000),
    });
    const j = await res.json().catch(() => ({ error: { message: 'bad json (HTTP ' + res.status + ')' } }));
    if (j.error) throw new Error(`${method}: ${j.error.message || JSON.stringify(j.error)}`);
    return j.result;
  };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Start a daemon on a private port pair. `initialfreecoins` + `connect_genesis_outputs` gives the
// first wallet something to spend without mining a subsidy (this chain has none — all SEQ is
// pre-mined, so a regtest has to be seeded at genesis).
export async function startNode({ port = 19998 + Math.floor(Math.random() * 500) * 2 } = {}) {
  const bin = findDaemon();
  if (!bin) throw new Error('no sequentiad binary found (set SEQUENTIAD)');
  const dir = mkdtempSync(join(tmpdir(), 'seqcj-regtest-'));
  writeFileSync(join(dir, 'elements.conf'), [
    'chain=elementsregtest',
    '[elementsregtest]',
    'server=1', 'listen=0', 'validatepegin=0', 'txindex=1',
    'rpcuser=seqcj', 'rpcpassword=seqcjtest',
    'rpcport=' + port, 'port=' + (port + 1),
    'fallbackfee=0.00001',
    'blindedaddresses=0',            // Sequentia is transparent by default; confidentiality is opt-in
    'initialfreecoins=10000000000',
    'con_blocksubsidy=0',
    'con_connect_genesis_outputs=1',
    'con_any_asset_fees=1',          // the open fee market, as the real chains run it
    'defaultpeggedassetname=gasset',
    'anyonecanspendaremine=1',
  ].join('\n') + '\n');
  const proc = spawn(bin, ['-datadir=' + dir], { stdio: 'ignore' });
  const rpc = makeRpc(`http://seqcj:seqcjtest@127.0.0.1:${port}`);
  for (let i = 0; i < 120; i++) {
    try { await rpc('getblockchaininfo'); break; } catch { await sleep(500); }
    if (i === 119) throw new Error('node did not come up');
  }
  const stop = async () => {
    try { await rpc('stop'); } catch {}
    for (let i = 0; i < 40 && !proc.killed; i++) { if (proc.exitCode !== null) break; await sleep(250); }
    try { proc.kill('SIGKILL'); } catch {}
    try { rmSync(dir, { recursive: true, force: true }); } catch {}
  };
  return { rpc, dir, port, stop, url: `http://seqcj:seqcjtest@127.0.0.1:${port}` };
}

// The coordinator's wallet: holds the genesis coins (the fee asset) and issues the asset the round
// will mix.
export async function setupChain(rpc, { issueAmount = '100000' } = {}) {
  await rpc('createwallet', ['coord']);
  await rpc('rescanblockchain', [0], 'coord');           // the genesis outputs predate the wallet
  const addr = await rpc('getnewaddress', [], 'coord');
  await rpc('generatetoaddress', [101, addr], 'coord');
  const iss = await rpc('issueasset', { assetamount: issueAmount, tokenamount: '1', blind: false, fee_asset: GASSET }, 'coord');
  await rpc('generatetoaddress', [1, addr], 'coord');
  return { asset: iss.asset, coordAddress: addr };
}

export async function mine(rpc, n = 1) {
  const addr = await rpc('getnewaddress', [], 'coord');
  return rpc('generatetoaddress', [n, addr], 'coord');
}

// ---- participant wallets ----------------------------------------------------
// Each participant is a separate node wallet, which is the closest analogue to a separate browser
// wallet: its own keys, its own blinding key, and no visibility into anyone else's.
export async function makeParticipant(rpc, name, { asset, amounts }) {
  await rpc('createwallet', [name]);
  const utxos = [];
  for (const amount of amounts) {
    const addr = await rpc('getnewaddress', [], name);           // transparent (blindedaddresses=0)
    const txid = await rpc('sendtoaddress', { address: addr, amount, assetlabel: asset, fee_asset_label: GASSET }, 'coord');
    utxos.push({ txid, addr });
  }
  return { name, utxos };
}

// ---- WIF -> raw key ---------------------------------------------------------
// The ownership proof is signed with the input's own key, so the test needs the scalar behind an
// address the node wallet generated. Base58check by hand: no dependency, and the wallet does the
// same job from its seed.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function base58decode(s) {
  let x = 0n;
  for (const ch of String(s)) {
    const v = B58.indexOf(ch);
    if (v < 0) throw new Error('bad base58 char ' + ch);
    x = x * 58n + BigInt(v);
  }
  const bytes = [];
  while (x > 0n) { bytes.unshift(Number(x & 0xffn)); x >>= 8n; }
  for (const ch of String(s)) { if (ch === '1') bytes.unshift(0); else break; }
  return Buffer.from(bytes);
}
export function wifToPrivateKey(wif) {
  const d = base58decode(wif);
  const body = d.subarray(0, d.length - 4);            // drop the 4-byte checksum
  let key = body.subarray(1);                          // drop the version byte
  if (key.length === 33 && key[32] === 0x01) key = key.subarray(0, 32);   // compressed marker
  if (key.length !== 32) throw new Error('unexpected WIF payload length ' + key.length);
  return key;
}
