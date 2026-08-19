// A headless participant: joins a round using a Sequentia node wallet.
//
// Two uses, both real. It is how a live coordinator is proven to work end to end against the actual
// testnet rather than a regtest, and it is what a round needs when only one human is awake — an
// anonymity set of one is not a mix, so somebody has to be the second participant.
//
// It performs exactly the same protocol as the wallets (client.mjs, unchanged), with the node wallet
// standing in for the browser's key handling: `dumpprivkey` for the ownership proof,
// `unblindrawtransaction` to check what the round pays it, `signrawtransactionwithwallet` to sign.
// The verification is not skipped because this is a script — a participant that signs without
// checking is the one failure mode that costs money.
//
//   node tools/live-participant.mjs \
//     --rpc http://user:pass@127.0.0.1:18200 --wallet alice \
//     --coordinator https://example/coinjoin --asset <hex> [--denominations 1]

import { createPrivateKey, sign as ecSign } from 'node:crypto';
import { runRound, verifyRoundOutputs } from '../client.mjs';

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, arr) => {
  if (a.startsWith('--')) acc.push([a.slice(2), arr[i + 1] && !arr[i + 1].startsWith('--') ? arr[i + 1] : 'true']);
  return acc;
}, []));
for (const need of ['rpc', 'wallet', 'coordinator', 'asset']) {
  if (!args[need]) { console.error('missing --' + need); process.exit(2); }
}

async function rpc(method, params = [], wallet = args.wallet) {
  const u = new URL(args.rpc);
  const auth = 'Basic ' + Buffer.from(decodeURIComponent(u.username) + ':' + decodeURIComponent(u.password)).toString('base64');
  u.username = ''; u.password = '';
  const base = u.toString().replace(/\/$/, '') + (wallet ? '/wallet/' + encodeURIComponent(wallet) : '');
  const res = await fetch(base, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: auth },
    body: JSON.stringify({ jsonrpc: '1.0', id: 'seqcj-live', method, params }),
    signal: AbortSignal.timeout(120000),
  });
  const j = await res.json().catch(() => ({ error: { message: 'bad json (HTTP ' + res.status + ')' } }));
  if (j.error) throw new Error(`${method}: ${j.error.message || JSON.stringify(j.error)}`);
  return j.result;
}

// WIF -> a signing key. The ownership proof is an ECDSA signature with the coin's own key, and the
// node hands it over as base58check, so it has to be decoded rather than used as-is.
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function keyFromWif(wif) {
  let x = 0n;
  for (const ch of String(wif)) { const v = B58.indexOf(ch); if (v < 0) throw new Error('bad WIF'); x = x * 58n + BigInt(v); }
  const bytes = [];
  while (x > 0n) { bytes.unshift(Number(x & 0xffn)); x >>= 8n; }
  for (const ch of String(wif)) { if (ch === '1') bytes.unshift(0); else break; }
  const d = Buffer.from(bytes);
  let key = d.subarray(1, d.length - 4);
  if (key.length === 33 && key[32] === 0x01) key = key.subarray(0, 32);
  const der = Buffer.concat([Buffer.from('302e0201010420', 'hex'), key, Buffer.from('a00706052b8104000a', 'hex')]);
  return createPrivateKey({ key: der, format: 'der', type: 'sec1' });
}

const api = async (path, body) => {
  const res = await fetch(args.coordinator.replace(/\/$/, '') + path, body
    ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }
    : { method: 'GET' });
  const j = await res.json().catch(() => ({ ok: false, error: 'bad json (HTTP ' + res.status + ')' }));
  if (!res.ok || j.ok === false) throw new Error(j.error || ('coordinator HTTP ' + res.status));
  return j;
};

const hooks = {
  fetchJson: api,
  onStatus: (phase, d) => console.log(new Date().toISOString(), phase, JSON.stringify(d)),

  // Transparent coins only: the coordinator refuses confidential ones, because blinding the round
  // would need their blinders.
  selectInputs: async ({ asset }) => {
    const utxos = await rpc('listunspent', [1, 9999999]);
    const mine = utxos.filter((u) => u.asset === asset && u.amountblinder === '0'.repeat(64));
    if (!mine.length) throw new Error('this wallet holds no transparent coins of that asset');
    return { inputs: mine.map((u) => ({ txid: u.txid, vout: u.vout, atoms: BigInt(Math.round(u.amount * 1e8)), address: u.address })) };
  },

  proveOwnership: async (message, input) => {
    const info = await rpc('getaddressinfo', [input.address]);
    const wif = await rpc('dumpprivkey', [input.address]);
    return { pubkey: info.pubkey, sig: ecSign('sha256', Buffer.from(message), keyFromWif(wif)).toString('hex') };
  },

  freshAddress: () => rpc('getnewaddress', ['', 'blech32']),

  // The gate, in full. Unblind with this wallet's own key and refuse unless the round pays exactly
  // what it promised — same function the wallets call, so a coordinator that cheats fails here too.
  verifyAndSign: async (txHex, ctx) => {
    const un = await rpc('unblindrawtransaction', [txHex]);
    const dec = await rpc('decoderawtransaction', [un.hex], null);
    const scriptOf = async (a) => (await rpc('validateaddress', [a], null)).scriptPubKey.toLowerCase();
    const mixScripts = [];
    for (const a of ctx.mixAddresses) mixScripts.push(await scriptOf(a));
    const changeScript = ctx.changeAddress ? await scriptOf(ctx.changeAddress) : null;
    const wanted = new Set([...mixScripts, ...(changeScript ? [changeScript] : [])]);
    const mine = dec.vout
      .filter((o) => o.scriptPubKey && wanted.has(String(o.scriptPubKey.hex).toLowerCase()))
      .map((o) => ({ scriptPubkey: o.scriptPubKey.hex, asset: o.asset, value: String(Math.round(o.value * 1e8)) }));
    const credited = verifyRoundOutputs({ mine, mixScripts, changeScript, denom: ctx.denom, change: ctx.change, asset: ctx.lane.asset });
    console.log(`verified: the round credits me ${credited} atoms across ${mine.length} outputs`);
    const signed = await rpc('signrawtransactionwithwallet', [txHex]);
    if (!signed.hex) throw new Error('the wallet did not sign');
    return signed.hex;
  },
};

const res = await runRound({ hooks, assetId: args.asset, maxCredentials: Number(args.denominations || 1) });
console.log(JSON.stringify(res, null, 2));
