import assert from 'node:assert/strict';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import WebSocket from 'ws';

const source = ['remote-crypto', 'remote-chat'].map((file) =>
  '{\n' + readFileSync(new URL('../../src/' + file + '.jsx', import.meta.url), 'utf8') + '\n}').join('\n');
function storage() {
  const values = new Map();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
}
const { RemoteCrypto, RemoteChat } = runInNewContext(source + '\n({ RemoteCrypto: globalThis.RemoteCrypto, RemoteChat: globalThis.RemoteChat });', {
  crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, setTimeout, clearTimeout,
  sessionStorage: storage(), localStorage: storage(),
});

const [url, deviceKey] = process.argv.slice(2);
const agentID = 'interop-chat-device';
const ephemeral = await RemoteCrypto.keyPair('ECDH');
const techRoom = await RemoteChat.create(agentID, deviceKey);
const guestKeys = await RemoteChat.guestKeys();
const expires = new Date(Date.now() + 60_000).toISOString();
const guestShare = { id: 'share-alice', agent_id: agentID, guest_name: 'Alice', expires_at: expires, ...guestKeys.publicKeys };
const wrapped = { ...await RemoteChat.wrap(techRoom, guestShare), expires_at: expires };
const guestInfo = { keys: guestKeys, requestId: 'share-alice', fingerprint: await RemoteCrypto.fingerprint(deviceKey) };
const guestRoom = await RemoteChat.unwrap(wrapped, guestInfo, { agentID, deviceKey });

console.log(ephemeral.pub);

const raw = new WebSocket(url);
const ws = RemoteCrypto.connect(raw, {
  id: 'interop-chat-session', agentID, kind: 'desktop', guestMode: '', deviceKey, ephemeral,
});

let sawDirectUser = false;
let sawGroupUser = false;
let resolveDone;
let rejectDone;
const done = new Promise((resolve, reject) => { resolveDone = resolve; rejectDone = reject; });

ws.onopen = () => {
  ws.send(JSON.stringify({
    t: 'chat_init',
    kid: techRoom.kid,
    k: RemoteCrypto.encode(techRoom.material),
    tech_pub: techRoom.techPub,
  }));
};

ws.onmessage = async ({ data }) => {
  try {
    if (typeof data !== 'string') return;
    const m = JSON.parse(data);
    if (m.t === 'chat_init_ack') {
      assert.equal(m.kid, techRoom.kid);
      const cert = await RemoteChat.userCert(techRoom, m.user_pub);
      ws.send(JSON.stringify({ t: 'chat_user_cert', kid: techRoom.kid, cert }));
      await ws.flush();

      // 1. Forged guest claiming "tech" must be rejected by the Go sidecar.
      const forged = await RemoteChat.encrypt({ ...guestRoom, grant: undefined }, 'Forged admin line');
      ws.send(JSON.stringify({ t: 'chat_guest', share_id: 'share-alice', envelope: forged }));

      // 2. Valid guest line must reach Go sidecar under Alice's certified name.
      const valid = await RemoteChat.encrypt(guestRoom, 'Olá\nfrom Alice');
      ws.send(JSON.stringify({ t: 'chat_guest', share_id: 'share-alice', envelope: valid }));

      // 3. Replaying the same guest envelope must be rejected by the Go sidecar.
      ws.send(JSON.stringify({ t: 'chat_guest', share_id: 'share-alice', envelope: valid }));

      // 4. Marker confirms replay was dropped without breaking the stream.
      ws.send(JSON.stringify({ t: 'kf' }));
    } else if (m.t === 'chat' && m.from === 'user') {
      assert.equal(m.text, 'Hi from endpoint');
      sawDirectUser = true;
    } else if (m.t === 'chat_group') {
      const decrypted = await RemoteChat.decrypt(guestRoom, m.envelope, { from: 'user' });
      assert.deepEqual({ ...decrypted }, { from: 'user', name: '', text: 'Hi from endpoint' });
      assert.equal(await RemoteChat.decrypt(guestRoom, m.envelope, { from: 'user' }), null, 'replayed user envelope');
      sawGroupUser = true;
    }
    if (sawDirectUser && sawGroupUser) {
      console.log('chat interop ok');
      ws.close();
      resolveDone();
    }
  } catch (err) {
    ws.close();
    rejectDone(err);
  }
};

ws.onclose = (ev) => {
  if (!sawDirectUser || !sawGroupUser) {
    rejectDone(new Error(`closed early code=${ev.code} cryptoFailed=${ev.cryptoFailed}`));
  }
};

await Promise.all([once(raw, 'open'), done]);
