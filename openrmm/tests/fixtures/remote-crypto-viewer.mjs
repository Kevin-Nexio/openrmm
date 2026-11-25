import assert from 'node:assert/strict';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import WebSocket from 'ws';

const cryptoSource = readFileSync(new URL('../../src/remote-crypto.jsx', import.meta.url), 'utf8');
const RemoteCrypto = runInNewContext(cryptoSource + '\nRemoteCrypto;', {
  crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob, setTimeout, clearTimeout,
});

const [url, deviceKey] = process.argv.slice(2);
const ephemeral = await RemoteCrypto.keyPair('ECDH');
console.log(ephemeral.pub);

const raw = new WebSocket(url);
const ws = RemoteCrypto.connect(raw, {
  id: 'interop-session', agentID: 'interop-device', kind: 'files', guestMode: '', deviceKey, ephemeral,
});
let receivedText = false;
let receivedBinary = false;
ws.onopen = () => {
  assert.equal(ws.identity.deviceKey, deviceKey);
  ws.send('{"t":"fget","path":"interop.txt"}');
  ws.send(new Uint8Array([2, 7, 42]));
};
ws.onmessage = ({ data }) => {
  if (typeof data === 'string') {
    assert.equal(data, '{"t":"fbegin","id":7}');
    receivedText = true;
  } else {
    assert.deepEqual([...new Uint8Array(data)], [2, 7, 12, 34]);
    receivedBinary = true;
    console.log('received text and binary');
  }
};
const closed = new Promise((resolve) => { ws.onclose = resolve; });
const [, event] = await Promise.all([once(raw, 'open'), closed]);
assert.ok(receivedText && receivedBinary);
assert.equal(event.cryptoFailed, true, 'a replay must fail the encrypted session');
