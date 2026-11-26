import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { test } from 'node:test';
import { runInNewContext } from 'node:vm';

const source = ['remote-crypto', 'remote-chat'].map((file) =>
  '{\n' + readFileSync(new URL('../src/' + file + '.jsx', import.meta.url), 'utf8') + '\n}').join('\n');

function makeStorage(throwing = false) {
  const values = new Map();
  return {
    getItem: (key) => { if (throwing) throw new Error('storage disabled'); return values.get(key) ?? null; },
    setItem: (key, value) => { if (throwing) throw new Error('storage disabled'); values.set(key, value); },
    removeItem: (key) => { if (throwing) throw new Error('storage disabled'); values.delete(key); },
    _map: values,
  };
}

function loadCryptoEnv({ throwingLocalStorage = false } = {}) {
  const local = makeStorage(throwingLocalStorage);
  const session = makeStorage(false);
  const ctx = runInNewContext(
    source + '\n({ RemoteCrypto: globalThis.RemoteCrypto, RemoteChat: globalThis.RemoteChat });',
    {
      crypto: webcrypto,
      TextEncoder,
      TextDecoder,
      btoa,
      atob,
      setTimeout,
      clearTimeout,
      sessionStorage: session,
      localStorage: local,
    },
  );
  return { ...ctx, local, session };
}

// In-memory WebSocket double that captures every wire frame in order.
class MockWebSocket {
  constructor() {
    this.readyState = 0;
    this.binaryType = 'blob';
    this.bufferedAmount = 0;
    this.sent = [];
    this.closed = false;
  }
  open() {
    this.readyState = 1;
    this.onopen?.();
  }
  send(data) {
    if (this.readyState !== 1) throw new Error('socket not open');
    this.sent.push(data);
    this._onSend?.(data);
  }
  deliver(data) {
    if (this.readyState !== 1) return;
    this.onmessage?.({ data });
  }
  close(code = 1000) {
    if (this.closed) return;
    this.closed = true;
    this.readyState = 3;
    this.onclose?.({ code });
  }
}

// Helper that acts as the remote endpoint side of rmm-e2e-p256-aes256gcm-v1 in JS.
async function makeEndpointResponder(RC, { sessionID, agentID, kind = 'desktop', guestMode = '', deviceIDKey, mutateHello, readyPayload = '{"t":"e2e_ready"}' }) {
  const agentEphemeral = await RC.keyPair('ECDH');
  const agentNonce = RC.random(32);
  const exp = Math.floor(Date.now() / 1000) + 300;
  const fields = [sessionID, agentID, kind, guestMode];
  const delegation = RC.concat(RC.tuple('rmm-e2e-del-v1', ...fields, RC.point(agentEphemeral.pub)), RC.uint64(exp));
  const sig = await RC.sign(deviceIDKey.key, delegation);
  const hello = {
    t: 'e2e_hello', v: 1, role: 'agent',
    agent_id: agentID, kind, guest_mode: guestMode,
    ek: agentEphemeral.pub, nonce: RC.encode(agentNonce),
    ik: deviceIDKey.pub, exp, sig,
  };
  if (mutateHello) mutateHello(hello);

  async function deriveFromViewerHello(viewerHello) {
    const transcript = RC.concat(
      RC.tuple('rmm-e2e-hs-v1', ...fields, RC.point(hello.ik), RC.point(viewerHello.ek),
        RC.decode(viewerHello.nonce, 32), RC.point(hello.ek), RC.decode(hello.nonce, 32)),
      RC.uint64(hello.exp),
      (() => {
        const s = RC.decode(hello.sig, 64);
        const len = new Uint8Array(4);
        new DataView(len.buffer).setUint32(0, s.length);
        return RC.concat(len, s);
      })(),
    );
    const salt = new Uint8Array(await webcrypto.subtle.digest('SHA-256', transcript));
    const shared = await RC.sharedKey(agentEphemeral.key, RC.point(viewerHello.ek));
    const mkDir = async (label) => ({
      key: await RC.aes(await RC.hkdf(shared, salt, 'rmm-e2e-v1 k ' + label, 32)),
      iv: await RC.hkdf(shared, salt, 'rmm-e2e-v1 iv ' + label, 12),
    });
    const [v2a, a2v] = await Promise.all([mkDir('v2a'), mkDir('a2v')]);
    return { v2a, a2v };
  }

  async function sealAsAgent(dir, seq, innerType, payloadBytes) {
    const header = RC.concat(Uint8Array.of(0xe0), RC.uint64(seq));
    const iv = dir.iv.slice();
    for (let i = 0; i < 8; i++) iv[i + 4] ^= header[i + 1];
    const plain = RC.concat(Uint8Array.of(innerType), payloadBytes);
    const ct = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: RC.concat(header, RC.utf8(sessionID)) }, dir.key, plain);
    return RC.concat(header, new Uint8Array(ct)).buffer;
  }

  async function openFromViewer(dir, seq, raw) {
    const bytes = new Uint8Array(raw);
    const header = RC.concat(Uint8Array.of(0xe0), RC.uint64(seq));
    const iv = dir.iv.slice();
    for (let i = 0; i < 8; i++) iv[i + 4] ^= header[i + 1];
    const plain = new Uint8Array(await webcrypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: RC.concat(header, RC.utf8(sessionID)) },
      dir.key,
      bytes.subarray(9),
    ));
    return { innerType: plain[0], payload: plain.subarray(1) };
  }

  return { hello, deriveFromViewerHello, sealAsAgent, openFromViewer, readyPayload };
}

test('RemoteCrypto primitives reject non-canonical base64url, invalid points, and fail closed on broken storage', async () => {
  const { RemoteCrypto } = loadCryptoEnv();
  const kp = await RemoteCrypto.keyPair('ECDSA');
  assert.equal(RemoteCrypto.point(kp.pub).length, 65);

  // Flip an unused trailing bit (bit 0) in the final base64url char of a 65-byte encoding (2 trailing zero bits).
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const lastIdx = alphabet.indexOf(kp.pub.at(-1));
  const badTrail = kp.pub.slice(0, -1) + alphabet[lastIdx | 1];
  assert.throws(() => RemoteCrypto.decode(badTrail, 65));
  assert.throws(() => RemoteCrypto.decode('not+valid/b64', 10));
  assert.throws(() => RemoteCrypto.decode(kp.pub, 64));

  const wrongPrefix = RemoteCrypto.point(kp.pub).slice();
  wrongPrefix[0] = 0x02;
  assert.throws(() => RemoteCrypto.point(RemoteCrypto.encode(wrongPrefix)));

  // Broken localStorage fails closed when a device key or pin write is involved.
  const broken = loadCryptoEnv({ throwingLocalStorage: true });
  assert.equal(broken.RemoteCrypto.deviceIdentity('dev-1', undefined, false), true);
  assert.equal(broken.RemoteCrypto.deviceIdentity('dev-1', kp.pub, false), false);
  assert.equal(broken.RemoteCrypto.deviceIdentity('dev-1', kp.pub, true), false);
  assert.equal(broken.RemoteCrypto.deviceIdentity('dev-1', undefined, true), false);
});

test('RemoteCrypto.connect completes E2E handshake, exchanges text/binary frames, and supports guest inviteFP', async () => {
  const { RemoteCrypto } = loadCryptoEnv();
  const deviceIDKey = await RemoteCrypto.keyPair('ECDSA');

  for (const mode of ['technician', 'guest']) {
    const viewerEph = await RemoteCrypto.keyPair('ECDH');
    const sessionID = 'sess-' + mode;
    const guestMode = mode === 'guest' ? 'view' : '';
    const responder = await makeEndpointResponder(RemoteCrypto, {
      sessionID, agentID: 'agent-1', kind: 'desktop', guestMode, deviceIDKey,
    });
    const raw = new MockWebSocket();
    const context = mode === 'guest'
      ? { id: sessionID, agentID: '', kind: 'desktop', guestMode, inviteFP: await RemoteCrypto.fingerprint(deviceIDKey.pub), ephemeral: viewerEph }
      : { id: sessionID, agentID: 'agent-1', kind: 'desktop', guestMode: '', deviceKey: deviceIDKey.pub, ephemeral: viewerEph };

    const facade = RemoteCrypto.connect(raw, context);
    assert.equal(facade.readyState, 0);
    assert.equal(facade.identity, null);

    let opened = false;
    const received = [];
    let closedEvent = null;
    const readyPromise = new Promise((resolve, reject) => {
      facade.onopen = () => { opened = true; resolve(); };
      facade.onclose = (ev) => { closedEvent = ev; if (!opened) reject(new Error('closed before open: ' + JSON.stringify(ev))); };
    });
    facade.onmessage = (ev) => received.push(ev.data);

    let keys;
    raw._onSend = async (msg) => {
      if (typeof msg === 'string') {
        const vh = JSON.parse(msg);
        assert.equal(vh.t, 'e2e_hello');
        assert.equal(vh.role, 'viewer');
        keys = await responder.deriveFromViewerHello(vh);
        raw.deliver(JSON.stringify(responder.hello));
        const readyFrame = await responder.sealAsAgent(keys.a2v, 0n, 1, RemoteCrypto.utf8('{"t":"e2e_ready"}'));
        raw.deliver(readyFrame);
      }
    };

    raw.open();
    await readyPromise;
    assert.equal(facade.readyState, 1);
    assert.deepEqual({ ...facade.identity }, { deviceKey: deviceIDKey.pub, agentID: 'agent-1' });

    // Send text and binary frames viewer -> agent and verify encryption on wire.
    facade.send('{"t":"kf"}');
    facade.send(new Uint8Array([0x02, 0x07, 0x99]));
    await facade.flush();

    // raw.sent = [viewerHello, viewerReady, seq1 text, seq2 binary]
    assert.equal(raw.sent.length, 4);
    const f1 = await responder.openFromViewer(keys.v2a, 1n, raw.sent[2]);
    assert.equal(f1.innerType, 1);
    assert.equal(RemoteCrypto.decoder.decode(f1.payload), '{"t":"kf"}');
    const f2 = await responder.openFromViewer(keys.v2a, 2n, raw.sent[3]);
    assert.equal(f2.innerType, 2);
    assert.deepEqual([...f2.payload], [0x02, 0x07, 0x99]);

    // Deliver encrypted text + binary frames agent -> viewer.
    raw.deliver(await responder.sealAsAgent(keys.a2v, 1n, 1, RemoteCrypto.utf8('{"t":"hello","v":"0.19.0"}')));
    raw.deliver(await responder.sealAsAgent(keys.a2v, 2n, 2, new Uint8Array([0x01, 0xAA, 0xBB])));
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(received[0], '{"t":"hello","v":"0.19.0"}');
    assert.deepEqual([...new Uint8Array(received[1])], [0x01, 0xAA, 0xBB]);

    facade.close();
    assert.equal(facade.readyState, 3);
    assert.equal(closedEvent.cryptoFailed, false);
    await assert.rejects(facade.flush(), /remote session closed/);
  }
});

test('RemoteCrypto.connect rejects tampered handshakes, cleartext post-handshake, replays, bad tags, bad types, and frame limit violations', async () => {
  const { RemoteCrypto } = loadCryptoEnv();
  const deviceIDKey = await RemoteCrypto.keyPair('ECDSA');
  const otherKey = await RemoteCrypto.keyPair('ECDSA');

  async function expectCryptoFailure(setup) {
    const viewerEph = await RemoteCrypto.keyPair('ECDH');
    const raw = new MockWebSocket();
    const closed = new Promise((resolve) => {
      setup.onReady = resolve;
    });
    let opened = false;
    let closeEv = null;
    const facade = RemoteCrypto.connect(raw, {
      id: 'sess-adv',
      agentID: setup.guest ? '' : 'agent-1',
      kind: 'desktop',
      guestMode: setup.guest ? 'view' : '',
      deviceKey: setup.guest ? undefined : deviceIDKey.pub,
      inviteFP: setup.guest ? await RemoteCrypto.fingerprint(deviceIDKey.pub) : undefined,
      ephemeral: viewerEph,
    });
    facade.onopen = () => { opened = true; setup.afterOpen?.(facade, raw); };
    facade.onclose = (ev) => { closeEv = ev; setup.onReady(ev); };
    await setup.run(raw, facade);
    await closed;
    assert.equal(closeEv.cryptoFailed, true, setup.name + ' must set cryptoFailed=true');
    if (!setup.afterOpen) assert.equal(opened, false, setup.name + ' must not open');
  }

  // Handshake-level tampering cases.
  const mutations = [
    ['wrong agent_id', (h) => { h.agent_id = 'agent-evil'; }],
    ['wrong kind', (h) => { h.kind = 'terminal'; }],
    ['wrong guest_mode', (h) => { h.guest_mode = 'control'; }],
    ['wrong device key', (h) => { h.ik = otherKey.pub; }],
    ['expired delegation', (h) => { h.exp = Math.floor(Date.now() / 1000) - 10; }],
    ['tampered signature', (h) => {
      const b = RemoteCrypto.decode(h.sig, 64);
      b[0] ^= 0xff;
      h.sig = RemoteCrypto.encode(b);
    }],
    ['short nonce', (h) => { h.nonce = RemoteCrypto.encode(new Uint8Array(16)); }],
  ];

  for (const [name, mutate] of mutations) {
    await expectCryptoFailure({
      name,
      async run(raw) {
        const responder = await makeEndpointResponder(RemoteCrypto, {
          sessionID: 'sess-adv', agentID: 'agent-1', deviceIDKey, mutateHello: mutate,
        });
        raw._onSend = () => raw.deliver(JSON.stringify(responder.hello));
        raw.open();
      },
    });
  }

  // Guest inviteFP mismatch.
  await expectCryptoFailure({
    name: 'guest wrong inviteFP',
    guest: true,
    async run(raw) {
      const responder = await makeEndpointResponder(RemoteCrypto, {
        sessionID: 'sess-adv', agentID: 'agent-1', guestMode: 'view', deviceIDKey: otherKey,
      });
      raw._onSend = () => raw.deliver(JSON.stringify(responder.hello));
      raw.open();
    },
  });

  // Binary frame arriving before e2e_hello.
  await expectCryptoFailure({
    name: 'binary before hello',
    async run(raw) {
      raw._onSend = () => raw.deliver(new Uint8Array(32).buffer);
      raw.open();
    },
  });

  // Encrypted seq=0 frame with wrong ready payload.
  await expectCryptoFailure({
    name: 'invalid e2e_ready body',
    async run(raw) {
      const responder = await makeEndpointResponder(RemoteCrypto, { sessionID: 'sess-adv', agentID: 'agent-1', deviceIDKey });
      raw._onSend = async (msg) => {
        if (typeof msg !== 'string') return;
        const keys = await responder.deriveFromViewerHello(JSON.parse(msg));
        raw.deliver(JSON.stringify(responder.hello));
        raw.deliver(await responder.sealAsAgent(keys.a2v, 0n, 1, RemoteCrypto.utf8('{"t":"not_ready"}')));
      };
      raw.open();
    },
  });

  // Post-handshake violations: cleartext injection, tampered ciphertext, out-of-order seq, unknown inner type, oversized outbound/inbound.
  const postCases = [
    ['cleartext after handshake', (_keys, _resp, raw) => raw.deliver('{"t":"notice","text":"injected"}')],
    ['tampered ciphertext tag', async (keys, resp, raw) => {
      const f = new Uint8Array(await resp.sealAsAgent(keys.a2v, 1n, 1, RemoteCrypto.utf8('{"t":"kf"}')));
      f[f.length - 1] ^= 0xff;
      raw.deliver(f.buffer);
    }],
    ['out-of-order seq', async (keys, resp, raw) => {
      raw.deliver(await resp.sealAsAgent(keys.a2v, 2n, 1, RemoteCrypto.utf8('{"t":"kf"}')));
    }],
    ['unknown inner frame type', async (keys, resp, raw) => {
      raw.deliver(await resp.sealAsAgent(keys.a2v, 1n, 3, RemoteCrypto.utf8('x')));
    }],
    ['oversized inbound frame', (_keys, _resp, raw) => {
      raw.deliver(new ArrayBuffer(32 * 1024 * 1024 + 1));
    }],
    ['oversized outbound frame', (_keys, _resp, _raw, facade) => {
      facade.send(new Uint8Array(32 * 1024 * 1024));
    }],
  ];

  for (const [name, inject] of postCases) {
    let keys;
    let responder;
    await expectCryptoFailure({
      name,
      async run(raw) {
        responder = await makeEndpointResponder(RemoteCrypto, { sessionID: 'sess-adv', agentID: 'agent-1', deviceIDKey });
        raw._onSend = async (msg) => {
          if (typeof msg !== 'string') return;
          keys = await responder.deriveFromViewerHello(JSON.parse(msg));
          raw.deliver(JSON.stringify(responder.hello));
          raw.deliver(await responder.sealAsAgent(keys.a2v, 0n, 1, RemoteCrypto.utf8('{"t":"e2e_ready"}')));
        };
        raw.open();
      },
      afterOpen(facade, raw) {
        Promise.resolve(inject(keys, responder, raw, facade)).catch(() => {});
      },
    });
  }
});

test('RemoteChat verifies certified local user envelopes, rejects malformed envelopes, and forgets cursors', async () => {
  const { RemoteCrypto, RemoteChat, session } = loadCryptoEnv();
  const { pub: deviceKey } = await RemoteCrypto.keyPair('ECDSA');
  const tech = await RemoteChat.create('agent-user-cert', deviceKey);
  const userKP = await RemoteCrypto.keyPair('ECDSA');
  const userCert = await RemoteChat.userCert(tech, userKP.pub);
  const guestKeys = await RemoteChat.guestKeys();
  const expires = new Date(Date.now() + 60_000).toISOString();
  const share = { id: 'share-u', agent_id: 'agent-user-cert', guest_name: 'Alice', expires_at: expires, ...guestKeys.publicKeys };
  const wrapped = await RemoteChat.wrap(tech, share);
  const guestRoom = await RemoteChat.unwrap(
    { ...wrapped, expires_at: expires },
    { keys: guestKeys, requestId: 'share-u', fingerprint: await RemoteCrypto.fingerprint(deviceKey) },
    { agentID: 'agent-user-cert', deviceKey },
  );

  // Build a valid "user" envelope signed by userKP with tech's userCert.
  const aad = RemoteCrypto.tuple('rmm-e2e-chat-v1', tech.kid, 'agent-user-cert');
  const sigMsg = RemoteCrypto.concat(RemoteCrypto.tuple('rmm-chat-msg-v2', tech.kid, 'agent-user-cert', 'user', '', 'Hi from endpoint'), RemoteCrypto.uint64(1));
  const sig = await RemoteCrypto.sign(userKP.key, sigMsg);
  const iv = RemoteCrypto.random(12);
  const ct = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    tech.key,
    RemoteCrypto.utf8(JSON.stringify({ from: 'user', name: '', text: 'Hi from endpoint', seq: 1, sig, user_cert: userCert })),
  );
  const env = { t: 'e2e_chat', v: 1, kid: tech.kid, iv: RemoteCrypto.encode(iv), ct: RemoteCrypto.encode(new Uint8Array(ct)) };

  // Valid decryption with matching meta.
  const decoded = await RemoteChat.decrypt(guestRoom, env, { from: 'user' });
  assert.deepEqual({ ...decoded }, { from: 'user', name: '', text: 'Hi from endpoint' });
  // Replay rejected.
  assert.equal(await RemoteChat.decrypt(guestRoom, env, { from: 'user' }), null);

  // Mismatched source metadata, kid, version, or tampered ciphertext.
  assert.equal(await RemoteChat.decrypt(guestRoom, env, { from: 'tech' }), null);
  assert.equal(await RemoteChat.decrypt(guestRoom, { t: 'e2e_chat', v: 1, kid: 'other', iv: env.iv, ct: env.ct }), null);
  assert.equal(await RemoteChat.decrypt(guestRoom, { t: 'e2e_chat', v: 2, kid: tech.kid, iv: env.iv, ct: env.ct }), null);
  await assert.rejects(RemoteChat.decrypt(guestRoom, { ...env, ct: 'AAAA' }));

  // forget() clears persisted guest replay state in sessionStorage.
  assert.ok(session._map.has('rmm-guest-chat:share-u'));
  RemoteChat.forget('share-u');
  assert.equal(session._map.has('rmm-guest-chat:share-u'), false);
});
