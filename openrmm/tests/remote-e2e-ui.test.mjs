import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import test from 'node:test';
import vm from 'node:vm';
import { transformSync } from 'esbuild';

const cryptoSrc = await readFile(new URL('../src/remote-crypto.jsx', import.meta.url), 'utf8');
const chatSrc = await readFile(new URL('../src/remote-chat.jsx', import.meta.url), 'utf8');
const devicesSrc = await readFile(new URL('../src/screens-devices.jsx', import.meta.url), 'utf8');

function between(src, from, to) {
  const a = src.indexOf(from), b = src.indexOf(to);
  assert.ok(a >= 0 && b > a, 'source markers not found: ' + from + ' .. ' + to);
  return src.slice(a, b);
}

const h = (type, props, ...children) => {
  const flat = children.flat(Infinity);
  if (typeof type === 'function') return type({ ...props, children: flat });
  return { type, props: props || {}, children: flat };
};
const Fragment = ({ children }) => ({ type: 'Fragment', props: {}, children });
const find = (pred, node, out = []) => {
  if (!node || typeof node !== 'object') return out;
  if (pred(node)) out.push(node);
  (node.children || []).flat(Infinity).forEach((c) => find(pred, c, out));
  return out;
};
const text = (node) => {
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (!node || typeof node !== 'object') return '';
  return (node.children || []).flat(Infinity).map(text).join('');
};

function makeStorage() {
  const map = new Map();
  return {
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => map.set(k, String(v)),
    removeItem: (k) => map.delete(k),
    _map: map,
  };
}

function createHooks() {
  const states = [], refs = [], deps = [], effects = [], memos = [];
  let cursor = 0;
  return {
    reset() { cursor = 0; },
    flushEffects() {
      const cleanups = [];
      for (const fn of effects.splice(0)) {
        const c = fn();
        if (typeof c === 'function') cleanups.push(c);
      }
      return cleanups;
    },
    hooks: {
      useState(initial) {
        const i = cursor++;
        if (!(i in states)) states[i] = typeof initial === 'function' ? initial() : initial;
        return [states[i], (v) => { states[i] = typeof v === 'function' ? v(states[i]) : v; }];
      },
      useRef(initial) {
        const i = cursor++;
        if (!(i in refs)) refs[i] = { current: initial };
        return refs[i];
      },
      useEffect(fn, values) {
        const i = cursor++;
        if (!values || !deps[i] || values.some((v, j) => v !== deps[i][j])) {
          effects.push(fn);
          deps[i] = values;
        }
      },
      useMemo(fn, values) {
        const i = cursor++;
        if (!memos[i] || values.some((v, j) => v !== memos[i].deps[j])) {
          memos[i] = { value: fn(), deps: values };
        }
        return memos[i].value;
      },
    },
  };
}

function makeBaseSandbox({ subtleEnabled = true, locationHash = '', apiOverrides = {} } = {}) {
  const localStorage = makeStorage();
  const sessionStorage = makeStorage();
  const toasts = { success: [], error: [], info: [] };
  const historyCalls = [];
  const runtime = createHooks();
  const cryptoObj = subtleEnabled
    ? webcrypto
    : { getRandomValues: webcrypto.getRandomValues.bind(webcrypto), subtle: undefined };

  const sandbox = {
    React: { createElement: h, Fragment },
    ...runtime.hooks,
    crypto: cryptoObj,
    TextEncoder,
    TextDecoder,
    btoa,
    atob,
    URL,
    setTimeout,
    clearTimeout,
    setInterval: () => 1,
    clearInterval: () => {},
    localStorage,
    sessionStorage,
    location: { origin: 'https://rmm.example.test', pathname: '/join', search: '', hash: locationHash },
    history: { replaceState: (...args) => historyCalls.push(args) },
    document: { documentElement: { classList: { toggle() {} } } },
    t: (key) => key,
    tEnum: (prefix, val) => prefix + ':' + val,
    fmtTime: (v) => String(v),
    cx: (...v) => v.filter(Boolean).join(' '),
    useToast: () => ({
      success: (...a) => toasts.success.push(a),
      error: (...a) => toasts.error.push(a),
      info: (...a) => toasts.info.push(a),
    }),
    useQuery: () => ({ data: { shares: [] }, refetch() {} }),
    api: apiOverrides,
    ...Object.fromEntries(['Modal', 'Field', 'Select', 'Input', 'Button', 'Icon', 'Toggle', 'CopyButton', 'BrandMark', 'Spinner', 'RemoteViewer'].map((k) => [k, k])),
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(cryptoSrc + '\n' + chatSrc, sandbox);
  return { sandbox, runtime, toasts, localStorage, sessionStorage, historyCalls };
}

test('ShareAccessModal appends E2E fingerprint, omits it on legacy devices, and prevents orphaned invites on crypto failure or key change', async () => {
  const shareCode = between(devicesSrc, 'const SHARE_LIFETIMES =', '// GuestJoinScreen opens');
  const compiled = transformSync(shareCode, { loader: 'jsx', jsxFragment: 'React.Fragment' }).code;

  // 1. E2E device appends .<22-char-fingerprint> to link.
  {
    const createdCalls = [];
    const env = makeBaseSandbox({
      apiOverrides: {
        createRemoteShare: async (id, body) => {
          createdCalls.push({ id, body });
          return {
            share: { id: 'sh-1', mode: body.mode, reusable: body.reusable, expires_at: '2026-12-01T00:00:00Z' },
            token: 'tok-e2e-123',
            code: '123456',
            device_public_key: deviceKey.pub,
          };
        },
        closeRemoteShare: async () => {},
      },
    });
    const deviceKey = await env.sandbox.RemoteCrypto.keyPair('ECDSA');
    const fp = await env.sandbox.RemoteCrypto.fingerprint(deviceKey.pub);
    vm.runInContext(compiled, env.sandbox);

    const render = () => {
      env.runtime.reset();
      const tree = env.sandbox.ShareAccessModal({ open: true, onClose() {}, device: { id: 'dev-e2e', hostname: 'PC-1', device_public_key: deviceKey.pub } });
      env.runtime.flushEffects();
      return tree;
    };
    let tree = render();
    const createBtn = find((n) => n.type === 'Button' && text(n) === 'share.create', tree)[0];
    await createBtn.props.onClick();
    tree = render();

    assert.equal(createdCalls.length, 1);
    const linkInput = find((n) => n.type === 'Input' && n.props.readOnly, tree)[0];
    assert.equal(linkInput.props.value, `https://rmm.example.test/join#tok-e2e-123.${fp}`);
    assert.equal(env.toasts.success.length, 1);
    assert.equal(env.toasts.error.length, 0);
  }

  // 2. Legacy device omits fingerprint fragment.
  {
    const env = makeBaseSandbox({
      apiOverrides: {
        createRemoteShare: async () => ({
          share: { id: 'sh-leg', mode: 'view', reusable: true, expires_at: '2026-12-01T00:00:00Z' },
          token: 'tok-leg-456',
          code: '654321',
          device_public_key: '',
        }),
        closeRemoteShare: async () => {},
      },
    });
    vm.runInContext(compiled, env.sandbox);
    const render = () => {
      env.runtime.reset();
      const tree = env.sandbox.ShareAccessModal({ open: true, onClose() {}, device: { id: 'dev-leg', hostname: 'OLD-PC', device_public_key: '' } });
      env.runtime.flushEffects();
      return tree;
    };
    let tree = render();
    await find((n) => n.type === 'Button' && text(n) === 'share.create', tree)[0].props.onClick();
    tree = render();
    assert.equal(find((n) => n.type === 'Input' && n.props.readOnly, tree)[0].props.value, 'https://rmm.example.test/join#tok-leg-456');
  }

  // 3. E2E device without crypto.subtle refuses BEFORE calling api.createRemoteShare (zero orphaned shares).
  {
    let apiCalled = 0;
    const keyEnv = makeBaseSandbox();
    const deviceKey = await keyEnv.sandbox.RemoteCrypto.keyPair('ECDSA');
    const env = makeBaseSandbox({
      subtleEnabled: false,
      apiOverrides: {
        createRemoteShare: async () => { apiCalled++; throw new Error('must not be called'); },
        closeRemoteShare: async () => {},
      },
    });
    vm.runInContext(compiled, env.sandbox);
    env.runtime.reset();
    const tree = env.sandbox.ShareAccessModal({ open: true, onClose() {}, device: { id: 'dev-e2e', hostname: 'PC-1', device_public_key: deviceKey.pub } });
    env.runtime.flushEffects();
    await find((n) => n.type === 'Button' && text(n) === 'share.create', tree)[0].props.onClick();
    assert.equal(apiCalled, 0, 'pre-check must block before creating an orphaned share');
    assert.deepEqual(env.toasts.error[0], ['share.failed', 'viewer.encryptionFailed']);
  }

  // 4. Post-call rollback: if server returns a changed key after createRemoteShare, ShareAccessModal revokes it immediately.
  {
    const closedIDs = [];
    const env = makeBaseSandbox({
      apiOverrides: {
        createRemoteShare: async () => ({
          share: { id: 'sh-rollback', mode: 'view', reusable: true, expires_at: '2026-12-01T00:00:00Z' },
          token: 'tok-rb',
          code: '111111',
          device_public_key: rogueKey.pub,
        }),
        closeRemoteShare: async (id) => { closedIDs.push(id); },
      },
    });
    const pinnedKey = await env.sandbox.RemoteCrypto.keyPair('ECDSA');
    const rogueKey = await env.sandbox.RemoteCrypto.keyPair('ECDSA');
    // Pin pinnedKey in localStorage, pass matching device props, but have API response return rogueKey.
    env.sandbox.RemoteCrypto.deviceIdentity('dev-pin', pinnedKey.pub, true);
    vm.runInContext(compiled, env.sandbox);
    env.runtime.reset();
    const tree = env.sandbox.ShareAccessModal({ open: true, onClose() {}, device: { id: 'dev-pin', hostname: 'PIN-PC', device_public_key: pinnedKey.pub } });
    env.runtime.flushEffects();
    await find((n) => n.type === 'Button' && text(n) === 'share.create', tree)[0].props.onClick();
    assert.deepEqual(closedIDs, ['sh-rollback'], 'mismatched post-call key must revoke newly created share');
    assert.deepEqual(env.toasts.error[0], ['share.failed', 'viewer.deviceKeyChanged']);
  }
});

test('GuestJoinScreen parses E2E and legacy fragments, generates guest keys, and rejects malformed links or missing WebCrypto', async () => {
  const joinCode = between(devicesSrc, 'const GUEST_STORE =', 'window.GuestJoinScreen =');
  const compiled = transformSync(joinCode, { loader: 'jsx', jsxFragment: 'React.Fragment' }).code;

  // 1. Malformed fragments immediately render invalid state without calling lookup.
  for (const badHash of ['', '#tok.short', '#tok.aaaaaaaaaaaaaaaaaaaaaa.extra', '#tok.bad!chars!12345678901']) {
    let lookups = 0;
    const env = makeBaseSandbox({
      locationHash: badHash,
      apiOverrides: { guest: { lookup: async () => { lookups++; return {}; } } },
    });
    vm.runInContext(compiled, env.sandbox);
    env.runtime.reset();
    const tree = env.sandbox.GuestJoinScreen({});
    env.runtime.flushEffects();
    assert.match(text(tree), /guest\.invalidTitle/, 'hash ' + badHash + ' should be invalid');
    assert.equal(lookups, 0);
  }

  // 2. Valid E2E fragment (#token.<22-char-fp>) strips URL hash, looks up, generates P-256 guest keys, and submits them.
  {
    const joinCalls = [];
    const env = makeBaseSandbox({
      locationHash: '#my-secret-token.ABCDEFGHIJKLMNOPQRSTUV',
      apiOverrides: {
        guest: {
          lookup: async (tok) => ({ technician: 'Alice', mode: 'view', tokenSeen: tok }),
          join: async (tok, code, name, pubKeys) => {
            joinCalls.push({ tok, code, name, pubKeys });
            return { guest_credential: 'cred-1', technician: 'Alice', mode: 'view', request_id: 'req-1' };
          },
          status: async () => ({ status: 'pending' }),
        },
      },
    });
    vm.runInContext(compiled, env.sandbox);
    const render = () => {
      env.runtime.reset();
      const tree = env.sandbox.GuestJoinScreen({});
      env.runtime.flushEffects();
      return tree;
    };
    render();
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(env.historyCalls.length, 1, 'hash must be stripped from URL');
    let tree = render();
    const inputs = find((n) => n.type === 'Input', tree);
    assert.equal(inputs.length, 2, 'form must show name and code inputs');
    inputs[0].props.onChange({ target: { value: 'Bob' } });
    inputs[1].props.onChange({ target: { value: '123456' } });
    tree = render();
    const form = find((n) => n.type === 'form', tree)[0];
    await form.props.onSubmit({ preventDefault() {} });
    assert.equal(joinCalls.length, 1);
    assert.equal(joinCalls[0].tok, 'my-secret-token');
    assert.equal(joinCalls[0].code, '123456');
    assert.equal(joinCalls[0].name, 'Bob');
    assert.ok(joinCalls[0].pubKeys?.guest_public_key, 'E2E join must include guest_public_key');
    assert.ok(joinCalls[0].pubKeys?.guest_sign_key, 'E2E join must include guest_sign_key');
    assert.equal(env.sandbox.RemoteCrypto.point(joinCalls[0].pubKeys.guest_public_key).length, 65);
    assert.equal(env.sandbox.RemoteCrypto.point(joinCalls[0].pubKeys.guest_sign_key).length, 65);
  }

  // 3. E2E fragment without crypto.subtle blocks join and shows viewer.encryptionFailed.
  {
    let joined = 0;
    const env = makeBaseSandbox({
      subtleEnabled: false,
      locationHash: '#e2e-tok.ABCDEFGHIJKLMNOPQRSTUV',
      apiOverrides: {
        guest: {
          lookup: async () => ({ technician: 'Alice', mode: 'view' }),
          join: async () => { joined++; return {}; },
        },
      },
    });
    vm.runInContext(compiled, env.sandbox);
    const render = () => {
      env.runtime.reset();
      const tree = env.sandbox.GuestJoinScreen({});
      env.runtime.flushEffects();
      return tree;
    };
    render();
    await new Promise((r) => setTimeout(r, 10));
    let tree = render();
    const inputs = find((n) => n.type === 'Input', tree);
    inputs[0].props.onChange({ target: { value: 'Bob' } });
    inputs[1].props.onChange({ target: { value: '654321' } });
    tree = render();
    await find((n) => n.type === 'form', tree)[0].props.onSubmit({ preventDefault() {} });
    tree = render();
    assert.equal(joined, 0, 'join must not be called without WebCrypto on an E2E invite');
    assert.match(text(tree), /viewer\.encryptionFailed/);
  }
});

test('TerminalViewer completes E2E handshake, pins device key, renders lock badge, and blocks legacy downgrade', async () => {
  const termCode = [
    between(devicesSrc, 'function relayProtocols(', '// Why a guest'),
    between(devicesSrc, 'function useDeviceKeyChange(', 'function ShareAccessModal('),
    between(devicesSrc, 'function RemoteEncryptionStatus(', 'window.TerminalViewer ='),
  ].join('\n');
  const compiled = transformSync(termCode, { loader: 'jsx', jsxFragment: 'React.Fragment' }).code;

  function makeTermEnv({ startRemote, wsFactory }) {
    const env = makeBaseSandbox({
      apiOverrides: {
        startRemote,
        websocketURL: (p) => 'wss://rmm.example.test' + p,
      },
    });
    const termWrites = [];
    let onDataCb = null;
    env.sandbox.Terminal = class {
      constructor() { this.cols = 80; this.rows = 24; }
      loadAddon() {}
      open() {}
      focus() {}
      dispose() {}
      onData(cb) { onDataCb = cb; }
      onResize() {}
      write(v) { termWrites.push(v); }
    };
    env.sandbox.adoptDynamicStyles = () => {};
    env.sandbox.addEventListener = () => {};
    env.sandbox.removeEventListener = () => {};
    env.sandbox.WebSocket = wsFactory;
    vm.runInContext(compiled, env.sandbox);
    return { ...env, termWrites, sendInput: (s) => onDataCb?.(s) };
  }

  // 1. Full E2E terminal session: lock badge appears only after encrypted handshake & key gets pinned.
  {
    let startOpts = null;
    let rawSocket = null;
    const sockets = [];
    class FakeWS {
      constructor(url, protos) {
        this.url = url;
        this.protos = protos;
        this.readyState = 0;
        this.bufferedAmount = 0;
        this.sent = [];
        rawSocket = this;
        sockets.push(this);
      }
      send(d) { this.sent.push(d); this._onSend?.(d); }
      close(code = 1000) { this.readyState = 3; this.onclose?.({ code }); }
    }

    const keyHelper = makeBaseSandbox();
    const deviceKey = await keyHelper.sandbox.RemoteCrypto.keyPair('ECDSA');
    const agentEph = await keyHelper.sandbox.RemoteCrypto.keyPair('ECDH');
    const agentNonce = keyHelper.sandbox.RemoteCrypto.random(32);
    const exp = Math.floor(Date.now() / 1000) + 300;
    const RC = keyHelper.sandbox.RemoteCrypto;
    const fields = ['term-sess-1', 'dev-term', 'terminal', ''];
    const delSig = await RC.sign(deviceKey.key, RC.concat(RC.tuple('rmm-e2e-del-v1', ...fields, RC.point(agentEph.pub)), RC.uint64(exp)));
    const agentHello = {
      t: 'e2e_hello', v: 1, role: 'agent', agent_id: 'dev-term', kind: 'terminal', guest_mode: '',
      ek: agentEph.pub, nonce: RC.encode(agentNonce), ik: deviceKey.pub, exp, sig: delSig,
    };

    const env = makeTermEnv({
      startRemote: async (_id, provider, opts) => {
        startOpts = { provider, opts };
        return { id: 'term-sess-1', viewer_ticket: 'vt-1', e2e: true, device_public_key: deviceKey.pub };
      },
      wsFactory: FakeWS,
    });
    const render = () => {
      env.runtime.reset();
      const tree = env.sandbox.TerminalViewer({ deviceId: 'dev-term', hostname: 'TERM-HOST', onClose() {} });
      env.runtime.flushEffects();
      return tree;
    };

    let tree = render();
    // Before handshake completes, lock icon is NOT rendered.
    assert.equal(find((n) => n.props?.['aria-label'] === 'viewer.encrypted', tree).length, 0);

    // Wait for async startRemote + WebSocket construction.
    for (let i = 0; i < 20 && !rawSocket; i++) await new Promise((r) => setTimeout(r, 10));
    assert.ok(rawSocket, 'TerminalViewer must open WebSocket');
    assert.equal(startOpts.provider, 'terminal');
    assert.ok(startOpts.opts.viewer_key, 'TerminalViewer must send viewer_key');

    let a2v;
    rawSocket._onSend = async (msg) => {
      if (typeof msg !== 'string') return;
      const vh = JSON.parse(msg);
      const sigRaw = RC.decode(agentHello.sig, 64);
      const len4 = new Uint8Array(4);
      new DataView(len4.buffer).setUint32(0, sigRaw.length);
      const th = new Uint8Array(await webcrypto.subtle.digest('SHA-256', RC.concat(
        RC.tuple('rmm-e2e-hs-v1', ...fields, RC.point(deviceKey.pub), RC.point(vh.ek), RC.decode(vh.nonce, 32), RC.point(agentEph.pub), agentNonce),
        RC.uint64(exp), len4, sigRaw,
      )));
      const shared = await RC.sharedKey(agentEph.key, RC.point(vh.ek));
      a2v = {
        key: await RC.aes(await RC.hkdf(shared, th, 'rmm-e2e-v1 k a2v', 32)),
        iv: await RC.hkdf(shared, th, 'rmm-e2e-v1 iv a2v', 12),
      };
      const sealA2V = async (seq, innerType, bytes) => {
        const hdr = RC.concat(Uint8Array.of(0xe0), RC.uint64(seq));
        const iv = a2v.iv.slice();
        for (let i = 0; i < 8; i++) iv[i + 4] ^= hdr[i + 1];
        const ct = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: RC.concat(hdr, RC.utf8('term-sess-1')) }, a2v.key, RC.concat(Uint8Array.of(innerType), bytes));
        return RC.concat(hdr, new Uint8Array(ct)).buffer;
      };
      rawSocket.onmessage({ data: JSON.stringify(agentHello) });
      rawSocket.onmessage({ data: await sealA2V(0n, 1, RC.utf8('{"t":"e2e_ready"}')) });
      rawSocket.onmessage({ data: await sealA2V(1n, 1, RC.utf8('{"t":"hello","shell":"/bin/sh","user":"root","elevated":true}')) });
      rawSocket.onmessage({ data: await sealA2V(2n, 2, RC.utf8('secret-shell-out')) });
    };
    rawSocket.readyState = 1;
    rawSocket.onopen();
    await new Promise((r) => setTimeout(r, 40));

    tree = render();
    assert.equal(find((n) => n.props?.['aria-label'] === 'viewer.encrypted', tree).length, 1, 'lock icon must appear after E2E handshake');
    assert.equal(env.localStorage.getItem('rmm-device-key:dev-term'), deviceKey.pub, 'device key must be pinned after handshake');
    assert.match(text(tree), /\/bin\/sh/);
    assert.equal(RC.decoder.decode(env.termWrites[0]), 'secret-shell-out');
  }

  // 2. Anti-downgrade refusal: previously pinned device returning legacy e2e=false never opens a socket.
  {
    let wsCreated = 0;
    const env = makeTermEnv({
      startRemote: async () => ({ id: 'term-legacy', viewer_ticket: 'vt', e2e: false, device_public_key: '' }),
      wsFactory: class { constructor() { wsCreated++; } },
    });
    const pinned = await env.sandbox.RemoteCrypto.keyPair('ECDSA');
    env.sandbox.RemoteCrypto.deviceIdentity('dev-pinned', pinned.pub, true);
    env.runtime.reset();
    env.sandbox.TerminalViewer({ deviceId: 'dev-pinned', hostname: 'PINNED', onClose() {} });
    env.runtime.flushEffects();
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(wsCreated, 0, 'legacy downgrade on pinned device must not open a WebSocket');
    assert.deepEqual(env.toasts.error[0], ['viewer.deviceKeyChanged']);
  }

  // 3. Server E2E error codes map to localized toast messages.
  for (const [code, wantMsg] of [['remote_agent_update_required', 'viewer.encryptionAgentUpdate'], ['remote_e2e_required', 'viewer.encryptionFailed']]) {
    const env = makeTermEnv({
      startRemote: async () => { const e = new Error('fail'); e.code = code; throw e; },
      wsFactory: class {},
    });
    env.runtime.reset();
    env.sandbox.TerminalViewer({ deviceId: 'dev-err', hostname: 'ERR', onClose() {} });
    env.runtime.flushEffects();
    await new Promise((r) => setTimeout(r, 20));
    assert.deepEqual(env.toasts.error[0], ['term.failed', wantMsg]);
  }
});
