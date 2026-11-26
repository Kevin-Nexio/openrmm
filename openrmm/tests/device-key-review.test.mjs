import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import test from 'node:test';
import vm from 'node:vm';
import { transformSync } from 'esbuild';

// The console side of a device key review: the fingerprint matches the one Go
// and `rmm-agent -fingerprint` print, the review panel approves exactly the
// presented key only after the reviewer checked it, and a browser that
// remembered the previous key accepts a new one only when an administrator
// approved it and the technician agrees.

const cryptoSrc = await readFile(new URL('../src/remote-crypto.jsx', import.meta.url), 'utf8');
const devicesSrc = await readFile(new URL('../src/screens-devices.jsx', import.meta.url), 'utf8');
function between(src, from, to) {
  const a = src.indexOf(from), b = src.indexOf(to);
  assert.ok(a >= 0 && b > a, 'source markers not found: ' + from + ' .. ' + to);
  return src.slice(a, b);
}
const reviewCode = transformSync(between(devicesSrc, 'const FINGERPRINT_COMMAND =', 'function ShareAccessModal('),
  { loader: 'jsx', jsxFragment: 'React.Fragment' }).code;

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
const byTestId = (tree, id) => find((n) => n.props?.['data-testid'] === id, tree);
const text = (node) => {
  if (typeof node === 'string' || typeof node === 'number') return String(node);
  if (!node || typeof node !== 'object') return '';
  return (node.children || []).flat(Infinity).map(text).join('');
};
function storage() {
  const map = new Map();
  return { getItem: (k) => map.get(k) ?? null, setItem: (k, v) => map.set(k, String(v)), removeItem: (k) => map.delete(k) };
}
function hooks() {
  const states = [], deps = [], effects = [];
  let cursor = 0;
  return {
    reset() { cursor = 0; },
    flush() { for (const fn of effects.splice(0)) fn(); },
    useState(initial) {
      const i = cursor++;
      if (!(i in states)) states[i] = typeof initial === 'function' ? initial() : initial;
      return [states[i], (v) => { states[i] = typeof v === 'function' ? v(states[i]) : v; }];
    },
    useEffect(fn, values) {
      const i = cursor++;
      if (!values || !deps[i] || values.some((v, j) => v !== deps[i][j])) { effects.push(fn); deps[i] = values; }
    },
  };
}
function sandbox(api = {}) {
  const runtime = hooks();
  const toasts = { success: [], error: [] };
  const sb = {
    React: { createElement: h, Fragment }, useState: runtime.useState, useEffect: runtime.useEffect,
    crypto: webcrypto, TextEncoder, TextDecoder, btoa, atob,
    localStorage: storage(),
    t: (key, vars) => (vars ? key + ' ' + JSON.stringify(vars) : key),
    timeAgo: (v) => 'ago(' + v + ')',
    useToast: () => ({ success: (...a) => toasts.success.push(a), error: (...a) => toasts.error.push(a) }),
    api,
    ...Object.fromEntries(['Modal', 'Field', 'Input', 'Button', 'Icon'].map((k) => [k, k])),
  };
  sb.globalThis = sb;
  sb.window = sb;
  vm.createContext(sb);
  vm.runInContext(cryptoSrc + '\n' + reviewCode, sb);
  return { sb, runtime, toasts };
}
async function waitFor(check, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
}

test('the console fingerprint matches the Go one', async () => {
  const { sb } = sandbox();
  // The P-256 base point; the value comes from e2e.DisplayFingerprint.
  const g = 'BGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU';
  assert.equal(await sb.RemoteCrypto.displayFingerprint(g), '698B-EA63-DC44-A344');
  await assert.rejects(sb.RemoteCrypto.displayFingerprint('not-a-key'));
});

test('a remembered device key is replaced only from the value the technician saw', async () => {
  const { sb } = sandbox();
  const a = await sb.RemoteCrypto.keyPair('ECDSA'), b = await sb.RemoteCrypto.keyPair('ECDSA');
  assert.equal(sb.RemoteCrypto.knownDeviceKey('dev'), '');
  assert.equal(sb.RemoteCrypto.deviceIdentity('dev', a.pub, true), true);
  assert.equal(sb.RemoteCrypto.knownDeviceKey('dev'), a.pub);
  assert.equal(sb.RemoteCrypto.deviceIdentity('dev', b.pub), false, 'another key is refused');
  assert.equal(sb.RemoteCrypto.rememberDeviceKey('dev', b.pub, 'stale'), false, 'not from a stale value');
  assert.equal(sb.RemoteCrypto.rememberDeviceKey('dev', 'bad', a.pub), false, 'not an invalid key');
  assert.equal(sb.RemoteCrypto.knownDeviceKey('dev'), a.pub);
  assert.equal(sb.RemoteCrypto.rememberDeviceKey('dev', b.pub, a.pub), true);
  assert.equal(sb.RemoteCrypto.deviceIdentity('dev', b.pub), true);
});

test('the review panel approves exactly the presented key, only after the reviewer checked it', async () => {
  const calls = [];
  const { sb, runtime, toasts } = sandbox({
    approveDeviceKey: async (...a) => { calls.push(['approve', ...a]); },
    dismissDeviceKeyIssue: async (...a) => { calls.push(['dismiss', ...a]); },
  });
  const pinned = await sb.RemoteCrypto.keyPair('ECDSA'), presented = await sb.RemoteCrypto.keyPair('ECDSA');
  const device = {
    id: 'dev-1', os: 'windows', device_public_key: pinned.pub, device_key_issue: 'changed', pending_device_public_key: presented.pub,
    device_key_issue_seen_at: '2026-11-26T12:00:00Z', device_key_issue_ip: '198.51.100.20', device_key_issue_version: '0.13.0', device_key_issue_count: 2,
  };
  let changed = 0;
  const render = (props = {}) => {
    runtime.reset();
    const tree = sb.DeviceKeyReview({ device, canReview: true, onChanged: () => changed++, ...props });
    runtime.flush();
    return tree;
  };
  render();
  let tree;
  await waitFor(() => {
    tree = render();
    return byTestId(tree, 'device-key-pinned').length > 0 && byTestId(tree, 'device-key-pending').length > 0;
  });
  assert.equal(text(byTestId(tree, 'device-key-pinned')[0]), await sb.RemoteCrypto.displayFingerprint(pinned.pub));
  assert.equal(text(byTestId(tree, 'device-key-pending')[0]), await sb.RemoteCrypto.displayFingerprint(presented.pub));
  assert.match(text(tree), /rmm-agent\.exe" -state .*-fingerprint/, 'the Windows command is shown');
  assert.match(text(tree), /198\.51\.100\.20/);

  find((n) => n.type === 'Button' && text(n) === 'devkey.approve', tree)[0].props.onClick();
  tree = render();
  const submit = () => byTestId(tree, 'device-key-submit')[0];
  assert.equal(submit().props.disabled, true, 'nothing to submit without a reason and the check');
  byTestId(tree, 'device-key-reason')[0].props.onChange({ target: { value: 'compared on the device' } });
  tree = render();
  assert.equal(submit().props.disabled, true, 'a reason alone is not enough to approve');
  byTestId(tree, 'device-key-checked')[0].props.onChange({ target: { checked: true } });
  tree = render();
  assert.equal(submit().props.disabled, false);
  await submit().props.onClick();
  assert.deepEqual(calls, [['approve', 'dev-1', presented.pub, 'compared on the device']]);
  assert.equal(changed, 1);
  assert.equal(toasts.success.length, 1);

  // Keeping the pinned key needs only a reason.
  tree = render();
  find((n) => n.type === 'Button' && text(n) === 'devkey.dismiss', tree)[0].props.onClick();
  tree = render();
  byTestId(tree, 'device-key-reason')[0].props.onChange({ target: { value: 'old machine' } });
  tree = render();
  await byTestId(tree, 'device-key-submit')[0].props.onClick();
  assert.deepEqual(calls[1], ['dismiss', 'dev-1', 'old machine']);
});

test('the review panel offers no approval when there is nothing to approve, and no actions without the permission', async () => {
  const { sb, runtime } = sandbox();
  const pinned = await sb.RemoteCrypto.keyPair('ECDSA');
  const render = (device, canReview) => { runtime.reset(); const t = sb.DeviceKeyReview({ device, canReview }); runtime.flush(); return t; };
  assert.equal(render({ id: 'd', device_public_key: pinned.pub }, true), null, 'hidden without an issue');
  const dup = render({ id: 'd', os: 'linux', device_public_key: pinned.pub, device_key_issue: 'duplicate', pending_device_public_key: '' }, true);
  assert.equal(find((n) => n.type === 'Button' && text(n) === 'devkey.approve', dup).length, 0, 'clones are re-enrolled, not approved');
  assert.equal(find((n) => n.type === 'Button' && text(n) === 'devkey.dismiss' && n.props['data-testid'] !== 'device-key-submit', dup).length, 1);
  assert.match(text(dup), /sudo \/usr\/local\/bin\/rmm-agent -state \/etc\/rmm-agent\/state\.json -fingerprint/);
  const viewer = render({ id: 'd', device_public_key: pinned.pub, device_key_issue: 'missing' }, false);
  const panelButtons = (tree) => find((n) => n.type === 'Button', { children: tree.children.filter((c) => c?.type !== 'Modal') });
  assert.equal(panelButtons(viewer).length, 0, 'no actions without devices.delete');
});

test('a browser accepts a new device key only when an administrator approved it and the technician agrees', async () => {
  let device = null;
  const { sb, runtime } = sandbox({ getDevice: async () => device });
  const oldKey = await sb.RemoteCrypto.keyPair('ECDSA'), newKey = await sb.RemoteCrypto.keyPair('ECDSA');
  const harness = () => { runtime.reset(); const [check, element] = sb.useDeviceKeyChange(); runtime.flush(); return { check, element }; };
  assert.equal(sb.RemoteCrypto.deviceIdentity('dev', oldKey.pub, true), true);

  // The server holds the new key, but nobody approved a change: refused, no prompt.
  device = { id: 'dev', device_public_key: newKey.pub };
  assert.equal(await harness().check('dev', newKey.pub), false);
  // Approved, but another review is open: refused.
  device = { id: 'dev', device_public_key: newKey.pub, device_key_changed_by: 'admin', device_key_changed_at: '2026-11-26T12:00:00Z', device_key_issue: 'changed' };
  assert.equal(await harness().check('dev', newKey.pub), false);
  // The server's key is not the one this session presents: refused.
  device = { id: 'dev', device_public_key: oldKey.pub, device_key_changed_by: 'admin' };
  assert.equal(await harness().check('dev', newKey.pub), false);

  // Approved: both fingerprints are shown, and cancelling keeps the old key.
  device = { id: 'dev', device_public_key: newKey.pub, device_key_changed_by: 'admin', device_key_changed_at: '2026-11-26T12:00:00Z' };
  let pending = harness().check('dev', newKey.pub);
  let shown;
  await waitFor(() => {
    shown = harness().element;
    return byTestId(shown, 'device-key-change-accept').length > 0;
  });
  assert.match(text(shown), new RegExp(await sb.RemoteCrypto.displayFingerprint(oldKey.pub)));
  assert.match(text(shown), new RegExp(await sb.RemoteCrypto.displayFingerprint(newKey.pub)));
  assert.match(text(shown), /"who":"admin"/);
  find((n) => n.type === 'Button' && text(n) === 'action.cancel', shown)[0].props.onClick();
  assert.equal(await pending, false);
  assert.equal(sb.RemoteCrypto.knownDeviceKey('dev'), oldKey.pub);

  // Accepting remembers the new key.
  pending = harness().check('dev', newKey.pub);
  await waitFor(() => {
    shown = harness().element;
    return byTestId(shown, 'device-key-change-accept').length > 0;
  });
  byTestId(shown, 'device-key-change-accept')[0].props.onClick();
  assert.equal(await pending, true);
  assert.equal(sb.RemoteCrypto.knownDeviceKey('dev'), newKey.pub);
  assert.equal(await harness().check('dev', newKey.pub), true, 'no prompt once remembered');

  // A malformed key never rejects unhandled: it refuses cleanly.
  device = { id: 'dev', device_public_key: 'not-a-key', device_key_changed_by: 'admin', device_key_changed_at: '2026-11-26T12:00:00Z' };
  assert.equal(await harness().check('dev', 'not-a-key'), false);
});
