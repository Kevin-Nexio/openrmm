import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
import { transformSync } from 'esbuild';

// Checks and tasks apply to any number of policies and devices: the editors
// edit that list as chips, a save sends only what changed, an editor opened
// from a policy offers a copy or a removal for what the policy shares, the
// lists say where each item applies, and the device page lists every source.
const rmm = await readFile(new URL('../src/screens-rmm.jsx', import.meta.url), 'utf8');
const rmm2 = await readFile(new URL('../src/screens-rmm2.jsx', import.meta.url), 'utf8');
const devices = await readFile(new URL('../src/screens-devices.jsx', import.meta.url), 'utf8');
const slice = (src, from, to) => {
  const a = src.indexOf(from), b = src.indexOf(to, a);
  assert.ok(a >= 0 && b > a, 'markers ' + from + ' … ' + to);
  return src.slice(a, b);
};
const definitions = slice(rmm, 'const CHECK_TYPES =', '// A task\'s schedule');
const editors = slice(rmm, 'function CheckEditor(', '/* ============================ SCHEDULED TASKS');
const plain = (x) => JSON.parse(JSON.stringify(x));

function harness(code, apiImpl = {}) {
  const states = []; let cursor = 0; const calls = []; const toasts = [];
  const sandbox = {
    React: { createElement(type, props, ...children) { return typeof type === 'function' ? type({ ...props, children }) : { type, props: props || {}, children }; } },
    useState(initial) { const i = cursor++; if (!(i in states)) states[i] = typeof initial === 'function' ? initial() : initial; return [states[i], (v) => { states[i] = typeof v === 'function' ? v(states[i]) : v; }]; },
    useEffect() {},
    useQuery: () => ({ data: {} }),
    useToast: () => ({ success: (...a) => toasts.push(a), error: (...a) => { throw new Error(a.join(':')); }, info() {} }),
    useAuth: () => ({ can: () => true }),
    t: (key, vars) => (vars ? key + ' ' + JSON.stringify(vars) : key),
    cx: (...v) => v.filter(Boolean).join(' '),
    api: new Proxy({}, { get: (_, name) => async (...args) => { calls.push([name, ...plain(args)]); return apiImpl[name] ? apiImpl[name](...args) : {}; } }),
    ...Object.fromEntries(['Modal', 'Field', 'Select', 'Input', 'Button', 'Icon', 'Combobox', 'Toggle', 'CodeEditor', 'ConfirmDialog', 'OsIcon'].map((k) => [k, k])),
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(transformSync(code, { loader: 'jsx' }).code, sandbox);
  const walk = (pred, node, out) => { if (!node || typeof node !== 'object') return out; if (pred(node)) out.push(node); (node.children || []).flat(Infinity).forEach((c) => walk(pred, c, out)); return out; };
  return {
    sandbox, calls, toasts,
    render(name, props) { cursor = 0; return sandbox[name](props); },
    find: (tree, pred) => walk(pred, tree, []),
    text: (node) => JSON.stringify(node),
  };
}

const devMap = { 'dev-1': { id: 'dev-1', hostname: 'FILES-01', os: 'windows' }, 'dev-2': { id: 'dev-2', hostname: 'BACKUP-01', os: 'windows' } };
const policies = [{ id: 'pol-files', name: 'File server' }, { id: 'pol-backup', name: 'Backup server' }];

test('the attachments field shows each target as a chip, offers only the others, and says when it is shared or applies nowhere', () => {
  const ui = harness(definitions + editors);
  let value = [{ policy_id: 'pol-files' }];
  const render = () => ui.render('AttachmentsField', { value, onChange: (v) => { value = v; }, devMap, policies });
  let tree = render();
  const picker = ui.find(tree, (n) => n.type === 'Combobox')[0];
  assert.deepEqual([...picker.props.options].map((o) => o.value), ['dev:dev-1', 'dev:dev-2', 'pol:pol-backup'], 'what it already applies to is not offered');
  picker.props.onChange('dev:dev-2');
  assert.deepEqual(plain(value), [{ policy_id: 'pol-files' }, { agent_id: 'dev-2' }]);
  tree = render();
  assert.match(ui.text(tree), /attach\.sharedNote \{\\"n\\":2\}/);
  assert.match(ui.text(tree), /File server/);
  assert.match(ui.text(tree), /BACKUP-01/);
  ui.find(tree, (n) => n.type === 'button' && n.props['aria-label'] === 'action.remove: File server')[0].props.onClick();
  assert.deepEqual(plain(value), [{ agent_id: 'dev-2' }]);
  value = [];
  assert.match(ui.text(render()), /attach\.noneHint/);
});

test('a new check is created with its attachments, opened from a policy that policy is the default', async () => {
  const ui = harness(definitions + editors);
  const props = { onClose() {}, devMap, policies, defaultPolicyId: 'pol-files' };
  const tree = ui.render('CheckEditor', props);
  await ui.find(tree, (n) => n.type === 'Button' && n.children.includes('checks.create'))[0].props.onClick();
  const [name, body] = ui.calls[0];
  assert.equal(name, 'createCheck');
  assert.deepEqual(body.attachments, [{ policy_id: 'pol-files' }]);
  assert.equal('policy_id' in body, false);
});

test('saving an edit sends the check, then only the attachments that changed', async () => {
  const ui = harness(definitions + editors);
  const check = { id: 'chk-1', type: 'diskspace', name: 'disk D:', config: { path: 'D:' }, warn_threshold: 20, err_threshold: 10,
    attachments: [{ policy_id: 'pol-files', name: 'File server' }, { policy_id: 'pol-backup', name: 'Backup server' }] };
  const props = { check, onClose() {}, devMap, policies };
  let tree = ui.render('CheckEditor', props);
  ui.find(tree, (n) => n.type === 'button' && n.props['aria-label'] === 'action.remove: Backup server')[0].props.onClick();
  tree = ui.render('CheckEditor', props);
  ui.find(tree, (n) => n.type === 'Combobox' && n.props.placeholder === 'attach.add')[0].props.onChange('dev:dev-1');
  tree = ui.render('CheckEditor', props);
  await ui.find(tree, (n) => n.type === 'Button' && n.children.includes('checks.save'))[0].props.onClick();
  assert.deepEqual(ui.calls.map((c) => c[0]), ['updateCheck', 'detachCheck', 'attachCheck']);
  assert.equal('attachments' in ui.calls[0][2], false, 'the edit itself does not carry attachments');
  assert.deepEqual(ui.calls[1].slice(1), ['chk-1', 'policy', 'pol-backup']);
  assert.deepEqual(ui.calls[2].slice(1), ['chk-1', { agent_id: 'dev-1' }]);
});

test('an editor opened from a policy offers a copy or a removal only for what that policy shares', async () => {
  const ui = harness(definitions + editors);
  const shared = { id: 'chk-2', type: 'memory', attachments: [{ policy_id: 'pol-files' }, { policy_id: 'pol-backup' }] };
  let done = 0;
  const actions = (item, policyId) => ui.render('PolicyAttachmentActions', { kind: 'check', item, policyId, onDone: () => { done++; } });
  assert.equal(actions(shared, undefined), null, 'not outside a policy');
  assert.equal(actions({ ...shared, attachments: [{ policy_id: 'pol-files' }] }, 'pol-files'), null, 'not when the policy is its only place');
  assert.equal(actions(shared, 'pol-other'), null, 'not for a policy it is not in');
  let tree = actions(shared, 'pol-files');
  await ui.find(tree, (n) => n.type === 'Button' && n.children.includes('attach.copyForPolicy'))[0].props.onClick();
  tree = actions(shared, 'pol-files');
  await ui.find(tree, (n) => n.type === 'Button' && n.children.includes('attach.removeFromPolicy'))[0].props.onClick();
  assert.deepEqual(ui.calls, [['copyCheck', 'chk-2', { policy_id: 'pol-files' }], ['detachCheck', 'chk-2', 'policy', 'pol-files']]);
  assert.equal(done, 2);
  const taskUI = harness(definitions + editors);
  const task = { id: 'tsk-1', attachments: [{ policy_id: 'pol-files' }, { agent_id: 'dev-1' }] };
  await taskUI.find(taskUI.render('PolicyAttachmentActions', { kind: 'task', item: task, policyId: 'pol-files', onDone() {} }),
    (n) => n.type === 'Button' && n.children.includes('attach.removeFromPolicy'))[0].props.onClick();
  assert.deepEqual(taskUI.calls, [['detachTask', 'tsk-1', 'policy', 'pol-files']]);
});

test('the lists say where an item applies: one place, the first of several, or not in use', () => {
  const ui = harness(definitions + editors);
  const cell = (attachments) => ui.text(ui.render('AppliesTo', { item: { attachments }, devMap, policies }));
  assert.match(cell([]), /attach\.notInUse/);
  assert.match(cell([{ agent_id: 'dev-1' }]), /FILES-01/);
  const many = cell([{ policy_id: 'pol-files', name: 'File server' }, { policy_id: 'pol-backup', name: 'Backup server' }, { agent_id: 'dev-2' }]);
  assert.match(many, /File server/);
  assert.match(many, /attach\.more \{\\"n\\":2\}/);
  assert.match(many, /"title":"File server, Backup server, BACKUP-01"/);
});

test('the device page lists every way a check reaches the device', () => {
  const ui = harness(slice(devices, '// Where a check or task on this device comes from', '// The link to the screen where these are created'));
  const text = (row) => ui.text(ui.render('MonitoringSource', { row }));
  const both = text({ sources: [{ direct: true }, { policy_id: 'pol-backup', name: 'Backup server' }, { policy_id: 'pol-files', name: 'File server' }] });
  assert.match(both, /dmon\.direct.*Backup server.*File server/);
  assert.match(text({ policy_id: 'pol-files', policy_name: 'File server' }), /File server/, 'an older server sends one policy');
  assert.match(text({}), /dmon\.direct/);
});

test('a policy can include an existing check or task, never one awaiting review or already in it', () => {
  const detail = slice(rmm2, 'function PolicyDetail(', '/* ============================ CLIENTS & SITES');
  assert.match(detail, /const attachable = \(items\) => \(items \|\| \[\]\)\.filter\(\(x\) => !awaitingReview\(x\) && !\(x\.attachments \|\| \[\]\)\.some\(\(a\) => a\.policy_id === policy\.id\)\)/);
  assert.match(detail, /api\.attachCheck\(id, \{ policy_id: policy\.id \}\)/);
  assert.match(detail, /api\.attachTask\(id, \{ policy_id: policy\.id \}\)/);
  assert.match(detail, /placeholder=\{t\('attach\.addExistingCheck'\)\}/);
  assert.match(detail, /placeholder=\{t\('attach\.addExistingTask'\)\}/);
});
