import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
import { transformSync } from 'esbuild';

// Edits the AI proposes are reviewed before anything changes: each screen
// lists the ones waiting, the review shows the object now against after, and
// only someone who could make the edit by hand may apply or reject it; a stale
// one cannot be applied.
const rmm = await readFile(new URL('../src/screens-rmm.jsx', import.meta.url), 'utf8');
const rmm2 = await readFile(new URL('../src/screens-rmm2.jsx', import.meta.url), 'utf8');
const patches = await readFile(new URL('../src/screens-patches.jsx', import.meta.url), 'utf8');
const code = rmm.slice(rmm.indexOf('// ---- edits the AI proposed ----'), rmm.indexOf('/* ============================ SCHEDULED TASKS'));

function harness({ perms = null, data = {} } = {}) {
  const states = []; let cursor = 0; const calls = []; const toasts = []; const emitted = [];
  const sandbox = {
    React: { createElement(type, props, ...children) { return typeof type === 'function' ? type({ ...props, children }) : { type, props: props || {}, children }; } },
    useState(initial) { const i = cursor++; if (!(i in states)) states[i] = typeof initial === 'function' ? initial() : initial; return [states[i], (v) => { states[i] = typeof v === 'function' ? v(states[i]) : v; }]; },
    useQuery: (key) => ({ data: data[key.join(':')] }),
    useAuth: () => ({ can: (p) => !perms || perms.includes(p) }),
    useToast: () => ({ success: (...a) => toasts.push(a), error: (...a) => toasts.push(['error', ...a]) }),
    t: (key, vars) => (vars ? key + ' ' + JSON.stringify(vars) : key),
    timeAgo: (v) => 'ago(' + v + ')',
    api: new Proxy({}, { get: (_, name) => async (...args) => { calls.push([name, ...args]); return {}; } }),
    ...Object.fromEntries(['Modal', 'Button', 'Icon', 'CodeBlock'].map((k) => [k, k])),
  };
  sandbox.window = { dataBus: { emit: (e) => emitted.push(e) } };
  vm.createContext(sandbox);
  vm.runInContext(transformSync(code, { loader: 'jsx' }).code + '\nthis.editDiff = editDiff;', sandbox);
  const walk = (pred, node, out) => { if (!node || typeof node !== 'object') return out; if (pred(node)) out.push(node); (node.children || []).flat(Infinity).forEach((c) => walk(pred, c, out)); return out; };
  return { sandbox, calls, toasts, emitted, render: (name, props) => { cursor = 0; return sandbox[name](props); }, find: (tree, pred) => walk(pred, tree, []) };
}

const detail = (over = {}) => ({
  proposal: { id: 'ep-1', kind: 'check', target_id: 'chk-1', target_name: 'disk D:', status: 'pending', reason: 'every ten minutes is enough', proposed_by: 'ai:alice', created_at: '2026-11-19T10:00:00Z' },
  current: { fields: { name: 'disk D:', interval_sec: 300, config: { path: 'D:' } }, attachments: ['agent:dev-1', 'policy:pol-files'] },
  proposed: { fields: { name: 'disk D:', interval_sec: 600, config: { path: 'D:' } }, attachments: ['agent:dev-1', 'policy:pol-backup'] },
  names: { 'agent:dev-1': 'FILES-01', 'policy:pol-files': 'File server', 'policy:pol-backup': 'Backup server' },
  stale: false,
  ...over,
});

test('the diff lists only what changes', () => {
  const { sandbox } = harness();
  const d = sandbox.editDiff(
    { fields: { a: 1, b: { x: 1 } }, attachments: ['agent:1'], assignments: [{ scope_type: 'site', scope_id: 's' }], exclusions: ['d1'] },
    { fields: { a: 1, b: { x: 2 }, c: 'new' }, attachments: ['agent:1', 'policy:p'], assignments: [{ scope_type: 'global' }], exclusions: ['d2'] });
  assert.deepEqual(JSON.parse(JSON.stringify(d.fields.map((f) => f.key))), ['b', 'c']);
  assert.deepEqual(JSON.parse(JSON.stringify(d.attachments)), { added: ['policy:p'], removed: [] });
  assert.equal(d.assignments.added[0].scope_type, 'global');
  assert.equal(d.assignments.removed[0].scope_type, 'site');
  assert.deepEqual(JSON.parse(JSON.stringify(d.exclusions)), { added: ['d2'], removed: ['d1'] });
});

test('the review shows each changed field before and after, and applying it reloads the lists', async () => {
  const ui = harness({ data: { 'edit-proposal:ep-1': detail() } });
  let closed = 0;
  const tree = ui.render('EditProposalReview', { id: 'ep-1', onClose: () => { closed++; } });
  const fields = ui.find(tree, (n) => n.props?.['data-edit-field']).map((n) => n.props['data-edit-field']);
  assert.deepEqual(fields, ['interval_sec'], 'unchanged fields are not shown');
  const text = JSON.stringify(tree);
  assert.match(text, /every ten minutes is enough/);
  assert.match(text, /Backup server/, 'an attachment added is named');
  assert.match(text, /File server/, 'an attachment removed is named');
  await ui.find(tree, (n) => n.type === 'Button' && n.children.includes('edits.apply'))[0].props.onClick();
  assert.deepEqual(ui.calls, [['applyEditProposal', 'ep-1']]);
  assert.deepEqual(ui.emitted, ['edit-proposals', 'checks']);
  assert.equal(closed, 1);
});

test('a stale proposal cannot be applied, only rejected', async () => {
  const ui = harness({ data: { 'edit-proposal:ep-1': detail({ stale: true }) } });
  const tree = ui.render('EditProposalReview', { id: 'ep-1', onClose() {} });
  assert.match(JSON.stringify(tree), /edits\.stale/);
  assert.equal(ui.find(tree, (n) => n.type === 'Button' && n.children.includes('edits.apply'))[0].props.disabled, true);
  await ui.find(tree, (n) => n.type === 'Button' && n.children.includes('edits.reject'))[0].props.onClick();
  assert.deepEqual(ui.calls, [['rejectEditProposal', 'ep-1']]);
});

test('without the permission an edit by hand takes, the review only shows', () => {
  const ui = harness({ perms: ['checks.view'], data: { 'edit-proposal:ep-1': detail() } });
  const tree = ui.render('EditProposalReview', { id: 'ep-1', onClose() {} });
  assert.equal(ui.find(tree, (n) => n.type === 'Button' && (n.children.includes('edits.apply') || n.children.includes('edits.reject'))).length, 0);
});

test('each screen lists the edits waiting for its kind of object, and nothing when there are none', () => {
  const empty = harness({ data: { 'edit-proposals:check': { proposals: [] } } });
  assert.equal(empty.render('EditProposalsPanel', { kind: 'check' }), null);
  const ui = harness({ data: { 'edit-proposals:task': { proposals: [{ id: 'ep-2', target_name: 'Sunday reboot', reason: 'move to 4am' }] } } });
  const tree = ui.render('EditProposalsPanel', { kind: 'task' });
  assert.equal(tree.props['data-edit-proposals'], 'task');
  assert.match(JSON.stringify(tree), /Sunday reboot.*move to 4am/);
  assert.match(rmm, /<EditProposalsPanel kind="check" \/>/);
  assert.match(rmm, /<EditProposalsPanel kind="task" \/>/);
  assert.match(rmm2, /<window\.EditProposalsPanel kind="script" \/>/);
  assert.match(rmm2, /<window\.EditProposalsPanel kind="policy" \/>/);
  assert.match(patches, /<window\.EditProposalsPanel kind="patch_policy" \/>/);
});
