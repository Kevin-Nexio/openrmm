import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
import { transformSync } from 'esbuild';

// Device page improvements: the Run script library picker is searchable and
// grouped by category; a job in the device's Jobs tab expands in place to show
// its output; the Devices list has a Last boot column, hidden until a viewer
// turns it on.
const devices = await readFile(new URL('../src/screens-devices.jsx', import.meta.url), 'utf8');
const between = (from, to) => {
  const a = devices.indexOf(from), b = devices.indexOf(to);
  assert.ok(a >= 0 && b > a, 'source markers: ' + from + ' … ' + to);
  return devices.slice(a, b);
};
const h = (type, props, ...children) => (typeof type === 'function' ? type({ ...props, children }) : { type, props: props || {}, children });
const find = (pred, node, out = []) => { if (!node || typeof node !== 'object') return out; if (pred(node)) out.push(node); (node.children || []).flat(Infinity).forEach((c) => find(pred, c, out)); return out; };
const text = (node) => (typeof node === 'string' ? node : (node?.children || []).flat(Infinity).map(text).join(''));

test('the library picker lists scripts grouped by category, alphabetically, uncategorized last', () => {
  const sandbox = { t: (key) => key };
  vm.createContext(sandbox);
  vm.runInContext(transformSync(between('// libraryScriptOptions lists saved scripts', 'function RunScriptForm('), { loader: 'jsx' }).code + '\nthis.options = libraryScriptOptions;', sandbox);
  const scripts = [
    { id: 'a', name: 'Zip logs', category: 'Maintenance' },
    { id: 'b', name: 'Install 7-Zip', category: '' },
    { id: 'c', name: 'Disk cleanup', category: 'maintenance' },
    { id: 'd', name: 'Agent 10', category: 'Deploy' },
    { id: 'e', name: 'Agent 9', category: 'Deploy' },
    { id: 'f', name: 'Flush DNS' },
  ];
  const options = sandbox.options(scripts);
  assert.deepEqual([...options].map((o) => o.value), ['e', 'd', 'c', 'a', 'f', 'b']);
  assert.deepEqual({ ...options[0] }, { value: 'e', label: 'Agent 9', group: 'Deploy' });
  assert.equal(options.at(-1).group, 'script.uncategorized');
  assert.deepEqual([...scripts].map((s) => s.id), ['a', 'b', 'c', 'd', 'e', 'f'], 'the list it was given is not reordered');
});

test('the Run script form picks library scripts with the searchable Combobox', () => {
  const form = between('function RunScriptForm(', 'function DevicePatches(');
  assert.match(form, /<Combobox value="" placeholder=\{t\('run\.startFrom'\)\} options=\{libraryScriptOptions\(/);
  assert.doesNotMatch(form, /<option value="">\{t\('run\.startFrom'\)\}<\/option>/, 'the plain list is gone');
});

function jobsHarness(jobs) {
  const states = [], nav = []; let cursor = 0, closed = 0, tree;
  const sandbox = {
    React: { createElement: h },
    useState(initial) { const i = cursor++; if (!(i in states)) states[i] = initial; return [states[i], (v) => { states[i] = typeof v === 'function' ? v(states[i]) : v; }]; },
    useQuery: () => ({ data: { jobs }, loading: false }),
    t: (key, vars) => (vars ? key + ' ' + JSON.stringify(vars) : key),
    timeAgo: (when) => 'ago(' + when + ')',
    cx: (...c) => c.filter(Boolean).join(' '),
    api: { listJobs() {} },
    window: {},
    ...Object.fromEntries(['Skeleton', 'EmptyState', 'Icon', 'StatusPill', 'OutputBlock', 'Button'].map((n) => [n, n])),
  };
  vm.createContext(sandbox);
  vm.runInContext(transformSync(between('// What an expanded job shows before it has output', '// Where a check or task on this device comes from'), { loader: 'jsx' }).code, sandbox);
  const render = () => { cursor = 0; tree = sandbox.DeviceJobs({ id: 'dev-1', navigate: (screen, opts) => nav.push([screen, opts]), onClose: () => { closed++; } }); return tree; };
  render();
  const row = (id) => find((n) => n.props?.['data-job'] === id, tree)[0];
  return {
    nav, closed: () => closed, render, row,
    toggle(id) { find((n) => n.type === 'button' && 'aria-expanded' in n.props, row(id))[0].props.onClick(); render(); },
    expanded(id) { return find((n) => n.type === 'button' && 'aria-expanded' in n.props, row(id))[0].props['aria-expanded']; },
    output(id) { return find((n) => n.type === 'OutputBlock', row(id))[0]; },
    text(id) { return text(row(id)); },
    openInJobs(id) { find((n) => n.type === 'Button' && text(n) === 'djobs.openInJobs', row(id))[0].props.onClick(); },
  };
}

const job = (id, status, extra = {}) => ({ id, status, description: 'Job ' + id, created_by: 'admin', created_at: '2026-11-19T10:00:00Z', exit_code: null, stdout: '', stderr: '', ...extra });

test('a finished job expands in place to show its output, without leaving the device', () => {
  const ui = jobsHarness([
    job('ok', 'completed', { exit_code: 0, stdout: 'hello\n' }),
    job('bad', 'failed', { exit_code: 2, stdout: 'partial', stderr: 'boom' }),
  ]);
  assert.equal(ui.expanded('ok'), false);
  assert.equal(ui.output('ok'), undefined, 'collapsed rows show no output');
  ui.toggle('ok');
  assert.equal(ui.expanded('ok'), true);
  assert.deepEqual({ ...ui.output('ok').props }, { stdout: 'hello\n', stderr: '', exitCode: 0 });
  assert.equal(ui.nav.length, 0, 'expanding does not navigate');
  // One job open at a time: opening another closes the first.
  ui.toggle('bad');
  assert.equal(ui.output('ok'), undefined);
  assert.deepEqual({ ...ui.output('bad').props }, { stdout: 'partial', stderr: 'boom', exitCode: 2 });
  ui.toggle('bad');
  assert.equal(ui.expanded('bad'), false, 'clicking again collapses it');
});

test('a job without output yet says why', () => {
  const ui = jobsHarness([job('wait', 'awaiting_approval'), job('no', 'rejected'), job('run', 'running'), job('sent', 'sent'), job('queued', 'pending')]);
  for (const [id, key] of [['wait', 'djobs.awaiting'], ['no', 'djobs.rejected'], ['run', 'djobs.inProgress'], ['sent', 'djobs.inProgress'], ['queued', 'djobs.inProgress']]) {
    ui.toggle(id);
    assert.equal(ui.output(id), undefined, id + ' has no output block');
    assert.match(ui.text(id), new RegExp(key.replace('.', '\\.')), id);
  }
});

test('"Open in Jobs" still leads to the full job', () => {
  const ui = jobsHarness([job('ok', 'completed', { exit_code: 0, stdout: 'x' })]);
  ui.toggle('ok');
  ui.openInJobs('ok');
  assert.equal(ui.closed(), 1, 'the drawer closes');
  assert.equal(JSON.stringify(ui.nav), JSON.stringify([['jobs', { focus: 'ok' }]]));
});

function columns() {
  const sandbox = {
    React: { createElement: h },
    t: (key, vars) => (vars ? key + ' ' + JSON.stringify(vars) : key),
    timeAgo: (when) => 'ago(' + when + ')',
    fmtTime: (when) => 'at(' + when + ')',
    cx: (...c) => c.filter(Boolean).join(' '),
  };
  vm.createContext(sandbox);
  vm.runInContext(transformSync(between("// The Devices grid's optional columns", 'function DevicesScreen('), { loader: 'jsx' }).code
    + '\nthis.cols = DEVICE_OPTIONAL_COLUMNS; this.labels = DEVICE_COLUMN_LABELS; this.hidden = deviceHiddenColumns; this.save = saveDeviceColumns; this.LastBoot = LastBoot; this.sortDevices = sortDevices; this.keys = [DEVICE_COLUMNS_KEY, DEVICE_COLUMNS_SHOWN_KEY];', sandbox);
  return sandbox;
}

test('Last boot is an optional column, hidden until a viewer shows it, and the choice is remembered', () => {
  const { cols, labels, hidden, save, keys } = columns();
  assert.ok(cols.includes('last_boot') && labels.last_boot === 'devices.col.lastBoot');
  const list = (a) => [...a];
  assert.deepEqual(list(hidden(null, null)), ['last_boot'], 'hidden for a viewer who never chose');
  assert.deepEqual(list(hidden('["tags"]', null)), ['tags', 'last_boot'], 'hidden for a viewer who arranged the list before it existed');
  assert.deepEqual(list(hidden('["tags"]', '["last_boot"]')), ['tags'], 'shown once chosen');
  assert.deepEqual(list(hidden('["last_boot"]', '["last_boot"]')), [], 'the shown key decides a default-hidden column');
  for (const raw of ['not json', '{"last_boot":true}', '"last_boot"', 'null']) assert.deepEqual(list(hidden(null, raw)), ['last_boot'], String(raw));

  const store = new Map();
  const storage = { setItem: (k, v) => store.set(k, v) };
  save(storage, ['tags']);
  assert.equal(store.get(keys[0]), '["tags"]');
  assert.equal(store.get(keys[1]), '["last_boot"]');
  assert.deepEqual(list(hidden(store.get(keys[0]), store.get(keys[1]))), ['tags']);
  save(storage, ['tags', 'last_boot']);
  assert.equal(store.get(keys[0]), '["tags"]', 'a default-hidden column is never written to the hidden key');
  assert.equal(store.get(keys[1]), '[]');
  assert.deepEqual(list(hidden(store.get(keys[0]), store.get(keys[1]))), ['tags', 'last_boot']);
});

test('the Last boot cell shows how long ago, the exact time on hover, and a dash before the first inventory', () => {
  const { LastBoot } = columns();
  const none = LastBoot({ device: {} });
  assert.equal(text(none), '—');
  const cell = LastBoot({ device: { last_boot_at: '2026-11-18T07:30:00Z' } });
  assert.equal(text(cell), 'ago(2026-11-18T07:30:00Z)');
  assert.equal(cell.props.title, 'at(2026-11-18T07:30:00Z)');
});

test('sorting by last boot puts the longest-running devices first, devices without one last', () => {
  const { sortDevices } = columns();
  const list = () => [{ id: 'a', last_boot_at: '2026-11-18T07:30:00Z' }, { id: 'b' }, { id: 'c', last_boot_at: '2026-10-01T00:00:00Z' }, { id: 'd', last_boot_at: '2026-11-19T01:00:00Z' }];
  const ids = (l) => l.map((d) => d.id).join('');
  assert.equal(ids(sortDevices(list(), (d) => d.last_boot_at || '', 'asc')), 'cadb');
  assert.equal(ids(sortDevices(list(), (d) => d.last_boot_at || '', 'desc')), 'dacb');
});
