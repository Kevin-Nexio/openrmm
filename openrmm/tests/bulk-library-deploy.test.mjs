import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
import { transformSync } from 'esbuild';

// Deploy to many runs either typed text or a saved library script. A saved
// script runs by id on every device, with its parameters and script variables,
// as it does from one device's page; proposals awaiting review are not offered.
const devices = await readFile(new URL('../src/screens-devices.jsx', import.meta.url), 'utf8');
const slice = (from, to) => devices.slice(devices.indexOf(from), devices.indexOf(to));
const source = slice('function BulkDeployModal(', '/* ----------------------------- Device detail')
  + slice('// libraryScriptOptions lists saved scripts', 'function RunScriptForm(');

const scripts = [
  { id: 's-agent', name: 'Install agent', category: 'Deploy', shell: 'powershell', body: 'install.ps1 $env:CUSTOMER_KEY', variables: ['CUSTOMER_KEY'],
    params: [{ name: 'site', kind: 'enum', values: ['hq', 'branch'] }, { name: 'ticket', kind: 'pattern', pattern: '^[0-9]+$' }] },
  { id: 's-plain', name: 'Uptime', category: '', shell: 'bash', body: 'uptime', variables: [], params: [] },
  { id: 's-ai', name: 'Proposed cleanup', category: 'AI proposals', shell: 'sh', body: 'rm -rf /tmp/x', variables: [], params: [], pending: true },
];
const fleet = [{ id: 'dev-1', hostname: 'PC-01', status: 'online', os: 'windows', site_id: 'site-1' }, { id: 'dev-2', hostname: 'PC-02', status: 'online', os: 'windows', site_id: 'site-1' }];

function harness({ perms } = {}) {
  const states = [], calls = []; let cursor = 0, tree;
  const sandbox = {
    React: { createElement(type, props, ...children) { return typeof type === 'function' ? type({ ...props, children }) : { type, props: props || {}, children }; }, Fragment: 'Fragment' },
    useState(initial) { const i = cursor++; if (!(i in states)) states[i] = typeof initial === 'function' ? initial() : initial; return [states[i], (v) => { states[i] = typeof v === 'function' ? v(states[i]) : v; }]; },
    useEffect() {},
    useAuth: () => ({ can: (p) => !perms || perms.includes(p) }),
    useToast: () => ({ success() {}, error(...a) { calls.push({ name: 'toast.error', args: a }); } }),
    useQuery: (key) => ({ data: key[0] === 'scripts-pick' ? { scripts } : { groups: [] } }),
    t: (key, vars) => (vars ? key + ' ' + JSON.stringify(vars) : key),
    tn: (key, n) => key + ':' + n,
    cx: (...v) => v.filter(Boolean).join(' '),
    api: { async createBulkJob(body) { calls.push({ name: 'createBulkJob', body: JSON.parse(JSON.stringify(body)) }); return { count: 2, companies: 1 }; } },
    ...Object.fromEntries(['Modal', 'Field', 'Select', 'Input', 'Button', 'Icon', 'OsIcon', 'CodeEditor', 'CodeBlock', 'Combobox'].map((n) => [n, n])),
  };
  vm.createContext(sandbox);
  vm.runInContext(transformSync(source, { loader: 'jsx' }).code, sandbox);
  // An undefined child ({cond && …}) must not fall back to the whole tree.
  const walk = (pred, node, out) => { if (!node || typeof node !== 'object') return out; if (pred(node)) out.push(node); (node.children || []).flat(Infinity).forEach((c) => walk(pred, c, out)); return out; };
  const find = (pred, node = tree) => walk(pred, node, []);
  const render = () => { cursor = 0; tree = sandbox.BulkDeployModal({ open: true, onClose() {}, devices: fleet, sites: [{ id: 'site-1', client_id: 'c-1', name: 'HQ' }], clients: [{ id: 'c-1', name: 'ACME' }] }); return tree; };
  render();
  const ui = {
    calls, find, render,
    selectAll() { find((n) => n.type === 'input' && n.props.type === 'checkbox').forEach((c) => c.props.onChange()); render(); },
    source(v) { find((n) => n.type === 'button' && n.props['aria-pressed'] !== undefined && n.children.flat(Infinity).includes('deploy.source.' + v))[0].props.onClick(); render(); },
    picker() { return find((n) => n.type === 'Combobox' && n.props.placeholder === 'deploy.pickScript')[0]; },
    pick(id) { ui.picker().props.onChange(id); render(); },
    create() { return find((n) => n.type === 'Button' && n.props.variant === 'primary')[0]; },
    async submit() { await ui.create().props.onClick(); },
    input(placeholder, value) { find((n) => n.type === 'Input' && n.props.placeholder === placeholder)[0].props.onChange({ target: { value } }); render(); },
    library() { return find((n) => n.props?.['data-deploy'] === 'library')[0]; },
  };
  return ui;
}

test('typed text is still sent as before', async () => {
  const ui = harness();
  ui.selectAll();
  assert.equal(ui.library(), undefined, 'the text editor is the default');
  ui.find((n) => n.type === 'CodeEditor')[0].props.onChange('echo hi'); ui.render();
  await ui.submit();
  const { body } = ui.calls.find((c) => c.name === 'createBulkJob');
  assert.deepEqual(body, { agent_ids: ['dev-1', 'dev-2'], shell: 'bash', script: 'echo hi', description: 'deploy.defaultDesc {"devices":"bulk.devices:2"}' });
});

test('a saved script is deployed by id, with its parameters, and its variables are named', async () => {
  const ui = harness();
  ui.selectAll();
  ui.source('library');
  assert.ok(ui.library(), 'the library picker is shown');
  assert.deepEqual([...ui.picker().props.options].map((o) => o.value), ['s-agent', 's-plain'], 'a proposal awaiting review is not offered');
  assert.equal(ui.create().props.disabled, true, 'nothing to deploy until a script is chosen');
  ui.pick('s-agent');
  const text = JSON.stringify(ui.library());
  assert.match(text, /deploy\.libraryVars .*CUSTOMER_KEY/, 'the variables that go with it are named');
  assert.equal(ui.find((n) => n.type === 'CodeBlock')[0].props.code, scripts[0].body, 'the script is shown, read-only');
  assert.equal(ui.create().props.disabled, true, 'a parameter without a value blocks it');
  ui.input('^[0-9]+$', '4521');
  assert.equal(ui.create().props.disabled, false);
  await ui.submit();
  const { body } = ui.calls.find((c) => c.name === 'createBulkJob');
  assert.deepEqual(body, { agent_ids: ['dev-1', 'dev-2'], script_id: 's-agent', params: { site: 'hq', ticket: '4521' } }, 'the server names it "library: Install agent"');
});

test('a saved script without parameters sends none, and a description typed goes with it', async () => {
  const ui = harness();
  ui.selectAll();
  ui.source('library');
  ui.pick('s-plain');
  ui.input('library: Uptime', 'Weekly uptime check');
  await ui.submit();
  assert.deepEqual(ui.calls.find((c) => c.name === 'createBulkJob').body, { agent_ids: ['dev-1', 'dev-2'], script_id: 's-plain', description: 'Weekly uptime check' });
});

test('without access to the library only typed text is offered', () => {
  const ui = harness({ perms: ['jobs.create', 'clients.view'] });
  assert.equal(ui.find((n) => n.props?.role === 'group').length, 0, 'no source switch');
  assert.ok(ui.find((n) => n.type === 'Field' && n.props.hint === 'deploy.noVariablesHintNoLibrary').length, 'the hint does not point to a library they cannot open');
});
