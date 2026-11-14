import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import vm from 'node:vm';
import { transformSync } from 'esbuild';

// A job stores who created and approved it as a user id. The console shows the
// username the server sends with it (created_by_name / approved_by_name) and
// keeps the id on hover; without a name (bootstrap admin, API token, scheduler,
// a deleted user) it shows the stored value as it is. A run released for the
// AI reads "pre-approved by <id> (hash …)": only the id inside becomes the name.
const jobs = await readFile(new URL('../src/screens-jobs.jsx', import.meta.url), 'utf8');
const chat = await readFile(new URL('../src/screens-chat.jsx', import.meta.url), 'utf8');
const devices = await readFile(new URL('../src/screens-devices.jsx', import.meta.url), 'utf8');

const helpers = jobs.slice(jobs.indexOf('const JOB_ACTOR_ID'), jobs.indexOf('window.jobCreator'));
const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(transformSync(helpers + '\nglobalThis.jobCreator = jobCreator; globalThis.jobApprover = jobApprover;', { loader: 'jsx' }).code, sandbox);
const id = '26141e80-3576-44f4-b43a-0e3812416736';

test('a job reads by its creator and approver names, falling back to what is stored', () => {
  assert.equal(sandbox.jobCreator({ created_by: id, created_by_name: 'admin-lab' }), 'admin-lab');
  assert.equal(sandbox.jobCreator({ created_by: 'admin' }), 'admin', 'the bootstrap admin has no user row');
  assert.equal(sandbox.jobCreator({ created_by: id }), id, 'a deleted user keeps its id');
  assert.equal(sandbox.jobApprover({ approved_by: id, approved_by_name: 'admin-lab' }), 'admin-lab');
  assert.equal(sandbox.jobApprover({ approved_by: 'pre-approved by ' + id + ' (hash 0123456789ab)', approved_by_name: 'maria' }),
    'pre-approved by maria (hash 0123456789ab)', 'only the id inside an autonomy basis is replaced');
  assert.equal(sandbox.jobApprover({ approved_by: 'autonomy: ai.autonomy.query' }), 'autonomy: ai.autonomy.query');
  assert.equal(sandbox.jobApprover({}), '');
});

test('job, batch, chat and device cards use the names, with the stored id on hover', () => {
  assert.match(jobs, /<span title=\{ai \? undefined : job\.created_by\}>[^\n]*t\('jobs\.by', \{ who: jobCreator\(job\) \}\)/);
  assert.match(jobs, /title=\{job\.approved_by\}>\{job\.autonomy \? t\('jobs\.autonomyBasis', \{ basis: jobApprover\(job\) \}\) : t\('jobs\.approvedBy', \{ who: jobApprover\(job\) \}\)\}/);
  assert.match(jobs, /t\('jobs\.by', \{ who: jobCreator\(head\) \}\)/, 'the batch card');
  assert.doesNotMatch(jobs, /who: (job|head)\.created_by \}|who: job\.approved_by \}|basis: job\.approved_by \}/, 'no raw id left in a sentence');
  assert.match(chat, /title=\{j\.approved_by\}>\{t\('chat\.autonomyBasis', \{ basis: window\.jobApprover \? window\.jobApprover\(j\) : j\.approved_by \}\)\}/);
  assert.match(devices, /<span title=\{j\.created_by\}>\{window\.jobCreator \? window\.jobCreator\(j\) : j\.created_by\}<\/span>/);
});
