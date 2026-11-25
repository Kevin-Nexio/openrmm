#!/usr/bin/env python3
"""Rules that keep release credentials away from code a release need not trust.

1. Every action is pinned to a full commit SHA.
2. A workflow that runs on release tags restores no Actions cache: setup-go
   runs with `cache: false`, and nothing uses actions/cache. Branch runs write
   that cache while running tests, npm packages and actions, and whatever they
   leave in it would end up in what the release builds and signs.
3. A job whose setup-go step saves a Go cache runs npm only as
   `npm ci --ignore-scripts`, because install scripts are npm packages' code.
4. Signing key material (the Apple certificate and its password, the update
   signing keys) goes in the env of the one step that uses it, never in the
   env of a whole job or workflow. Comparing such a secret with '' to learn
   whether it exists is allowed anywhere.
5. A Docker layer cache is read and written only off release tags.

The parsing is line-based on purpose. The runner's Python has no YAML parser,
and these workflows keep one layout: jobs at two spaces, steps at six.

Usage: check-workflow-policy.py [workflows-dir]
"""
import pathlib
import re
import sys

KEY_MATERIAL = {
    'APPLE_SIGNING_P12',
    'APPLE_SIGNING_P12_PASSWORD',
    'RMM_SIGNING_KEY',
    'RMM_SIGNING_KEY_P256',
}

USES = re.compile(r'^\s*(?:-\s+)?uses:\s*([^\s#]+)')
PINNED = re.compile(r'^[^@\s]+@[0-9a-f]{40}$')
JOB = re.compile(r'^  ([A-Za-z0-9_-]+):\s*$')
JOB_KEY = re.compile(r'^    [A-Za-z_-]+:')
STEP = re.compile(r'^      - ')
RUN = re.compile(r'^(\s*)(?:-\s+)?run:\s*(.*)$')
SECRET = re.compile(r'secrets\.([A-Za-z0-9_]+)')
EXISTENCE = r"secrets\.{}\s*(?:!=|==)\s*''"
NPM = re.compile(r'(?:^|[\s;&|(])(?:npm|npx|pnpm|yarn)(?:\s|$)')
NPM_OK = re.compile(r'\bnpm\b.*\bci\b.*--ignore-scripts')
GHA_CACHE = re.compile(r'^\s*(cache-from|cache-to):\s*(.*)$')
TAG_GUARD = "startsWith(github.ref, 'refs/tags/')"


def parse(path):
    """Returns (preamble, jobs): numbered lines before `jobs:`, and for each
    job its job-level lines and the numbered lines of each of its steps."""
    preamble, jobs, current, in_jobs = [], {}, None, False
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if line.rstrip() == 'jobs:':
            in_jobs = True
            continue
        if not in_jobs:
            preamble.append((n, line))
            continue
        match = JOB.match(line)
        if match:
            current = {'head': [], 'steps': [], 'in_steps': False}
            jobs[match.group(1)] = current
            continue
        if current is None:
            continue
        if line.rstrip() == '    steps:':
            current['in_steps'] = True
            continue
        if current['in_steps'] and JOB_KEY.match(line):
            current['in_steps'] = False
        if not current['in_steps']:
            current['head'].append((n, line))
            continue
        if STEP.match(line):
            current['steps'].append([])
        if current['steps']:
            current['steps'][-1].append((n, line))
    return preamble, jobs


def uses_of(step):
    for _, line in step:
        match = USES.match(line)
        if match:
            return match.group(1)
    return ''


def commands(step):
    """The shell lines of a step's `run:`, one-line or block form."""
    block_indent = None
    for n, line in step:
        if block_indent is not None:
            if line.strip() and len(line) - len(line.lstrip()) <= block_indent:
                block_indent = None
            elif line.strip() and not line.strip().startswith('#'):
                yield n, line.strip()
                continue
            else:
                continue
        match = RUN.match(line)
        if match:
            rest = match.group(2).strip()
            if rest in ('|', '>', '|-', '>-', '|+', '>+'):
                block_indent = len(match.group(1))
            elif rest:
                yield n, rest


def check(path):
    problems = []
    name = path.name
    preamble, jobs = parse(path)
    on_tags = any(re.match(r'^\s+tags:', line) for _, line in preamble)

    def report(n, message):
        problems.append(f'{name}:{n}: {message}')

    everything = list(preamble)
    for job in jobs.values():
        everything += job['head']
        for step in job['steps']:
            everything += step

    # 1. Pinned actions.
    for n, line in everything:
        match = USES.match(line)
        if match:
            ref = match.group(1)
            if not (PINNED.match(ref) or ref.startswith('./')):
                report(n, f'action not pinned to a full commit SHA: {ref}')

    # 4. Key material only in a step's env.
    def key_refs(lines):
        for n, line in lines:
            for secret in SECRET.findall(line):
                if secret in KEY_MATERIAL and not re.search(EXISTENCE.format(secret), line):
                    yield n, secret

    for n, secret in key_refs(preamble):
        report(n, f'secrets.{secret} is set for the whole workflow; set it in the env of the step that uses it')
    for job_name, job in jobs.items():
        for n, secret in key_refs(job['head']):
            report(n, f'secrets.{secret} is set for all of job {job_name}; set it in the env of the step that uses it')

    for job_name, job in jobs.items():
        saves_go_cache = False
        for step in job['steps']:
            ref = uses_of(step)
            no_cache = any(re.match(r'^\s+cache:\s*false\s*$', line) for _, line in step)
            first = step[0][0]
            # 2. Tag workflows restore no Actions cache.
            if on_tags and ref.startswith('actions/setup-go@') and not no_cache:
                report(first, f'setup-go in {job_name} restores the Actions cache on a release tag; add `cache: false`')
            if on_tags and ref.startswith('actions/cache'):
                report(first, f'{job_name} uses actions/cache on a release tag')
            if ref.startswith('actions/setup-go@') and not no_cache:
                saves_go_cache = True
            # 5. Docker layer cache only off release tags.
            if on_tags:
                for n, line in step:
                    match = GHA_CACHE.match(line)
                    if match and match.group(2).strip() and TAG_GUARD not in match.group(2):
                        report(n, f'{match.group(1)} in {job_name} also applies on a release tag; guard it with {TAG_GUARD}')
        # 3. No npm package code in a job that saves a Go cache.
        if saves_go_cache:
            for step in job['steps']:
                for n, command in commands(step):
                    if NPM.search(command) and not NPM_OK.search(command):
                        report(n, f'{job_name} saves a Go cache and runs npm package code: use `npm ci --ignore-scripts` or `cache: false`')
    return problems


def main():
    root = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parents[1] / 'workflows'
    files = sorted(root.glob('*.yml')) + sorted(root.glob('*.yaml'))
    if not files:
        print(f'no workflows found in {root}', file=sys.stderr)
        return 2
    problems = [problem for path in files for problem in check(path)]
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        print(f'workflow policy: {len(problems)} problem(s) in {len(files)} workflows', file=sys.stderr)
        return 1
    print(f'workflow policy: {len(files)} workflows, every rule holds')
    return 0


if __name__ == '__main__':
    sys.exit(main())
