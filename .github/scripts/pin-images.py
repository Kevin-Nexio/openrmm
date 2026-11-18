#!/usr/bin/env python3
"""Pin the self-hosted deployment files to one release's images.

    pin-images.py <version> --server <digest> --frontend <digest> --artifacts <digest> <file>...

<version> has no leading "v" (0.11.3); each <digest> is sha256:<64 hex>. Files:

  docker-compose.images.yml  the three image defaults,
                             ghcr.io/<owner>/openrmm-{server,frontend,artifacts}:<v>@sha256:...,
                             become <version>@<digest>
  README-production.md       the one `--build-arg VERSION=<v>` becomes <version>

The release workflow runs it on the tag's compose file, which it attaches to the
release, and on main's files, for the pull request that moves main's pins. Every
pattern must match exactly once in its file and nothing else changes: anything
else stops the script before it writes a single file.
"""
import argparse
import os
import re
import sys

VERSION = re.compile(r'^\d+\.\d+\.\d+([+-][0-9A-Za-z.-]+)?$')
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
IMAGES = ('server', 'frontend', 'artifacts')
TAG = r'[0-9A-Za-z.+-]+'


def image_line(name):
    return re.compile(r'(ghcr\.io/[a-z0-9._-]+/openrmm-' + name + r'):' + TAG + r'@sha256:[0-9a-f]{64}')


BUILD_ARG = re.compile(r'(--build-arg VERSION=)' + TAG)


def pin(path, text, version, digests):
    base = os.path.basename(path)
    if base == 'docker-compose.images.yml':
        rules = [(image_line(n), lambda m, n=n: f'{m.group(1)}:{version}@{digests[n]}', f'openrmm-{n}')
                 for n in IMAGES]
    elif base == 'README-production.md':
        rules = [(BUILD_ARG, lambda m: f'{m.group(1)}{version}', '--build-arg VERSION=')]
    else:
        raise SystemExit(f'{path}: not a file this script pins')
    for pattern, repl, what in rules:
        text, count = pattern.subn(repl, text)
        if count != 1:
            raise SystemExit(f'{path}: expected one {what} pin, found {count}')
    return text


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('version')
    for name in IMAGES:
        ap.add_argument(f'--{name}', required=True, metavar='DIGEST')
    ap.add_argument('files', nargs='+')
    args = ap.parse_args(argv)
    if not VERSION.match(args.version):
        raise SystemExit(f'not a release version: {args.version!r}')
    digests = {n: getattr(args, n) for n in IMAGES}
    for name, digest in digests.items():
        if not DIGEST.match(digest):
            raise SystemExit(f'--{name}: not a sha256 digest: {digest!r}')
    out = {}
    for path in args.files:
        with open(path, encoding='utf-8') as f:
            out[path] = pin(path, f.read(), args.version, digests)
    for path, text in out.items():
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
        print(f'pinned {path} to {args.version}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
