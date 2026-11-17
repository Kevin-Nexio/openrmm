import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/postcss';
import postcss from 'postcss';

// The stylesheet as scripts/build.mjs compiles it (Tailwind 4 through
// @tailwindcss/postcss), unminified, compiled once for every test below.
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const stylesPath = path.join(root, 'src/styles.css');
const styles = await readFile(stylesPath, 'utf8');
const css = (await postcss([tailwindcss({ base: root, optimize: { minify: false } })])
  .process(styles, { from: stylesPath })).css;
const sources = await Promise.all((await readdir(path.join(root, 'src')))
  .filter((name) => name.endsWith('.jsx'))
  .map((name) => readFile(path.join(root, 'src', name), 'utf8')));
const html = await readFile(path.join(root, 'index.html'), 'utf8');
const classTokens = new Set([...sources, html].flatMap((source) =>
  [...source.matchAll(/["'`]([^"'`\n]*)["'`]/g)].flatMap((m) => m[1].split(/\s+/)).filter(Boolean)));
const escape = (name) => name.replace(/[/:.[\]]/g, (c) => '\\' + c);
const generated = (name) => css.includes('.' + escape(name) + ' ') || css.includes('.' + escape(name) + '{')
  || css.includes('.' + escape(name) + ':') || css.includes('.' + escape(name) + ',');

test('the console builds with Tailwind 4 and keeps its theme in the stylesheet', () => {
  assert.match(styles, /^@import "tailwindcss" source\(none\);$/m);
  assert.doesNotMatch(styles, /@tailwind (base|components|utilities)/);
  assert.match(css, /--color-panel: var\(--panel\)/);
  assert.match(css, /--radius-xl: 10px/);
  assert.ok(generated('rounded-xl') && generated('bg-panel') && generated('animate-fade-in'));
});

// The status colours are chosen at runtime (`text-${tone}`), so only the
// inline source makes Tailwind generate them.
test('the runtime status colours are generated', () => {
  for (const name of ['text-ok', 'text-warn', 'text-run', 'text-bad', 'text-muted', 'fill-ok', 'fill-warn', 'fill-bad']) {
    assert.ok(generated(name), `${name} is missing from the stylesheet`);
  }
});

// Tailwind 3 never rendered an opacity on the var() palette; those classes
// stay off so the upgrade changes nothing visible.
test('the palette opacity classes Tailwind 3 never rendered stay off', () => {
  for (const name of ['bg-elevated/40', 'hover:bg-elevated/40', 'border-warn/25', 'bg-panel/70', 'focus:ring-brand/25', 'bg-warn/[0.04]', 'text-faint/70']) {
    assert.ok(classTokens.has(name), `${name} is no longer used; drop it from the dormant list`);
    assert.ok(!generated(name), `${name} is generated, which changes how the console looks`);
  }
});

// Tailwind 4 spaces children with :where(> :not(:last-child)) and no
// specificity; the console keeps Tailwind 3's rule for every stack it uses.
test('every space-y and divide class in use keeps Tailwind 3 semantics', () => {
  const stacks = [...classTokens].filter((name) => /^(?:[a-z]+:)?(?:space-[xy]|divide)(?:-|$)/.test(name));
  assert.ok(stacks.length > 5, 'expected the console to use stacks');
  for (const name of stacks) {
    const v3 = '.' + escape(name) + ' > :not([hidden]) ~ :not([hidden])';
    assert.ok(css.includes(v3), `${name} has no Tailwind 3 rule in src/styles.css ("Tailwind 3 stacks")`);
    assert.ok(!css.includes(':where(.' + escape(name) + ' > :not(:last-child))'), `${name} is also generated with Tailwind 4's selector`);
  }
});

test('Tailwind 3 defaults the console relied on are kept', () => {
  assert.match(css, /border-color: #e5e7eb/, 'bare borders keep the gray-200 default');
  assert.match(css, /var\(--tw-ring-color, ?#3b82f680\)/, 'rings without a colour keep blue-500 at 50%');
  assert.match(css, /input::placeholder, textarea::placeholder \{\s*color: #9ca3af;/);
  assert.match(css, /td, th, option \{\s*padding: revert-layer;/, 'table cells keep the browser padding');
  // The skeleton sweep sits at -translate-x-full; its keyframes must animate the
  // same property or the sweep stops halfway.
  assert.match(css, /@keyframes shimmer \{\s*100% \{\s*translate: 100%;/);
});

// The console's own rules must not beat every utility: in Tailwind 3 an input
// with a utility font kept it over `textarea, input { font-family: inherit }`.
test('the console rules sit in the utilities layer, after the utilities', () => {
  const layered = styles.slice(styles.lastIndexOf('@layer utilities {'));
  assert.match(layered, /textarea, input \{ font-family: inherit; \}/);
  assert.match(layered, /:root \{/);
});
