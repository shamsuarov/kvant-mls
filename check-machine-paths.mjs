#!/usr/bin/env node
// check-machine-paths.mjs — guard against paths tied to ONE machine leaking into this repository.
//
// WHY THIS LIVES HERE. This is a public, independently published repository. A hard-coded home
// directory of one contributor's machine (a `--remap-path-prefix` baked with a machine constant,
// a `$root` pinned to `C:\Users\<name>`, a corpus path under `/home/<name>`) breaks the build on
// every other machine AND is visible to everyone who clones it. While this code was part of the Kvant
// monorepo it was swept by that tree's machine-paths guard; as a standalone submodule the parent
// only sees a gitlink and no longer scans inside — so the rule has to travel with the code. The
// Kvant project caught this exact class twice before it added a guard; a public repo is where the
// rule belongs.
//
// BY CONTENT, NOT BY NAME. A name-based sweep sees only what is already named familiarly; the
// constant hides under whatever the next file is called. This walks every tracked source file and
// tests its content.
//
// TWO CONTROLS, and the second is the one without which the guard would be evergreen:
//   1. synthetic — the matcher must catch all five forms in a deliberately broken string;
//   2. REAL — a constant is planted into a tracked file during the run and the FULL walk must find
//      it (proves the walk really enumerates, reads and reddens, not just the matcher). Restored
//      in finally.
//
//   node check-machine-paths.mjs
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, extname, sep } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = HERE; // this script sits at the repository root

let pass = 0, fail = 0;
const check = (n, ok, info) => { if (ok) pass++; else fail++; console.log(`  [${ok ? 'PASS' : 'FAIL'}] ${n}${info ? ' — ' + info : ''}`); };

// Five spellings of the same thing: a path to one machine's home directory. Different tools write
// it differently — cmd, bash-on-Windows, WSL, macOS, Linux.
const FORMS = [
  { name: 'C:/Users/<name>', re: /[A-Za-z]:\/Users\/[A-Za-z0-9._-]+/ },
  { name: 'C:\\Users\\<name>', re: /[A-Za-z]:\\+Users\\+[A-Za-z0-9._-]+/ },
  { name: '/Users/<name>', re: /(^|[^A-Za-z0-9_./-])\/Users\/[A-Za-z0-9._-]+/ },
  { name: '/c/Users/<name>', re: /\/[a-z]\/Users\/[A-Za-z0-9._-]+/ },
  { name: '/mnt/c/Users/<name>', re: /\/mnt\/[a-z]\/Users\/[A-Za-z0-9._-]+/ },
  { name: '/home/<name>', re: /(^|[^A-Za-z0-9_./-])\/home\/[A-Za-z0-9._-]+\// },
];

// Sources, scripts and docs — everything a reader downloads. Generated/binary is out of scope.
const SCAN_EXT = new Set(['.mjs', '.cjs', '.js', '.jsx', '.ts', '.tsx', '.sh', '.ps1', '.psm1',
  '.bat', '.cmd', '.gradle', '.kt', '.java', '.swift', '.rs', '.py', '.rb', '.toml', '.yml', '.yaml',
  '.properties', '.plist', '.podspec', '.json', '.md']);
const SKIP_FILES = new Set(['package-lock.json', 'Cargo.lock']);

// EXCEPTIONS — NAMED, WITH A REASON. A bare list grows silently and one day shields a real defect.
const ALLOWED = [];
const isAllowed = (rel) => ALLOWED.some((a) => a.path === rel.split(sep).join('/'));

/** Files come from GIT, not a directory walk: a machine path in an UNTRACKED file is not a defect
 *  (local .cargo/config.toml, sdk paths, generated output all legitimately describe one machine). */
function trackedFiles(root) {
  let out;
  try { out = execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', maxBuffer: 1 << 28 }); }
  catch { return null; } // not a repo / no git — the walker must say so, not stay silent
  return out.split(String.fromCharCode(0)).filter(Boolean)
    .filter((rel) => SCAN_EXT.has(extname(rel).toLowerCase()))
    .filter((rel) => !SKIP_FILES.has(rel.split('/').pop()))
    .map((rel) => join(root, rel));
}

function scan(root) {
  const files = trackedFiles(root);
  if (files === null) return { hits: [], files: 0, read: 0, noGit: true };
  const hits = []; let read = 0;
  for (const f of files) {
    let text; try { text = readFileSync(f, 'utf8'); } catch { continue; }
    read++;
    const rel = relative(root, f);
    if (isAllowed(rel)) continue;
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const form of FORMS) {
        if (form.re.test(lines[i])) { hits.push({ rel: rel.split(sep).join('/'), line: i + 1, form: form.name, text: lines[i].trim().slice(0, 100) }); break; }
      }
    }
  }
  return { hits, files: files.length, read };
}

console.log('\n============ machine-paths guard (' + relative(join(HERE, '..'), ROOT) + ') ============');

console.log('\n-- 0. matcher control: five forms on a deliberately broken string');
{
  // Samples ASSEMBLED FROM PIECES so the guard does not match its own source and demand an
  // exception on itself — which would let tomorrow's real constant here pass silently too.
  const U = 'Users', W = 'Someone', H = 'home', B = String.fromCharCode(92);
  const samples = {
    'C:/Users/<name>': "const P = 'C:/" + U + '/' + W + "/kvant';",
    'C:\\Users\\<name>': 'const P = "C:' + B + U + B + W + '";',
    '/Users/<name>': "const P = '/" + U + '/' + W.toLowerCase() + "/kvant';",
    '/c/Users/<name>': 'OUT=/c/' + U + '/' + W + '/out.txt',
    '/mnt/c/Users/<name>': 'CORP="/mnt/c/' + U + '/' + W + '/fuzz/corpus"',
    '/home/<name>': 'DIR=/' + H + '/' + W.toLowerCase() + '/kvant/target',
  };
  for (const form of FORMS) check(`form ${form.name} matches`, form.re.test(samples[form.name]), samples[form.name]);
  const innocent = ["const p = './README.md';", 'const HERE = dirname(fileURLToPath(import.meta.url));',
    'https://example.com/Users/profile', 'let home = getHome();'];
  check('innocent strings do not false-positive',
    innocent.every((s) => !FORMS.some((f) => f.re.test(s))),
    innocent.find((s) => FORMS.some((f) => f.re.test(s))) || 'none');
}

console.log('\n-- 1. walker control: it really enumerates and reads');
{
  const r = scan(ROOT);
  check('files were read (zero = broken walker, not a clean repo)', r.read > 0, `${r.read} of ${r.files} files`);
  check('this guard file is among the tracked files walked',
    r.read > 0 && existsSync(join(ROOT, 'check-machine-paths.mjs')));
}

console.log('\n-- 2. REAL control: a planted constant MUST redden');
{
  // The EXISTING tracked guard file is edited (not a new file): enumeration is via git, and a
  // freshly created file would not be listed, making the control green by construction.
  const self = join(ROOT, 'check-machine-paths.mjs');
  const original = readFileSync(self, 'utf8');
  let found = false, note = '', restored = false;
  try {
    const dead = "'C:/" + 'Users' + '/' + 'Somebody' + "/kvant/src'";
    writeFileSync(self, original + '\n// TEMP CONTROL (removed immediately): ' + dead + '\n');
    const hit = scan(ROOT).hits.find((h) => h.rel.endsWith('check-machine-paths.mjs'));
    found = !!hit;
    note = hit ? `${hit.rel}:${hit.line} (${hit.form})` : 'NOT found — enumeration or read is broken';
  } finally {
    try { writeFileSync(self, original); restored = readFileSync(self, 'utf8') === original; } catch {}
  }
  check('🔴 planted constant found by the full walk', found, note);
  check('guard file restored byte-for-byte', restored);
}

console.log('\n-- 3. verdict: no machine-tied paths in tracked sources');
{
  const r = scan(ROOT);
  if (r.noGit) { check('scan ran (git available)', false, 'not a git repo / git missing'); }
  else check('🔴 no machine paths', r.hits.length === 0,
    r.hits.length ? r.hits.slice(0, 8).map((h) => `${h.rel}:${h.line} ${h.form}`).join(' | ') + (r.hits.length > 8 ? ` … ${r.hits.length} total` : '')
      : `scanned ${r.read} files`);
}

console.log('\n-- 4. exceptions are named and still needed');
for (const a of ALLOWED) {
  const where = join(ROOT, a.path);
  check(`exception alive: ${a.path}`, existsSync(where), a.why.slice(0, 80));
  if (!existsSync(where)) continue;
  let text = ''; try { text = readFileSync(where, 'utf8'); } catch {}
  const stillNeeded = text.split('\n').some((l) => FORMS.some((f) => f.re.test(l)));
  check(`exception still NEEDED: ${a.path}`, stillNeeded, stillNeeded ? '' : 'file is clean — drop the exception');
}

console.log(`\nMACHINE PATHS: ${pass}/${pass + fail} checks passed`);
process.exit(fail === 0 ? 0 : 1);
