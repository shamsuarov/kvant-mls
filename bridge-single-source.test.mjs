// bridge-single-source.test.mjs — у RN-моста к крейту ОДИН источник истины.
//
// ЧТО ЭТО ЗА МИНА. `scripts/build-mls-aar.ps1` последним шагом копировал
// `kvant-mls/android/KvantMlsModule.kt` ПОВЕРХ рабочего
// `app/src/main/java/com/kvantrn/KvantMlsModule.kt`. Две копии одного моста, редактировалась одна,
// перезаписывала другая — и увидеть это можно было только собрав .so, то есть в тот самый момент,
// когда правку вводят в строй.
//
// ЦЕНА, ИЗМЕРЕННАЯ 2026-08-27. Расхождение записали ещё 2026-08-11 (IOS-PORT-ANALYSIS, 🟡 «запуск
// as-written регрессирует B1») и не починили. За шестнадцать дней отставание выросло с одного слоя
// B1 до ДЕВЯТИ методов: весь мост C4 (m3PeekFrame / m3MergePending / m3ClearPending / m3GroupEpoch /
// m3GroupStateFp), плюс m3Drop, m3IsLive, m3KekForm и m3SetGroupRoles. Сборка .so для ввода в строй
// KV-03-001 молча отменила бы и KV-03-001, и многоадминные гонки.
//
// НАЗВАННЫЙ, НО НЕ ЗАКРЫТЫЙ ДОЛГ НЕ СТОИТ НА МЕСТЕ — ОН РАСТЁТ. Поэтому здесь сторож, а не ещё
// одна строчка в отчёте.
//
//   node bridge-single-source.test.mjs

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const APPRN = join(HERE, '..', '..');           // app-rn/
const read = (p) => { try { return readFileSync(p, 'utf8'); } catch { return ''; } };

let passed = 0, total = 0;
const check = (l, c, e = '') => { total++; console.log(`  [${c ? 'PASS' : 'FAIL'}] ${l}${e ? ' — ' + e : ''}`); if (c) passed++; };

console.log('\n==== МОСТ К КРЕЙТУ: ОДИН ИСТОЧНИК ИСТИНЫ ====');

// ---- 1. копия в дереве ровно одна ---------------------------------------------------------------
const found = [];
const walk = (dir, depth = 0) => {
  if (depth > 8) return;
  let ents = [];
  try { ents = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of ents) {
    if (e.isDirectory()) {
      if (['node_modules', 'build', 'target', '.gradle', '.cxx'].includes(e.name)) continue;
      walk(join(dir, e.name), depth + 1);
    } else if (e.name === 'KvantMlsModule.kt') {
      found.push(join(dir, e.name));
    }
  }
};
walk(APPRN);
check('КОНТРОЛЬ: мост вообще найден (иначе проверка не проверяет ничего)', found.length >= 1, `${found.length}`);
check('🔴 KvantMlsModule.kt в дереве РОВНО ОДИН',
  found.length === 1, found.map((p) => p.slice(APPRN.length + 1)).join(' | '));
check('и лежит он там, где его компилируют',
  found.length === 1 && found[0].replace(/\\/g, '/').endsWith('app/src/main/java/com/kvantrn/KvantMlsModule.kt'),
  found[0] || '');

// ---- 2. сборочный скрипт его не перезаписывает ---------------------------------------------------
{
  const ps1 = read(join(HERE, 'scripts', 'build-mls-aar.ps1'));
  check('КОНТРОЛЬ: сборочный скрипт прочитан', /cargo ndk/.test(ps1));
  check('🔴 скрипт НЕ копирует мост поверх рабочего файла',
    !/Copy-Item[^\n]*KvantMlsModule\.kt/i.test(ps1));
  check('и причина записана рядом, чтобы шаг не «вернули как было»',
    /мина|мину|источник истины/i.test(ps1));
}

// ---- 3. мост покрывает то, что крейт экспортирует ------------------------------------------------
// Расхождение росло не потому, что кто-то злонамеренно, а потому что его нечем было заметить.
// Здесь оно замечается: каждый FFI-метод крейта должен иметь мост, либо стоять в списке исключений.
{
  const client = read(join(HERE, 'src', 'client.rs'));
  const kt = read(found[0] || '');
  // Публичные методы MlsClient — то, что uniffi выносит наружу.
  const ffi = [...client.matchAll(/^    pub fn ([a-z_0-9]+)\(/gm)].map((m) => m[1])
    .filter((n) => n !== 'new');
  // Не мостится намеренно: чисто внутренние/для тестов и то, что JS вызывает иначе.
  const NOT_BRIDGED = ['fixture_a', 'process_stateful', 'emit_seeds_a', 'op_sequence'];
  const camel = (s) => s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
  const missing = ffi.filter((n) => !NOT_BRIDGED.includes(n) && !kt.includes(camel(n) + '('));
  check('КОНТРОЛЬ: FFI-методы крейта найдены', ffi.length >= 15, `${ffi.length}`);
  check('🔴 каждый FFI-метод крейта имеет мост (или назван исключением)',
    missing.length === 0, missing.join(', '));
}

console.log(`\n  один источник моста: ${passed}/${total} checks passed`);
console.log('=============================================');
if (passed !== total) process.exit(1);
