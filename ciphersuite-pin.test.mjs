// ciphersuite-pin.test.mjs — вторая половина KV-11-006: закрепить ПРЕМИССУ, а не только поведение.
//
// ЧТО ДОКАЗАНО ГДЕ. Что чужой шифронабор не пускают — доказывают два поведенческих теста в самом
// крейте (`dispatch/tests.rs`: подменённый Welcome и чужой KeyPackage на добавлении). Они покраснеют,
// если OpenMLS сменит ПОВЕДЕНИЕ. Но есть второй способ потерять свойство, которого поведенческий тест
// не видит: сменить КОНФИГУРАЦИЮ — версию библиотеки, набор её фич, криптопровайдер. Тогда тесты
// по-прежнему зелёные, а рассуждение, на котором всё держится, уже про другую библиотеку.
//
// Это четвёртое правило семейства, применённое буквально: живой тест доказывает утверждение только
// про ту конфигурацию, в которой бежал. Стоило оно KV-05-001 — два месяца на проде.
//
// ПОЧЕМУ ХВАТАЕТ ПИНА ВЕРСИИ. Версии на crates.io НЕИЗМЕНЯЕМЫ: `openmls =0.9.0-rc.1` — это всегда
// один и тот же исходник. Значит семь контролей, перечисленных в шапке `policy::assert_ciphersuite`,
// заморожены вместе с пином, и сломать премиссу можно ровно тремя способами, каждый виден в
// Cargo.toml / Cargo.lock:
//   1. поднять версию openmls;
//   2. поменять список фич (особенно включить `virtual-clients-draft` — он открывает путь вступления,
//      которого наши поведенческие тесты не проходят);
//   3. сменить криптопровайдера (набор поддерживаемых шифронаборов — его свойство, не наше).
//
// ЧЕГО ЭТОТ ТЕСТ НЕ ДОКАЗЫВАЕТ, вслух: он не читает исходники OpenMLS, если реестра cargo нет на
// машине. Когда реестр есть — семь мест сверяются по-настоящему, и об этом печатается строка. Когда
// нет — печатается, что не сверялось. «Не смог прочитать» ≠ «всё на месте».
//
//   node ciphersuite-pin.test.mjs

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';

const HERE = dirname(fileURLToPath(import.meta.url));
const read = (p) => { try { return readFileSync(p, 'utf8'); } catch { return ''; } };

let passed = 0, total = 0;
const check = (l, c, e = '') => { total++; console.log(`  [${c ? 'PASS' : 'FAIL'}] ${l}${e ? ' — ' + e : ''}`); if (c) passed++; };

// Конфигурация, ПРОТИВ КОТОРОЙ проведён разбор KV-11-006. Меняется — разбор надо переделать, и
// красное здесь именно об этом, а не о поломке.
const PINNED_OPENMLS = '0.9.0-rc.1';
const PINNED_FEATURES = ['draft-ietf-mls-pq-ciphersuites'];
const PINNED_PROVIDER = 'openmls_libcrux_crypto';
// Семь мест внутри OpenMLS, которыми свойство и держится. Файл + опорная строка (не номер: номера
// плывут, а текст в неизменяемой версии — нет).
const SITES = [
  ['src/group/mls_group/creation.rs', 'WelcomeError::UnsupportedCiphersuite'],
  ['src/group/mls_group/creation.rs', 'welcome.ciphersuite() != key_package_bundle.key_package().ciphersuite()'],
  ['src/group/mls_group/creation.rs', 'verifiable_group_info.ciphersuite() != key_package_bundle.key_package().ciphersuite()'],
  ['src/group/mls_group/creation.rs', 'material.key_package_ciphersuite != ciphersuite'],
  ['src/group/public_group/validation.rs', 'add_proposal.add_proposal().key_package().ciphersuite() != self.ciphersuite()'],
  ['src/messages/proposals_in.rs', 'key_package.ciphersuite() != ciphersuite'],
  ['src/group/public_group/validation.rs', 'contains_ciphersuite'],
];

console.log('\n==== ШИФРОНАБОР: ЧЕМ ЗАКРЕПЛЕНА ПРЕМИССА РАЗБОРА ====');

const toml = read(join(HERE, 'Cargo.toml'));
const lock = read(join(HERE, 'Cargo.lock'));
check('КОНТРОЛЬ: Cargo.toml прочитан', /\[dependencies\]/.test(toml) && toml.length > 1000);
check('КОНТРОЛЬ: Cargo.lock прочитан', /\[\[package\]\]/.test(lock) && lock.length > 1000);

// ---- 1. версия прибита ТОЧНО ---------------------------------------------------------------------
{
  const m = toml.match(/^openmls = \{ version = "=([^"]+)", features = \[([^\]]*)\] \}/m);
  check('🔴 openmls прибит ТОЧНОЙ версией (=), а не диапазоном — иначе премисса плывёт молча', !!m,
    m ? '' : 'строка openmls = { version = "=…" } не найдена');
  if (m) {
    check(`🔴 версия ровно ${PINNED_OPENMLS} — разбор KV-11-006 проведён против неё`,
      m[1] === PINNED_OPENMLS, m[1]);
    const feats = m[2].split(',').map((f) => f.trim().replace(/^"|"$/g, '')).filter(Boolean);
    check('🔴 список фич ровно тот, против которого считали',
      feats.length === PINNED_FEATURES.length && PINNED_FEATURES.every((f) => feats.includes(f)),
      feats.join(', '));
  }
  // \r\n: файл лежит в рабочей копии с CRLF. Первая редакция искала голый \n и не находила НИЧЕГО —
  // то есть краснела бы на ЛЮБОЙ версии, включая правильную. Проверка, которая не может стать
  // зелёной, бесполезна так же, как та, которая не может стать красной.
  const lockVer = (lock.match(/name = "openmls"\r?\nversion = "([^"]+)"/) || [])[1];
  check('🔴 и Cargo.lock согласен с пином (сборка идёт против того же исходника)',
    lockVer === PINNED_OPENMLS, String(lockVer));
}

// ---- 2. virtual-clients-draft ВЫКЛЮЧЕН -----------------------------------------------------------
// Он открывает второй путь вступления (creation.rs:723), которого поведенческие тесты не проходят.
// Включат — красное здесь скажет: «сначала проверь этот путь, потом включай».
{
  check('🔴 virtual-clients-draft нигде не включён', !/virtual-clients-draft/.test(toml + lock));
}

// ---- 3. провайдер тот же -------------------------------------------------------------------------
// Набор поддерживаемых шифронаборов — свойство ПРОВАЙДЕРА. Поведенческий тест опирается на то, что
// 0x0001 поддерживается (иначе отказ приходил бы из supports(), а не из сравнения с KeyPackage).
{
  const m = toml.match(new RegExp('^' + PINNED_PROVIDER + ' = \\{ version = "=([^"]+)"', 'm'));
  check(`🔴 криптопровайдер по-прежнему ${PINNED_PROVIDER}, прибитый точно`, !!m, m ? m[1] : 'не найден');
}

// ---- 4. наш собственный вызов на месте -----------------------------------------------------------
// Тот единственный, который не декоративен: загрузка группы из хранилища (четвёртый вход).
{
  const client = read(join(HERE, 'src/client.rs'));
  const policy = read(join(HERE, 'src/policy.rs'));
  check('КОНТРОЛЬ: client.rs прочитан', /fn group_mut/.test(client));
  check('🔴 assert_ciphersuite ВЫЗЫВАЕТСЯ из group_mut — вход, которого нет ни в одном из семи мест',
    /fn group_mut[\s\S]{0,3000}assert_ciphersuite\(/.test(client));
  check('🔴 и шапка перечисляет, кто держит свойство на самом деле (было: врала)',
    /creation\.rs:168/.test(policy) && /validation\.rs:383/.test(policy));
  check('🔴 в шапке записано, что в проде функция звалась ноль раз и почему это нормально',
    /НЕ дыра|не дыра/.test(policy));
}

// ---- 4a. §10.11: отбраковка Welcome стоит ДО OpenMLS и её нельзя обойти -------------------------
// Правило «тест на место»: свойство здесь — не «проверка существует», а «проверка стоит РАНЬШЕ
// потребления KeyPackage». Обойти её можно ровно одним способом — завести второй вход, зовущий
// build_from_welcome напрямую. Поэтому считаем вызовы.
{
  const dispatch = read(join(HERE, 'src/dispatch.rs'));
  check('КОНТРОЛЬ: dispatch.rs прочитан', /fn dispatch_welcome/.test(dispatch));
  const calls = (dispatch.match(/StagedWelcome::build_from_welcome/g) || []).length;
  check('🔴 build_from_welcome вызывается РОВНО ОДИН раз — второй вход обошёл бы отбраковку',
    calls === 1, `${calls} вызов(ов)`);
  const body = dispatch.slice(dispatch.indexOf('pub fn dispatch_welcome'));
  const iGuard = body.indexOf('assert_ciphersuite(');
  const iBuild = body.indexOf('StagedWelcome::build_from_welcome');
  check('🔴 и отбраковка стоит ДО него — после неё KeyPackage уже потреблён',
    iGuard >= 0 && iGuard < iBuild, `guard@${iGuard} build@${iBuild}`);
  const client = read(join(HERE, 'src/client.rs'));
  check('КОНТРОЛЬ: вступление в группу идёт через dispatch_welcome, а не мимо',
    /dispatch_welcome\(&\*provider/.test(client) && !/build_from_welcome/.test(client));
}

// ---- 5. семь мест — по-настоящему, когда реестр доступен -----------------------------------------
{
  const cargoHome = process.env.CARGO_HOME || join(homedir(), '.cargo');
  const regRoot = join(cargoHome, 'registry', 'src');
  let src = '';
  if (existsSync(regRoot)) {
    for (const d of readdirSync(regRoot)) {
      const cand = join(regRoot, d, `openmls-${PINNED_OPENMLS}`);
      if (existsSync(cand)) { src = cand; break; }
    }
  }
  if (!src) {
    // НЕ «пропущено молча»: печатаем и считаем непроверенным. Реестра нет — значит крейт тут ни разу
    // не собирали, и утверждать про его исходники нечего.
    console.log('  [ ?? ] исходники openmls НЕ СВЕРЯЛИСЬ: реестр cargo не найден (' + regRoot + ')');
    console.log('         это не «всё хорошо», это «здесь не проверено» — сверка идёт там, где крейт собирают');
  } else {
    let found = 0;
    for (const [file, needle] of SITES) {
      if (read(join(src, file)).includes(needle)) found++;
    }
    check(`🔴 все семь контролей шифронабора на месте в openmls ${PINNED_OPENMLS}`,
      found === SITES.length, `${found} из ${SITES.length}`);
    // КОНТРОЛЬ на сам способ: заведомо отсутствующая строка НЕ должна находиться, иначе проверка выше
    // зелёная просто потому, что includes() всегда true.
    check('КОНТРОЛЬ: заведомо отсутствующая строка не находится',
      !read(join(src, SITES[0][0])).includes('KvantDefinitelyNotInOpenMls'));
  }
}

console.log(`\n  пин шифронабора: ${passed}/${total} checks passed`);
console.log('=====================================================');
if (passed !== total) process.exit(1);
