//! panichook.rs — A-CRASH-FIX §2: паника Rust оставляет след БЕЗ adb.
//!
//! ── ЧТО БЫЛО СЛЕПЫМ ─────────────────────────────────────────────────────────────────────────
//! У приложения есть свой журнал (`kvant-diag.log`), и весь его смысл — «разбирать без USB».
//! Нативная половина в него не попадала ВООБЩЕ:
//!
//!   * у крейта не было `panic::set_hook`, поэтому текст и МЕСТО паники не печатались никуда;
//!   * наружу выходил либо `MlsError::Mls("panic caught in {label}")` — и только для трёх мест,
//!     обёрнутых в `guard` (lib.rs), — либо общий `InternalException` от uniffi. Оба ответа не
//!     называют ни файла, ни строки;
//!   * `android_logger` в зависимостях нет, значит и в logcat паника не писалась.
//!
//! Итог измеренный: полевой краш-цикл на планшете не оставил в `kvant-diag.log` ни одной строки,
//! и отличить «нативный краш» от «ОС убила процесс» по нашему журналу было НЕЛЬЗЯ.
//!
//! ── ЧТО ДЕЛАЕТ ЭТОТ МОДУЛЬ ──────────────────────────────────────────────────────────────────
//! Ставит один процессный хук, который на КАЖДУЮ панику (а не только на пойманную `guard`) пишет
//! одну строку в два места: в `kvant-diag.log` рядом с записями JS и в logcat под своим тегом.
//! Хук срабатывает ДО раскрутки стека, то есть и тогда, когда паника дальше превратится в abort
//! (двойная паника, паника в `Drop`) — а это ровно тот случай, который сегодня уносит процесс
//! молча.
//!
//! ── ПОЧЕМУ БЕЗ НОВЫХ ЗАВИСИМОСТЕЙ ───────────────────────────────────────────────────────────
//! Крейт входит в релизный провенанс (`Cargo.lock` пинится, сверяется гейтом), и добавить
//! `android_logger` ради одной строки значило бы протащить `log`-фасад и его дерево в аудированное
//! дерево зависимостей. В logcat пишет `liblog` из NDK-сайрута — он есть на любом Android, а
//! объявление `extern "C"` стоит трёх строк. `#[link(name = "log")]` спрятан за
//! `#[cfg(target_os = "android")]`, поэтому статическая сборка для iOS/macOS не меняется вовсе.
//!
//! ── ЧЕГО ХУК НЕ ДЕЛАЕТ, И ЭТО НАМЕРЕННО ─────────────────────────────────────────────────────
//!   * НЕ печатает backtrace: он требует символов, стоит времени в момент аварии и на release-сборке
//!     всё равно бесполезен. Файл и строка — то, за чем сюда придут;
//!   * НЕ паникует сам. Хук, упавший внутри паники, превращает её в abort — то есть ровно в тот
//!     исход, который мы диагностируем. Поэтому здесь нет ни одного `unwrap`, а все отказы
//!     ввода-вывода проглатываются;
//!   * НЕ трогает существующий хук поведения: после записи вызывается прежний хук, поэтому
//!     стандартный вывод Rust (и то, что делает uniffi) сохраняется.

use std::fs::OpenOptions;
use std::io::Write;
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, Once};

/// Тег в logcat. Короткий и уникальный: по нему фильтруют `adb logcat -s`.
pub const LOGCAT_TAG: &str = "KvantRustPanic";

/// Потолок длины строки. Панику печатает уже аварийный код, и простыня в журнале хуже короткой
/// правды: журнал подрезается с головы (diagTrim.js), и длинная запись вытеснит соседние.
const MAX_LINE: usize = 1000;

static INSTALL: Once = Once::new();
static INSTALLED: AtomicBool = AtomicBool::new(false);
/// Путь к журналу приложения. Задаётся Kotlin/Swift — крейт его не знает и знать не должен.
/// `Mutex<Option<String>>`, а не `OnceCell`: путь может прийти позже (модуль создаётся раньше, чем
/// известен каталог) и может смениться при переносе журнала.
static LOG_PATH: Mutex<Option<String>> = Mutex::new(None);

/// Android: запись в logcat через `liblog` NDK. Без крейта-обёртки — см. шапку.
#[cfg(target_os = "android")]
mod logcat {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};

    const ANDROID_LOG_ERROR: c_int = 6;

    #[link(name = "log")]
    extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }

    pub fn write(tag: &str, msg: &str) {
        // CString отказывает на внутреннем NUL — тогда просто молчим: сообщать об отказе
        // логирования некуда, а паниковать здесь нельзя ни при каких условиях.
        if let (Ok(t), Ok(m)) = (CString::new(tag), CString::new(msg)) {
            unsafe { __android_log_write(ANDROID_LOG_ERROR, t.as_ptr(), m.as_ptr()); }
        }
    }
}

#[cfg(not(target_os = "android"))]
mod logcat {
    /// Не-Android: logcat-а нет. Печатаем в stderr — на macOS/iOS это уходит в унифицированный
    /// журнал системы, на хосте видно в прогоне тестов.
    pub fn write(tag: &str, msg: &str) {
        eprintln!("[{tag}] {msg}");
    }
}

/// Куда писать журнал приложения. Пустая строка снимает запись в файл (logcat остаётся).
pub fn set_log_path(path: String) {
    if let Ok(mut p) = LOG_PATH.lock() {
        *p = if path.is_empty() { None } else { Some(path) };
    }
}

fn append_line(line: &str) {
    let path = match LOG_PATH.lock() {
        Ok(p) => match p.as_ref() {
            Some(s) => s.clone(),
            None => return,
        },
        // Мьютекс отравлен — то есть мы УЖЕ внутри паники, случившейся при взятом замке.
        // Восстанавливаемся намеренно: потерять запись именно в этот момент значит потерять
        // единственную, ради которой всё это писалось.
        Err(poisoned) => match poisoned.into_inner().as_ref() {
            Some(s) => s.clone(),
            None => return,
        },
    };
    // ОДНОЙ записью: журнал пишет и JS, и мы. Короткая запись в режиме O_APPEND не рвётся
    // пополам, а два `write` — рвутся, и в журнале появилась бы половина чужой строки.
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Одна строка про панику: место, причина и пометка про отравленный замок.
///
/// Формат намеренно совпадает по форме с записями JS (`[ISO] текст`), чтобы строки читались в
/// одном потоке. Времени у крейта нет (`std::time` даёт только UNIX-эпоху без форматтера, а
/// тащить `chrono` ради метки — та же цена, что и `android_logger`), поэтому метка ставится
/// словом `rust`, а порядок восстанавливается по соседним строкам JS.
pub fn format_panic(info: &panic::PanicHookInfo<'_>) -> String {
    let place = match info.location() {
        Some(l) => format!("{}:{}:{}", l.file(), l.line(), l.column()),
        None => "<место неизвестно>".to_string(),
    };
    let payload = info
        .payload()
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| info.payload().downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "<причина не строка>".to_string());

    // ОТРАВЛЕННЫЙ ЗАМОК НАЗЫВАЕТСЯ СВОИМ ИМЕНЕМ. `lock().unwrap()` на отравленном мьютексе даёт
    // «called `Result::unwrap()` on an `Err` value: PoisonError { .. }» — текст, по которому не
    // видно главного: это НЕ первая авария, а следствие ПРЕДЫДУЩЕЙ паники, случившейся под этим
    // замком. Дальше так будет падать КАЖДЫЙ вызов, до перезапуска процесса. Разница между
    // «сломалось сейчас» и «сломалось раньше, а это эхо» — первое, что нужно знать при разборе.
    let poisoned = payload.contains("PoisonError");

    let mut line = format!(
        "[rust] ПАНИКА в {place}: {payload}{}\n",
        if poisoned {
            " — ОТРАВЛЕННЫЙ ЗАМОК: авария была РАНЬШЕ, это её эхо; так будет падать каждый вызов до перезапуска"
        } else {
            ""
        }
    );
    // Переводы строк внутри причины сломали бы разбор журнала построчно.
    line = line.replace('\r', " ");
    if line.len() > MAX_LINE {
        // Режем по границе символа: строка идёт в UTF-8 файл, обрезанный посередине символа
        // сделал бы её нечитаемой целиком.
        let mut cut = MAX_LINE;
        while cut > 0 && !line.is_char_boundary(cut) { cut -= 1; }
        line.truncate(cut);
        line.push_str("…\n");
    }
    let body_end = line.len() - 1;
    let body = line[..body_end].replace('\n', " ");
    format!("{body}\n")
}

/// Поставить хук. Идемпотентно: второй вызов только обновляет путь.
///
/// Возвращает `true`, если хук стоит (в том числе если он был поставлен раньше) — вызывающему
/// важно знать факт, а не то, в этот ли раз он поставлен.
pub fn install(log_path: String) -> bool {
    set_log_path(log_path);
    INSTALL.call_once(|| {
        let prev = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let line = format_panic(info);
            // Сначала logcat: он дешевле и не зависит от файловой системы, которая в момент
            // аварии может быть тем, что и сломалось.
            logcat::write(LOGCAT_TAG, line.trim_end());
            append_line(&line);
            // Прежний хук — последним: пусть Rust и uniffi отработают как раньше.
            prev(info);
        }));
        INSTALLED.store(true, Ordering::SeqCst);
    });
    INSTALLED.load(Ordering::SeqCst)
}

/// Стоит ли хук. Для самопроверки на устройстве.
pub fn is_installed() -> bool {
    INSTALLED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::AssertUnwindSafe;

    /// ВСЁ ОДНИМ ТЕСТОМ, И СЧЁТ — ТОЛЬКО ПО СВОИМ СТРОКАМ. Ни то, ни другое не лень.
    ///
    /// Хук паники ПРОЦЕССНЫЙ: один на процесс, с одним путём к журналу. `cargo test` гоняет тесты
    /// параллельно в ОДНОМ процессе, и это ударило дважды, обе редакции покраснели по делу:
    ///
    ///   1. два МОИХ теста, ставившие разные пути, писали друг другу в файлы → слиты в один;
    ///   2. ЧУЖИЕ тесты крейта тоже паникуют (например `guard("unit-panic", …)` в lib.rs), и их
    ///      паники честно проходят через тот же хук в тот же файл. Счёт «сколько всего строк»
    ///      поэтому неверен по построению — считать можно только СВОИ.
    ///
    /// Признак своих — место: все паники этого теста происходят в `panichook.rs`. Внешней
    /// сериализации тестов нет намеренно: она была бы враньём про природу хука, который в бою
    /// именно что один на процесс и ловит всё подряд.
    #[test]
    fn panic_leaves_a_named_line_with_place() {
        let dir = std::env::temp_dir().join("kvant-panichook-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("kvant-diag.log");
        let _ = std::fs::remove_file(&path);

        assert!(install(path.to_string_lossy().to_string()), "хук обязан встать");
        assert!(is_installed(), "и обязан об этом говорить");

        // ── 1. ИСКУССТВЕННАЯ ПАНИКА → СТРОКА С МЕСТОМ ────────────────────────────────────────
        // Это и есть требуемая проверка: не «хук поставлен», а «след остался, и по нему видно,
        // где рвануло».
        let line_no = line!() + 2;
        let caught = panic::catch_unwind(AssertUnwindSafe(|| {
            panic!("искусственная паника для проверки журнала");
        }));
        assert!(caught.is_err(), "паника обязана быть пойманной, а не пройти мимо");

        // `mine` — только строки этого теста (см. шапку: в файл пишут и чужие паники крейта).
        let mine = |b: &str| b.lines().filter(|l| l.contains("panichook.rs")).count();
        let body = std::fs::read_to_string(&path).expect("журнал обязан существовать");
        assert!(body.contains("ПАНИКА"), "нет пометки паники: {body}");
        assert!(body.contains("искусственная паника"), "нет причины: {body}");
        assert!(body.contains("panichook.rs"), "нет ФАЙЛА места: {body}");
        assert!(body.contains(&format!(":{line_no}:")), "нет СТРОКИ места ({line_no}): {body}");
        assert!(body.ends_with('\n'), "запись обязана быть одной законченной строкой");
        assert_eq!(mine(&body), 1, "ровно одна строка на одну панику: {body}");

        // ── 2. ОТРАВЛЕННЫЙ ЗАМОК НАЗЫВАЕТСЯ СВОИМ ИМЕНЕМ ────────────────────────────────────
        // Иначе эхо прошлой аварии читается как новая авария, и разбор уходит не туда.
        let m = std::sync::Mutex::new(0u8);
        let _ = panic::catch_unwind(AssertUnwindSafe(|| {
            let _g = m.lock().unwrap();
            panic!("первая авария под замком");
        }));
        let second = panic::catch_unwind(AssertUnwindSafe(|| { drop(m.lock().unwrap()); }));
        assert!(second.is_err(), "второй захват отравленного замка обязан паниковать");

        let body = std::fs::read_to_string(&path).expect("журнал обязан существовать");
        assert_eq!(mine(&body), 3, "три паники — три строки: {body}");
        let last = body.lines().filter(|l| l.contains("panichook.rs")).last().unwrap();
        assert!(last.contains("ОТРАВЛЕННЫЙ ЗАМОК"), "отравление не названо: {last}");
        assert!(last.contains("до перезапуска"), "не сказано, что это навсегда: {last}");

        // ── 3. ДЛИННАЯ ПРИЧИНА НЕ ВЫТЕСНЯЕТ СОСЕДНИЕ ЗАПИСИ ─────────────────────────────────
        // Журнал подрезается с головы (diagTrim.js), и простыня в 5 КБ съела бы окружение аварии
        // — то есть ровно то, ради чего в него смотрят.
        let huge = "я".repeat(5000);
        let _ = panic::catch_unwind(AssertUnwindSafe(move || { panic!("{}", huge); }));

        let body = std::fs::read_to_string(&path).expect("журнал обязан существовать");
        assert_eq!(mine(&body), 4, "подрезка не должна плодить строки: {body}");
        let last = body.lines().filter(|l| l.contains("panichook.rs")).last().unwrap();
        assert!(last.len() <= MAX_LINE + 8, "строка не подрезана: {} байт", last.len());
        assert!(last.ends_with('…'), "подрезка обязана быть видна глазом: {last}");

        // ── 4. ПУСТОЙ ПУТЬ СНИМАЕТ ЗАПИСЬ В ФАЙЛ, НЕ ЛОМАЯ ХУК ──────────────────────────────
        set_log_path(String::new());
        let _ = panic::catch_unwind(AssertUnwindSafe(|| { panic!("в файл не пишем"); }));
        let body_after = std::fs::read_to_string(&path).expect("журнал обязан существовать");
        assert_eq!(mine(&body_after), 4, "с пустым путём файл не трогаем");
    }
}
