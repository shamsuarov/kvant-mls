// policy.rs — M2 version/capability FLOOR and the B2.4 INTERNAL-DOWNGRADE guard.
//
// The auditor's B2.4 (the 4th enforcement point): my three earlier points (creation / Welcome-reject /
// KeyPackage-reject) all guard group *entry*. They do NOT cover an INTERNAL downgrade. required_capabilities
// is a GroupContext extension that can be changed MID-GROUP via a GroupContextExtensions (GCE) proposal.
// A compromised admin / forged Commit can propose LOWERING required_capabilities — e.g. dropping the
// requirement that every member carry the Kvant device-cert binding — which would let future un-bound
// (ghost) leaves in. So process_message MUST reject any Commit / GCE proposal that lowers
// required_capabilities below the floor. This is "monotone up", enforced on COMMIT PROCESSING, not just
// at creation/join. as_validate.rs calls check_no_downgrade() while walking a StagedCommit's proposals.
//
// (The group ciphersuite itself is fixed at creation in MLS and cannot change via GCE, so X-Wing 0x004D
// cannot be swapped mid-group. Кто именно держит это свойство и где — в шапке assert_ciphersuite
// ниже; коротко: семь контролей внутри OpenMLS плюс один наш, на загрузке группы из хранилища.)

use openmls::prelude::{CredentialType, ExtensionType, ProposalType, RequiredCapabilitiesExtension};

/// X-Wing — MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519. The only ciphersuite we permit.
pub const REQUIRED_CIPHERSUITE: u16 = 0x004D;

/// 🔴 LEVELS (auditor Q2): the LOAD-BEARING ghost-defense is `as_validate::validate_leaf` — it runs
/// ALWAYS, on every leaf path, and is what actually keeps un-bound leaves out. The required_capabilities
/// floor and this B2.4 guard are **defense-in-depth**, NOT the primary enforcement. In particular
/// `KVANT_DEVCERT_EXT` below is a capability **marker**: the device-cert travels inside the credential
/// (see as_validate.rs), so the required leaf extension carries no data — it exists only so a
/// downgrade GCE that drops it is detectable. Do not mistake the DiD layer for the enforcement layer.
/// The genuinely meaningful floor item is `CredentialType::Basic` (dropping it would admit non-Basic
/// credentials our decode path rejects anyway — belt and suspenders).
///
/// Capability marker for "this group enforces the Kvant device-cert binding". Private-use range, never
/// collides with a registered MLS extension type.
pub const KVANT_DEVCERT_EXT: ExtensionType = ExtensionType::Unknown(0xF100);

// The FLOOR: what required_capabilities must ALWAYS keep requiring. Monotone — a GCE proposal may ADD
// to these, never drop below them.
//   - KVANT_DEVCERT_EXT: every member must support (carry) the device-cert binding → no un-bound leaf.
//   - CredentialType::Basic: we use BasicCredential + the external account-signature chain (NOT X.509).
const FLOOR_EXTENSIONS: &[ExtensionType] = &[KVANT_DEVCERT_EXT];
const FLOOR_CREDENTIALS: &[CredentialType] = &[CredentialType::Basic];

#[derive(Debug, PartialEq, Eq)]
pub enum DowngradeReject {
    MissingRequiredExtension(ExtensionType),
    MissingRequiredCredential(CredentialType),
    WrongCiphersuite(u16),
}

/// B2.4 core. Reject a proposed required_capabilities that drops any floor requirement. Fail-closed:
/// the proposal must be a SUPERSET of the floor for both extension types and credential types.
pub fn check_no_downgrade(proposed: &RequiredCapabilitiesExtension) -> Result<(), DowngradeReject> {
    for e in FLOOR_EXTENSIONS {
        if !proposed.extension_types().contains(e) {
            return Err(DowngradeReject::MissingRequiredExtension(*e));
        }
    }
    for c in FLOOR_CREDENTIALS {
        if !proposed.credential_types().contains(c) {
            return Err(DowngradeReject::MissingRequiredCredential(*c));
        }
    }
    Ok(())
}

/// Шифронабор группы обязан быть X-Wing (0x004D).
///
/// 🔴 ЧТО ЗДЕСЬ РАНЬШЕ БЫЛО НАПИСАНО И ПОЧЕМУ ЭТО ВАЖНО. Прежняя шапка гласила: «a Welcome/creation
/// path asserts it so a low-ciphersuite group is never adopted». ТАКОГО ВЫЗОВА НЕТ И НЕ БЫЛО —
/// функция звалась только из собственного юнит-теста (KV-11-006). Это третий за двое суток случай
/// одного класса: шапка `safety.ts` СЛОВАМИ требовала латча чтения, которого в коде не было, а
/// строка «joining ungated» в CallGroupScreen описывала поведение, которого не было. Комментарий,
/// описывающий несуществующее поведение, хуже отсутствующего: он снимает у читателя вопрос, и
/// следующий человек не спросит, кто ЖЕ на самом деле держит свойство.
///
/// ДЕРЖИТ ЕГО OpenMLS — снято с исходников `openmls =0.9.0-rc.1` (версии на crates.io неизменяемы,
/// поэтому пин версии замораживает и этот список; следит `mlsCiphersuitePin.test.mjs`):
///   1. `creation.rs:152`      `crypto().supports(cs)`                     → `UnsupportedCiphersuite`
///   2. `creation.rs:168`      `welcome.ciphersuite() != kp.ciphersuite()` → `CiphersuiteMismatch`
///   3. `creation.rs:249`      GroupInfo vs KeyPackage (valn1404)          → `CiphersuiteMismatch`
///   4. `creation.rs:767`      то же на virtual-client пути (за `virtual-clients-draft`, у нас выключен)
///   5. `validation.rs:383`    ValSem105: ciphersuite KeyPackage-а в Add vs группа
///   6. `proposals_in.rs:179`  тот же контроль при декоде предложения
///   7. `validation.rs:804`    capabilities листа обязаны содержать шифронабор группы
///
/// Наш `KeyPackage` всегда строится с константой `crate::CIPHERSUITE`, а `group_config()` жёстко
/// ставит `.ciphersuite(CS)` — значит все семь сравнений фактически означают «== X-Wing». Поэтому
/// «ноль вызовов в проде» здесь НЕ дыра: свойство выполняется, просто не нами.
///
/// ГДЕ ВЫЗОВ ВСЁ-ТАКИ НУЖЕН — вход, которого нет в списке выше: `client.rs::group_mut` грузит
/// группу из запечатанного хранилища. Все семь контролей стоят на ВСТУПЛЕНИИ в группу; уже лежащая
/// группа считается доверенной, и её шифронабор не смотрит никто. Там ассерт не декоративен —
/// оттуда он и вызывается. Эксплуатируемость низкая (хранилище под мастер-ключом с AEAD, подменить
/// запись = уже иметь ключ), так что это defense-in-depth в буквальном смысле, а не закрытие дыры.
pub fn assert_ciphersuite(cs: u16) -> Result<(), DowngradeReject> {
    if cs != REQUIRED_CIPHERSUITE {
        return Err(DowngradeReject::WrongCiphersuite(cs));
    }
    Ok(())
}

/// The required_capabilities a Kvant group MUST be created with (and never drop below). Used at group
/// creation so the floor is signed into GroupContext from epoch 0.
pub fn floor_required_capabilities() -> RequiredCapabilitiesExtension {
    RequiredCapabilitiesExtension::new(FLOOR_EXTENSIONS, &[] as &[ProposalType], FLOOR_CREDENTIALS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floor_caps_pass_self_check() {
        // The capabilities we create groups with must themselves satisfy the floor (no accidental gap).
        assert!(check_no_downgrade(&floor_required_capabilities()).is_ok());
    }

    #[test]
    fn superset_is_allowed() {
        // Adding MORE requirements is fine (monotone up).
        let more = RequiredCapabilitiesExtension::new(
            &[KVANT_DEVCERT_EXT, ExtensionType::ApplicationId],
            &[] as &[ProposalType],
            &[CredentialType::Basic],
        );
        assert!(check_no_downgrade(&more).is_ok());
    }

    #[test]
    fn dropping_devcert_extension_rejected() {
        // B2.4: a GCE proposal that removes the device-cert requirement = internal downgrade.
        let downgraded = RequiredCapabilitiesExtension::new(
            &[] as &[ExtensionType],
            &[] as &[ProposalType],
            &[CredentialType::Basic],
        );
        assert_eq!(
            check_no_downgrade(&downgraded),
            Err(DowngradeReject::MissingRequiredExtension(KVANT_DEVCERT_EXT))
        );
    }

    #[test]
    fn dropping_basic_credential_rejected() {
        let downgraded = RequiredCapabilitiesExtension::new(
            &[KVANT_DEVCERT_EXT],
            &[] as &[ProposalType],
            &[] as &[CredentialType],
        );
        assert_eq!(
            check_no_downgrade(&downgraded),
            Err(DowngradeReject::MissingRequiredCredential(CredentialType::Basic))
        );
    }

    #[test]
    fn wrong_ciphersuite_rejected() {
        assert!(assert_ciphersuite(REQUIRED_CIPHERSUITE).is_ok());
        assert_eq!(assert_ciphersuite(0x0001), Err(DowngradeReject::WrongCiphersuite(0x0001)));
    }
}

// ----------------------------- KV-03-001: полномочия на СОСТАВ -----------------------------
//
// ЧТО БЫЛО. `walk_staged_commit` проверяет КЛЮЧИ (привязку листов, даунгрейд required_capabilities)
// и не смотрит на автора коммита вообще; `remove_proposals()` не вызывался ни разу. Права
// проверялись только у ОТПРАВИТЕЛЯ (`mlsRemoveMember` → `mlsRoles.isAdmin`), то есть любой участник
// мог закоммитить Remove владельца, и все мержили. ROOT-1 аудита: личность берётся из тела
// сообщения, а не из локального состояния.
//
// Половина этой дыры уже была закрыта — блок B8 отказывается хранить standalone-предложения, и его
// комментарий называет ровно это правило: «Remove … bypasses the whole owner-signed roles chain,
// which exists precisely to decide who may remove whom». Оставался путь ПРЯМОГО коммита, а он в
// kvant основной.
//
// ОТКУДА РОЛИ. Из owner-signed цепочки (`crypto/mlsroles.js`), проверенной в JS и протолкнутой сюда
// через `set_group_roles` — по форме `pin_account`/`add_revocation`. Держатся в памяти, поэтому
// пере-подаются на старте мостом в `mlsWiring.ts` (там же, где пины и отзывы, и по той же причине).
//
// СВЯЗЬ «лист → аккаунт» уже существует: `account_id` — это байты канонического ника, те же, что в
// `pin_account` и в ролях, а `ProcessedMessage::credential()` даёт credential автора коммита.

/// Роли группы: владелец (неизменяем) + текущее множество админов. Владелец в `admins` не дублируется.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRoles {
    pub owner: Vec<u8>,
    pub admins: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MembershipReject {
    /// Автор не владелец и не админ, а удаляет чужое.
    NotAdmin,
    /// Лист ВЛАДЕЛЬЦА удаляет кто-то, кроме самого владельца. Не разрешено даже админу: владелец
    /// неизменяем в цепочке, и это ровно то же свойство, только на составе.
    OwnerRemoval,
    /// Ролей для этой группы ещё нет — окно между вступлением и первым `groles`. См. шапку ниже.
    RolesUnknown,
}

/// Можно ли автору коммита удалить этот лист.
///
/// ОКНО «РОЛЕЙ ЕЩЁ НЕТ» и почему оно решается именно так. Цепочка приходит конвертом `groles`
/// ВНУТРИ группы, то есть новый участник получает её только ПОСЛЕ вступления. В этом окне:
///   * впустить всё — оставить дыру ровно там, где участник наиболее уязвим: у него нет никаких
///     оснований судить о чём-либо, и первый же коммит может снести владельца;
///   * отвергать всё — расстыковать группу на легальной операции: отказ от коммита не откладывает
///     его, а оставляет нас в старой эпохе (ratchet приёма уже сдвинут, повторно кадр не обработать).
/// Поэтому правило окна УЖЕ, а не «всё или ничего»: разрешено то, что решается БЕЗ ролей вообще, —
/// удаление листа СВОЕГО ЖЕ аккаунта (своё устройство, самовыход). Стороннее удаление отклоняется.
///   * обычный трафик, Add, Update, application-сообщения окно не трогает — отказ узкий;
///   * названная атака закрыта и для свежего участника;
///   * цена — редкая расстыковка при неудачном чередовании; она ВИДИМА (именованный отказ + запись
///     в журнал) и восстановима существующими примитивами (детект десинка → remove-leaf + re-add,
///     mlsSelfHeal), в отличие от тихого захвата группы, который не виден никак;
///   * и окно коротко по конструкции: добавляющий рассылает `groles` сразу после add.
/// Убрать окно совсем — значит доставлять цепочку ВМЕСТЕ с приглашением; это смена формата, отдельной
/// задачей, и до неё правило выше — верхняя граница того, что решается локально.
pub fn may_remove(
    roles: Option<&GroupRoles>,
    committer_account: &[u8],
    removed_account: &[u8],
) -> Result<(), MembershipReject> {
    // Своё же — всегда можно, и это НЕ требует ролей: remove_device своего устройства и самовыход.
    // Сравниваются АККАУНТЫ, поэтому многоустройственность не ломается.
    if committer_account == removed_account {
        return Ok(());
    }
    let r = match roles {
        Some(r) => r,
        None => return Err(MembershipReject::RolesUnknown),
    };
    if removed_account == r.owner.as_slice() {
        return Err(MembershipReject::OwnerRemoval);
    }
    if committer_account == r.owner.as_slice() || r.admins.iter().any(|a| a.as_slice() == committer_account) {
        return Ok(());
    }
    Err(MembershipReject::NotAdmin)
}

#[cfg(test)]
mod membership_tests {
    use super::*;

    fn roles() -> GroupRoles {
        GroupRoles { owner: b"alice".to_vec(), admins: vec![b"bob".to_vec()] }
    }

    #[test]
    fn non_admin_cannot_remove_anyone_else() {
        // Названный сценарий аудита в чистом виде.
        assert_eq!(may_remove(Some(&roles()), b"carol", b"alice"), Err(MembershipReject::OwnerRemoval));
        assert_eq!(may_remove(Some(&roles()), b"carol", b"bob"), Err(MembershipReject::NotAdmin));
    }

    #[test]
    fn owner_is_removable_by_nobody_but_himself() {
        // ДАЖЕ АДМИНОМ: владелец неизменяем в цепочке ролей, и на составе это то же свойство.
        assert_eq!(may_remove(Some(&roles()), b"bob", b"alice"), Err(MembershipReject::OwnerRemoval));
        assert!(may_remove(Some(&roles()), b"alice", b"alice").is_ok(), "сам себя — можно (это выход)");
    }

    #[test]
    fn owner_and_admin_may_remove_members() {
        // КОНТРОЛЬ: правило не «отказывать всем». Без этого все проверки выше зелены и на
        // заглушке, которая всегда возвращает Err.
        assert!(may_remove(Some(&roles()), b"alice", b"carol").is_ok(), "владелец может");
        assert!(may_remove(Some(&roles()), b"bob", b"carol").is_ok(), "админ может");
    }

    #[test]
    fn own_account_needs_no_roles_at_all() {
        // Своё устройство / самовыход решаются БЕЗ ролей — на этом и стоит правило окна.
        assert!(may_remove(None, b"carol", b"carol").is_ok());
        assert!(may_remove(Some(&roles()), b"carol", b"carol").is_ok());
    }

    #[test]
    fn window_refuses_third_party_removals_and_says_so_by_name() {
        // Окно «ролей ещё нет»: стороннее удаление отклоняется, и причина ОТДЕЛЬНАЯ — «роли не
        // доехали» это гонка доставки, а не атака, и в журнале это должно читаться по-разному.
        assert_eq!(may_remove(None, b"bob", b"carol"), Err(MembershipReject::RolesUnknown));
        assert_eq!(may_remove(None, b"carol", b"alice"), Err(MembershipReject::RolesUnknown));
    }

    #[test]
    fn admin_set_is_read_as_a_set_not_a_prefix() {
        // Мелочь, которая ломается молча: админ, стоящий НЕ первым, обязан считаться админом.
        let r = GroupRoles { owner: b"alice".to_vec(), admins: vec![b"bob".to_vec(), b"dave".to_vec()] };
        assert!(may_remove(Some(&r), b"dave", b"carol").is_ok());
        assert_eq!(may_remove(Some(&r), b"dav", b"carol"), Err(MembershipReject::NotAdmin), "префикс — не совпадение");
    }
}
