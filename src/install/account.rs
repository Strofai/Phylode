//! The `_phylode` account the service runs as: created by `install`, never removed by
//! `uninstall`.

use super::{InstallError, SERVICE_USER, run};

const DSCL: &str = "/usr/bin/dscl";

/// Makes sure the `_phylode` account and its group exist, creating both when either is missing.
///
/// Creating takes seven `dscl` steps, so it is all or nothing: a step that fails removes what
/// the earlier ones made, and a half-made account left by an older version is removed and made
/// again. What breaks if you change it: count a half-made account as existing and every later
/// install stops at reading its ID, with no way forward but `dscl` by hand.
pub(super) fn ensure_service_user() -> Result<(), InstallError> {
    let record = format!("/Users/{SERVICE_USER}");
    let group = format!("/Groups/{SERVICE_USER}");
    let complete = directory_id(&record, "UniqueID").is_ok()
        && directory_id(&record, "PrimaryGroupID").is_ok()
        && directory_id(&group, "PrimaryGroupID").is_ok();
    if complete {
        out_line!("    already exists");
        return Ok(());
    }
    remove_service_user(&record, &group);
    let users = run(DSCL, &[".", "-list", "/Users", "UniqueID"])?;
    let groups = run(DSCL, &[".", "-list", "/Groups", "PrimaryGroupID"])?;
    let id = next_system_id(&users, &groups)
        .ok_or(InstallError::NoFreeId)?
        .to_string();
    let created = create_service_user(&record, &group, &id);
    if created.is_err() {
        remove_service_user(&record, &group);
    }
    created?;
    out_line!("    created with ID {id}");
    Ok(())
}

/// Deletes whatever exists of the service account and its group; either may be missing.
fn remove_service_user(record: &str, group: &str) {
    for path in [record, group] {
        let _ = run(DSCL, &[".", "-delete", path]);
    }
}

fn create_service_user(record: &str, group: &str, id: &str) -> Result<(), InstallError> {
    for args in [
        vec![".", "-create", record],
        vec![".", "-create", record, "UserShell", "/usr/bin/false"],
        vec![".", "-create", record, "RealName", "Phylode Gatekeeper"],
        vec![".", "-create", record, "UniqueID", id],
        vec![".", "-create", record, "PrimaryGroupID", id],
        vec![".", "-create", record, "NFSHomeDirectory", "/var/empty"],
        vec![".", "-create", group, "PrimaryGroupID", id],
    ] {
        run(DSCL, &args)?;
    }
    Ok(())
}

/// The highest ID below 500 that no account or group uses, so the same number is free for
/// both. `None` when every one from 499 down to 400 is taken.
/// Makes sure the `_phylode` account and its group exist, creating both when either is missing.
///
/// What breaks if you change it: Apple adds system accounts upward from the low hundreds, and
/// a macOS update deletes any account holding an ID it wants (macOS 15 took 301–304 from Nix's
/// build accounts). Counting down from 499 keeps as far from that as the system range allows.
fn next_system_id(users: &str, groups: &str) -> Option<u32> {
    let taken: std::collections::HashSet<u32> = users
        .lines()
        .chain(groups.lines())
        .filter_map(|line| line.split_whitespace().nth(1)?.parse::<u32>().ok())
        .collect();
    (400..500).rev().find(|id| !taken.contains(id))
}

/// Reads a numeric attribute such as `UniqueID` from a directory service record.
pub(super) fn directory_id(record: &str, attribute: &str) -> Result<u32, InstallError> {
    run(DSCL, &[".", "-read", record, attribute])?
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| InstallError::UnknownId {
            record: record.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_next_id_is_free_for_both_accounts_and_groups() {
        let users = "_www 70\n_modelmanagerd 301\n_taken 499\nroot 0\njohn 501\n";
        let groups = "admin 80\n_also 498\nstaff 20\n";
        assert_eq!(next_system_id(users, groups), Some(497));
    }

    #[test]
    fn no_id_is_offered_once_the_system_range_is_full() {
        let full: String = (400..500).map(|id| format!("_a{id} {id}\n")).collect();
        assert_eq!(next_system_id(&full, ""), None);
        assert_eq!(next_system_id("", ""), Some(499));
    }
}
