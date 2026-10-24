//! Refuses to install into a folder that an account other than root or an administrator could
//! change.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use super::{InstallError, io_error, run};

/// Fails unless `dir` (or, if it does not exist yet, the nearest folder above it) and every
/// folder above that can only be changed by root or an administrator. Administrators can
/// become root anyway, so only a standard account being able to write there is a risk.
///
/// What breaks if you change it: without this, a standard account that can write to, say,
/// `/usr/local/bin` swaps in its own program and the next `sudo phylode` runs it as root.
pub(super) fn require_only_administrators_can_change(
    dir: &Path,
    admin_gid: u32,
) -> Result<(), InstallError> {
    let existing = dir
        .ancestors()
        .find(|p| p.exists())
        .unwrap_or(Path::new("/"));
    for folder in folders_to_check(existing)? {
        let folder = folder.as_path();
        let meta = fs::metadata(folder).map_err(|source| io_error(folder, source))?;
        let safe =
            match writers(meta.uid(), meta.gid(), meta.mode(), admin_gid) {
                Writers::RootOrAdministrators => true,
                Writers::Owner(uid) => is_administrator(uid)?,
                Writers::Anyone => false,
            } && !acl_lets_others_write(&run("/bin/ls", &["-lde", &folder.to_string_lossy()])?);
        if !safe {
            return Err(InstallError::UnprotectedDirectory {
                path: folder.to_path_buf(),
            });
        }
    }
    Ok(())
}

/// Every folder whose writers decide what ends up at `path`: its ancestors as written and
/// the ancestors of the folder it resolves to, each once.
///
/// What breaks if you change it: checking only the resolved folder misses a symbolic link
/// along the written path — whoever can change the folder holding that link can point it
/// somewhere protected for the check, then back at their own folder afterwards.
fn folders_to_check(path: &Path) -> Result<std::collections::BTreeSet<PathBuf>, InstallError> {
    let real = fs::canonicalize(path).map_err(|source| io_error(path, source))?;
    Ok(path
        .ancestors()
        .chain(real.ancestors())
        .map(Path::to_path_buf)
        .collect())
}

/// Who, besides root, can change a folder with this owner, group and mode.
#[derive(Debug, PartialEq, Eq)]
enum Writers {
    RootOrAdministrators,
    /// Root, administrators, and this owner, who may or may not be an administrator.
    Owner(u32),
    /// Every account, or a group other than wheel and admin.
    Anyone,
}

fn writers(uid: u32, gid: u32, mode: u32, admin_gid: u32) -> Writers {
    let group_writable = mode & 0o020 != 0;
    let world_writable = mode & 0o002 != 0;
    if world_writable || (group_writable && gid != 0 && gid != admin_gid) {
        Writers::Anyone
    } else if uid == 0 {
        Writers::RootOrAdministrators
    } else {
        Writers::Owner(uid)
    }
}

/// Accounts an access control entry may grant change rights to without making a folder unsafe.
const ACL_TRUSTED: [&str; 3] = ["user:root", "group:wheel", "group:admin"];

/// Access control rights that change a folder or what is in it, as `ls -le` names them.
const ACL_WRITE_RIGHTS: [&str; 10] = [
    "write",
    "append",
    "add_file",
    "add_subdirectory",
    "delete",
    "delete_child",
    "writeattr",
    "writeextattr",
    "writesecurity",
    "chown",
];

/// Whether an `ls -lde` listing shows an access control entry that lets an account other than
/// root or an administrator change the folder, or the folders install later creates inside it
/// (entries meant only for those are counted too).
/// What breaks if you change it: the owner, group and mode checks alone miss a macOS access
/// control entry granting a standard account the same rights.
fn acl_lets_others_write(listing: &str) -> bool {
    listing.lines().skip(1).any(|entry| {
        let Some((head, rights)) = entry.trim().rsplit_once(' ') else {
            return false;
        };
        let Some(principal) = head.strip_suffix(" allow") else {
            return false;
        };
        let principal = principal.strip_suffix(" inherited").unwrap_or(principal);
        let principal = principal
            .split_once(": ")
            .map_or(principal, |(_, name)| name);
        !ACL_TRUSTED.contains(&principal)
            && rights
                .split(',')
                .any(|right| ACL_WRITE_RIGHTS.contains(&right))
    })
}

fn is_administrator(uid: u32) -> Result<bool, InstallError> {
    let answer = run(
        "/usr/bin/dsmemberutil",
        &["checkmembership", "-u", &uid.to_string(), "-G", "admin"],
    )?;
    Ok(answer.trim() == "user is a member of the group")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Should change: the folder holding a symbolic link on the written path is checked, not
    /// only the folder the link resolves to.
    /// Should not change: the resolved folder and its ancestors are still checked.
    #[test]
    fn the_folder_holding_a_link_on_the_path_is_checked_too() {
        let base = std::env::temp_dir().join(format!("phylode-link-{}", std::process::id()));
        let holder = base.join("holder");
        let target = base.join("target");
        fs::create_dir_all(&holder).unwrap();
        fs::create_dir_all(&target).unwrap();
        let link = holder.join("bin");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let folders = folders_to_check(&link).unwrap();
        assert!(folders.contains(&holder), "the folder holding the link");
        let real_target = fs::canonicalize(&target).unwrap();
        assert!(
            folders.contains(&real_target),
            "the folder the link resolves to"
        );
        assert!(folders.contains(real_target.parent().unwrap()));
        assert!(folders.contains(Path::new("/")));
        let _ = fs::remove_dir_all(&base);
    }

    /// Should change: an access control entry granting a standard account or group change
    /// rights is caught, including one inherited or meant only for folders created inside.
    /// Should not change: no entries, deny entries, read-only grants, and grants to root or
    /// the admin group pass. Listings follow the format `ls -lde` prints on macOS.
    #[test]
    fn access_control_entries_that_let_others_write_are_caught() {
        let header = "drwxr-xr-x  3 root  wheel  96 Aug  8 15:25 /usr/local/bin\n";
        let with = |entries: &str| format!("{header}{entries}");

        for unsafe_entries in [
            " 0: group:staff allow add_file,add_subdirectory,delete_child\n",
            " 0: group:everyone deny delete\n 1: user:alex allow write\n",
            " 0: group:staff inherited allow add_file\n",
            " 0: group:everyone allow add_file,directory_inherit,only_inherit\n",
        ] {
            assert!(
                acl_lets_others_write(&with(unsafe_entries)),
                "{unsafe_entries}"
            );
        }
        for safe_entries in [
            "",
            " 0: group:everyone deny delete\n",
            " 0: group:staff allow list,search,readattr,readextattr,readsecurity\n",
            " 0: group:admin allow add_file,add_subdirectory,delete_child\n",
        ] {
            assert!(
                !acl_lets_others_write(&with(safe_entries)),
                "{safe_entries}"
            );
        }
    }

    /// Should change: a folder any account, or an unrelated group, can write is refused, and
    /// one owned by an ordinary account needs that account checked.
    /// Should not change: root-owned folders, including admin-group-writable ones such as
    /// the list folder install itself creates, pass without a lookup.
    #[test]
    fn only_root_and_administrators_may_be_able_to_change_an_install_folder() {
        let admin = 80;
        assert_eq!(writers(0, 0, 0o755, admin), Writers::RootOrAdministrators);
        assert_eq!(
            writers(0, admin, 0o775, admin),
            Writers::RootOrAdministrators
        );
        assert_eq!(writers(501, 20, 0o755, admin), Writers::Owner(501));
        assert_eq!(writers(0, 0, 0o777, admin), Writers::Anyone);
        assert_eq!(writers(0, 20, 0o775, admin), Writers::Anyone);
    }
}
