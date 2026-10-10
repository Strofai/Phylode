//! Runs the daily list updater for real, with a stand-in `curl` that serves lists from a
//! folder, to check which downloads it swaps in.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use phylode::policy::held_entries;

/// A list in HaGeZi's format: the header the updater checks, then one domain per line.
fn write_list(path: &Path, entries: usize) {
    let mut text = format!("# Number of entries: {entries}\n");
    for index in 0..entries {
        text.push_str(&format!("d{index}.example.com\n"));
    }
    std::fs::write(path, text).unwrap();
}

fn entries_in(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.starts_with('#'))
        .count()
}

/// Runs the updater against `lists`, downloading from `served`; returns its exit code.
fn update(root: &Path, lists: &Path, served: &Path) -> i32 {
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    // Copies the file named at the end of the URL to the path after -o, as curl -o would.
    let curl = bin.join("curl");
    std::fs::write(
        &curl,
        format!(
            "#!/bin/bash\nout=\"\"\nwhile [[ $# -gt 1 ]]; do [[ $1 == -o ]] && out=$2; shift; done\n\
             cp \"{}/${{1##*/}}\" \"$out\" || exit 22\n",
            served.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = root.join("phylode.conf");
    std::fs::write(&config, "protection = standard\n").unwrap();

    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/update-blocklists.sh");
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let output = Command::new("/bin/bash")
        .arg(&script)
        .arg(lists)
        .arg(&config)
        .env("PATH", path)
        .output()
        .unwrap();
    output.status.code().unwrap()
}

/// Should change: a download with under half the entries of the list in use is set aside
/// beside it, the service can count it, and the run reports failure; a later download of
/// ordinary size is swapped in and clears what was set aside.
/// Should not change: the list in use stays exactly as it was, and a download that shrank by
/// less than half is swapped in as before.
#[test]
fn a_download_under_half_the_list_in_use_is_set_aside() {
    let root = std::env::temp_dir().join(format!("phylode-list-update-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let lists = root.join("lists");
    let served = root.join("served");
    std::fs::create_dir_all(&lists).unwrap();
    std::fs::create_dir_all(&served).unwrap();
    let main = lists.join("hagezi-main.txt");
    let feed = lists.join("hagezi-tif.txt");
    write_list(&main, 25_000);
    write_list(&feed, 25_000);

    write_list(&served.join("pro-onlydomains.txt"), 12_000);
    write_list(&served.join("tif.medium-onlydomains.txt"), 20_000);
    assert_eq!(update(&root, &lists, &served), 1);
    assert_eq!(entries_in(&main), 25_000);
    assert_eq!(held_entries(&main), Some(12_000));
    assert_eq!(entries_in(&feed), 20_000);
    assert_eq!(held_entries(&feed), None);

    write_list(&served.join("pro-onlydomains.txt"), 24_000);
    assert_eq!(update(&root, &lists, &served), 0);
    assert_eq!(entries_in(&main), 24_000);
    assert_eq!(held_entries(&main), None);

    let _ = std::fs::remove_dir_all(&root);
}
