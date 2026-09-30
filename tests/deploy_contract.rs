//! Guards the places the deployment files must agree with each other and with the program:
//! socket names, the account it runs as, list paths and resource limits.
//!
//! When these disagree **each file looks perfectly fine on its own**, while the symptom is
//! "installed but nothing in the house resolves" or "installed but nothing is blocked". That is
//! why a test guards them rather than anyone's memory.

use std::path::PathBuf;

fn plist() -> String {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("deploy/com.Phylode.gatekeeper.plist");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

#[test]
fn the_plists_socket_names_match_the_constants_in_the_code() {
    let text = plist();
    for name in [
        phylode::dns::LAUNCHD_UDP_SOCKET,
        phylode::dns::LAUNCHD_TCP_SOCKET,
    ] {
        assert!(
            text.contains(&format!("<key>{name}</key>")),
            "socket name {name} is missing from the plist — launchd hands over nothing, and the \
             service silently falls back to binding port 53 itself and fails"
        );
    }
}

#[test]
fn the_plist_listens_on_every_interface() {
    // A SockNodeName pins launchd to one address; pinned to loopback, the service installs and
    // answers this Mac while every other device on the network silently goes unfiltered.
    assert!(
        !plist().contains("<key>SockNodeName</key>"),
        "the plist binds a single address, so other devices cannot use the service"
    );
}

#[test]
fn the_plist_sends_output_and_errors_somewhere() {
    // Without these two, a service that fails to start leaves no error message anywhere.
    let text = plist();
    assert!(text.contains("<key>StandardOutPath</key>"));
    assert!(text.contains("<key>StandardErrorPath</key>"));
}

#[test]
fn the_plist_does_not_run_as_root() {
    // A service with a network port open to the world should not have root.
    let text = plist();
    assert!(
        text.contains("<key>UserName</key>"),
        "the plist sets no UserName, so the service would run as root"
    );
    assert!(
        !text.contains("<string>root</string>"),
        "the plist explicitly runs the service as root"
    );
}

#[test]
fn the_plist_starts_at_boot_and_restarts_on_crash() {
    let text = plist();
    assert!(text.contains("<key>RunAtLoad</key>"));
    assert!(text.contains("<key>KeepAlive</key>"));
}

fn deploy_file(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("deploy")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

#[test]
fn the_plist_sets_both_the_soft_and_hard_file_limits() {
    // launchd defaults the soft limit to 256 and the program reads the soft limit, so setting
    // only the hard limit changes nothing.
    let text = plist();
    assert!(text.contains("<key>SoftResourceLimits</key>"));
    assert!(text.contains("<key>HardResourceLimits</key>"));
}

#[test]
fn the_list_update_schedule_avoids_root_and_runs_once_at_boot() {
    let text = deploy_file("com.Phylode.blocklist-update.plist");
    assert!(text.contains("<key>UserName</key>"));
    assert!(!text.contains("<string>root</string>"));
    assert!(
        text.contains("<key>RunAtLoad</key>"),
        "without it the list stays empty from installation until the first scheduled run"
    );
}

#[test]
fn the_default_config_reads_exactly_the_lists_the_updater_writes() {
    // All three files look right individually, but if the names disagree the service reads no
    // list, allows everything, and not one of the files reports an error.
    let install = deploy_file("phylode.conf");
    let updater = deploy_file("update-blocklists.sh");
    let lists_dir = "/usr/local/etc/phylode/lists";
    assert!(updater.contains(lists_dir) && install.contains(lists_dir));

    let written: Vec<&str> = updater
        .lines()
        .filter_map(|line| line.trim().strip_prefix("\"hagezi-"))
        .filter_map(|rest| rest.split_whitespace().next())
        .collect();
    assert_eq!(written.len(), 2, "the updater should download two lists");
    for name in written {
        let path = format!("blocklist = {lists_dir}/hagezi-{name}.txt");
        assert!(
            install.contains(&path),
            "{path} is missing from the default configuration"
        );
    }
}
