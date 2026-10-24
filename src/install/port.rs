//! Checks that only launchd and the Phylode job it started hold the service's port.

use std::net::SocketAddr;
use std::process::Command;

use super::{GATEKEEPER_LABEL, InstallError, LAUNCHCTL, run};
use crate::config::Config;

const LSOF: &str = "/usr/sbin/lsof";
/// launchd's process ID. It holds the sockets it binds for a job as long as the job is loaded.
const LAUNCHD_PID: u32 = 1;

/// Checks that launchd and the Phylode job it started are the only programs holding the
/// service's port. A reply on that port proves nothing by itself: while launchd is not holding
/// it, macOS lets any account bind a port below 1024 on every address.
///
/// What breaks if you change it: check only that something answers, and a program another
/// account left listening receives every lookup this Mac and the network make.
pub(super) fn ensure_phylode_holds_port(config: &Config) -> Result<(), InstallError> {
    let port = config.listen().first().map_or(53, SocketAddr::port);
    let job = run(LAUNCHCTL, &["print", &format!("system/{GATEKEEPER_LABEL}")])
        .ok()
        .and_then(|printed| job_pid(&printed));
    let listing = list_port(port)?;
    others_on_port(&holders(&listing, port), job)
        .map_err(|holders| InstallError::PortTaken { port, holders })
}

/// `lsof` output for every socket on `port`, as process, command and address fields. Empty when
/// nothing holds it.
fn list_port(port: u16) -> Result<String, InstallError> {
    let args = [
        "-nP".to_string(),
        format!("-iUDP:{port}"),
        format!("-iTCP:{port}"),
        "-F".to_string(),
        "pcn".to_string(),
    ];
    let output = Command::new(LSOF)
        .args(&args)
        .output()
        .map_err(|source| InstallError::Spawn {
            program: LSOF.to_string(),
            source,
        })?;
    // lsof also exits unsuccessfully when nothing matches; only then is standard error empty.
    if output.status.success() || output.stderr.is_empty() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(InstallError::Failed {
            command: format!("{LSOF} {}", args.join(" ")),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

/// The process ID in `launchctl print` output for a running job. `None` while it is not running.
fn job_pid(printed: &str) -> Option<u32> {
    printed
        .lines()
        .find_map(|line| line.strip_prefix("\tpid = "))
        .and_then(|pid| pid.trim().parse().ok())
}

/// Each process in `lsof -F pcn` output with a socket whose own end is `port`: one listening
/// there, or one that accepted a connection there. A connection this Mac made to another
/// machine's port does not count.
fn holders(listing: &str, port: u16) -> Vec<(u32, String)> {
    let own_end = format!(":{port}");
    let mut found: Vec<(u32, String)> = Vec::new();
    let mut process: Option<u32> = None;
    let mut command = String::new();
    for line in listing.lines() {
        match line.split_at_checked(1) {
            Some(("p", pid)) => {
                process = pid.parse().ok();
                command.clear();
            }
            Some(("c", name)) => command = name.to_string(),
            Some(("n", address)) => {
                let local = address.split("->").next().unwrap_or(address);
                if let Some(pid) = process
                    && local.ends_with(&own_end)
                    && !found.iter().any(|(seen, _)| *seen == pid)
                {
                    found.push((pid, command.clone()));
                }
            }
            _ => {}
        }
    }
    found
}

/// `Ok` when `job` is among the holders and everyone else is launchd; otherwise names who
/// else holds the port.
fn others_on_port(holders: &[(u32, String)], job: Option<u32>) -> Result<(), String> {
    let others: Vec<String> = holders
        .iter()
        .filter(|(pid, _)| *pid != LAUNCHD_PID && Some(*pid) != job)
        .map(|(pid, command)| format!("{command} (process {pid})"))
        .collect();
    let ours = job.is_some_and(|job| holders.iter().any(|(pid, _)| *pid == job));
    match (others.is_empty(), ours) {
        (true, true) => Ok(()),
        (true, false) => Err("no program Phylode started".to_string()),
        (false, _) => Err(others.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `lsof -nP -iUDP:53 -iTCP:53 -F pcn` as root, on a Mac where launchd and Phylode hold
    /// port 53, mDNSResponder has asked the router something, and another account's program
    /// sits on 127.0.0.1:53.
    const LISTING: &str = "p1\nclaunchd\nf20\nn*:53\nf21\nn*:53\n\
                           p412\ncphylode\nf3\nn*:53\nf4\nn*:53\nf9\nn[::1]:53->[::1]:61022\n\
                           p300\ncmDNSResponder\nf9\nn192.168.0.192:61000->192.168.0.1:53\n\
                           p900\ncimpostor\nf3\nn127.0.0.1:53\n";

    /// Should change: every process with its own end on the port is found, once each.
    /// Should not change: a connection this Mac made to another machine's port 53 is not
    /// holding it, and port 53 does not match 153 or 5353.
    #[test]
    fn the_programs_holding_a_port_are_read_from_lsof() {
        let found: Vec<u32> = holders(LISTING, 53)
            .into_iter()
            .map(|(pid, _)| pid)
            .collect();
        assert_eq!(found, [1, 412, 900]);
        assert_eq!(holders(LISTING, 53)[2].1, "impostor");
        assert!(holders("p7\ncx\nf1\nn*:153\nf2\nn*:5353\n", 53).is_empty());
        assert!(holders("", 53).is_empty());
    }

    #[test]
    fn a_running_jobs_process_id_is_read_from_launchctl() {
        let printed = "system/com.Phylode.gatekeeper = {\n\tactive count = 1\n\tstate = running\n\
                       \tpid = 412\n\tsockets = {\n\t\tpid = 9\n\t}\n}\n";
        assert_eq!(job_pid(printed), Some(412));
        assert_eq!(job_pid("system/x = {\n\tstate = not running\n}\n"), None);
    }

    /// Should change: anyone besides launchd and the job holding the port is named, and so is
    /// a port the job does not hold at all.
    /// Should not change: launchd and the job together are fine.
    #[test]
    fn only_launchd_and_the_job_may_hold_the_port() {
        let ours = [(1, "launchd".to_string()), (412, "phylode".to_string())];
        assert_eq!(others_on_port(&ours, Some(412)), Ok(()));

        let taken = holders(LISTING, 53);
        assert_eq!(
            others_on_port(&taken, Some(412)),
            Err("impostor (process 900)".to_string())
        );

        let squatter = [(900, "impostor".to_string())];
        assert_eq!(
            others_on_port(&squatter, None),
            Err("impostor (process 900)".to_string())
        );
        assert_eq!(
            others_on_port(&[(1, "launchd".to_string())], Some(412)),
            Err("no program Phylode started".to_string())
        );
    }
}
