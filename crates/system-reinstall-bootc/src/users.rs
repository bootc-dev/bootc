use anyhow::{Context, Result};
use bootc_utils::CommandRunExt;
use bootc_utils::PathQuotedDisplay;
use fn_error_context::context;
use openssh_keys::PublicKey;
use rustix::fs::Uid;
use rustix::process::geteuid;
use rustix::process::getuid;
use rustix::thread::set_thread_res_uid;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fs::File;
use std::io::BufReader;
use std::os::unix::process::CommandExt;
use std::process::Command;
use uzers::os::unix::UserExt;

#[context("loginctl_users")]
fn loginctl_users() -> Result<BTreeSet<String>> {
    let loginctl_raw_output = loginctl_run_compat()?;

    loginctl_parse(loginctl_raw_output)
}

/// See `test::test_parse_lsblk` for example loginctl output
#[context("loginctl_parse")]
fn loginctl_parse(users: Value) -> Result<BTreeSet<String>> {
    users
        .as_array()
        .context("loginctl output is not an array")?
        .iter()
        .map(|user_value| {
            user_value
                .as_object()
                .context("user entry is not an object")?
                .get("user")
                .context("user object doesn't have a user field")?
                .as_str()
                .context("user name field is not a string")
                .map(String::from)
        })
        // Artificially add the root user to the list of users as it doesn't always appear in
        // `loginctl list-sessions`
        .chain(std::iter::once(Ok("root".to_string())))
        .collect::<Result<_>>()
        .context("error parsing users")
}

/// Run `loginctl` with some compatibility maneuvers to get JSON output
#[context("loginctl_run_compat")]
fn loginctl_run_compat() -> Result<Value> {
    let mut command = Command::new("loginctl");
    command.arg("list-sessions").arg("--output").arg("json");
    let output = command.run_get_output().context("running loginctl")?;
    let users: Value = match serde_json::from_reader(output) {
        Ok(users) => users,
        // Failing to parse means loginctl is not outputting JSON despite `--output`
        // (https://github.com/systemd/systemd/issues/15275), we need to use the `--json` flag
        Err(_err) => Command::new("loginctl")
            .arg("list-sessions")
            .arg("--json")
            .arg("short")
            .run_and_parse_json()
            .context("running loginctl")?,
    };
    Ok(users)
}

struct UidChange {
    uid: Uid,
    euid: Uid,
}

impl UidChange {
    #[context("new")]
    fn new(change_to_uid: Uid) -> Result<Self> {
        let (uid, euid) = (getuid(), geteuid());
        set_thread_res_uid(uid, change_to_uid, euid).context("setting effective uid failed")?;
        Ok(Self { uid, euid })
    }
}

impl Drop for UidChange {
    fn drop(&mut self) {
        set_thread_res_uid(self.uid, self.euid, self.euid).expect("setting effective uid failed");
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UserKeys {
    pub(crate) user: String,
    pub(crate) authorized_keys: Vec<PublicKey>,
}

impl UserKeys {
    pub(crate) fn num_keys(&self) -> usize {
        self.authorized_keys.len()
    }
}

impl Display for UserKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "User {} ({} authorized keys)",
            self.user,
            self.num_keys()
        )
    }
}

#[derive(Debug)]
struct SshdConfig<'a> {
    authorized_keys_files: Vec<&'a str>,
    authorized_keys_command: &'a str,
    authorized_keys_command_user: &'a str,
}

impl<'a> SshdConfig<'a> {
    #[context("parse")]
    pub fn parse(sshd_output: &'a str) -> Result<SshdConfig<'a>> {
        let config = sshd_output
            .lines()
            .filter_map(|line| line.split_once(' '))
            .collect::<BTreeMap<&str, &str>>();

        let authorized_keys_files: Vec<&str> = config
            .get("authorizedkeysfile")
            .unwrap_or(&"none")
            .split_whitespace()
            .collect();
        let authorized_keys_command = config.get("authorizedkeyscommand").unwrap_or(&"none");
        let authorized_keys_command_user =
            config.get("authorizedkeyscommanduser").unwrap_or(&"none");

        Ok(Self {
            authorized_keys_files,
            authorized_keys_command,
            authorized_keys_command_user,
        })
    }
}

#[context("get_keys_from_files")]
fn get_keys_from_files(user: &uzers::User, keyfiles: &Vec<&str>) -> Result<Vec<PublicKey>> {
    let home_dir = user.home_dir();
    let mut user_authorized_keys: Vec<PublicKey> = Vec::new();

    for keyfile in keyfiles {
        let user_authorized_keys_path = home_dir.join(keyfile);

        if !user_authorized_keys_path.exists() {
            tracing::debug!(
                "Skipping authorized key file {} for user {} because it doesn't exist",
                PathQuotedDisplay::new(&user_authorized_keys_path),
                user.name().to_string_lossy()
            );
            continue;
        }

        // Safety: The UID should be valid because we got it from uzers
        let user_uid = Uid::from_raw(user.uid());

        // Change the effective uid for this scope, to avoid accidentally reading files we
        // shouldn't through symlinks
        let _uid_change = UidChange::new(user_uid)?;

        let file = File::open(user_authorized_keys_path)
            .context("Failed to read user's authorized keys")?;
        let mut keys = PublicKey::read_keys(BufReader::new(file))?;
        user_authorized_keys.append(&mut keys);
    }

    Ok(user_authorized_keys)
}

#[context("get_keys_from_command")]
fn get_keys_from_command(command: &str, command_user: &str) -> Result<Vec<PublicKey>> {
    let user_config = uzers::get_user_by_name(command_user).context(format!(
        "authorized_keys_command_user {command_user} not found"
    ))?;

    let mut cmd = Command::new(command);
    cmd.uid(user_config.uid());
    let output = cmd
        .run_get_output()
        .context(format!("running authorized_keys_command {command}"))?;
    let keys = PublicKey::read_keys(output)?;
    Ok(keys)
}

#[context("get_all_users_keys")]
pub(crate) fn get_all_users_keys() -> Result<Vec<UserKeys>> {
    let loginctl_user_names = loginctl_users().context("enumerate users")?;

    let mut all_users_authorized_keys = Vec::new();

    let sshd_output = Command::new("sshd")
        .arg("-T")
        .run_get_string()
        .context("running sshd -T")?;
    tracing::trace!("sshd output:\n {}", sshd_output);

    let sshd_config = SshdConfig::parse(sshd_output.as_str())?;
    tracing::debug!("parsed sshd config: {:?}", sshd_config);

    for user_name in loginctl_user_names {
        let user_info = uzers::get_user_by_name(user_name.as_str())
            .context(format!("user {user_name} not found"))?;

        let mut user_authorized_keys: Vec<PublicKey> = Vec::new();
        if !sshd_config.authorized_keys_files.is_empty() {
            let mut keys = get_keys_from_files(&user_info, &sshd_config.authorized_keys_files)?;
            user_authorized_keys.append(&mut keys);
        }

        if sshd_config.authorized_keys_command != "none" {
            let mut keys = get_keys_from_command(
                &sshd_config.authorized_keys_command,
                &sshd_config.authorized_keys_command_user,
            )?;
            user_authorized_keys.append(&mut keys);
        };

        let user_name = user_info
            .name()
            .to_str()
            .context("user name is not valid utf-8")?;

        if user_authorized_keys.is_empty() {
            tracing::debug!(
                "Skipping user {} because it has no SSH authorized_keys",
                user_name
            );
            continue;
        }

        let user_keys = UserKeys {
            user: user_name.to_string(),
            authorized_keys: user_authorized_keys,
        };

        tracing::debug!(
            "Found user {} with {} SSH authorized_keys",
            user_keys.user,
            user_keys.num_keys()
        );

        all_users_authorized_keys.push(user_keys);
    }

    Ok(all_users_authorized_keys)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    pub(crate) fn test_parse_lsblk() {
        let fixture = include_str!("../tests/fixtures/loginctl.json");

        let result = loginctl_parse(serde_json::from_str(fixture).unwrap()).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains("root"));
        assert!(result.contains("foo-doe"));
    }
}
