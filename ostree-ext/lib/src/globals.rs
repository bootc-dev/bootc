//! Module containing access to global state.

use super::Result;
use camino::{Utf8Path, Utf8PathBuf};
use cap_std_ext::cap_std::fs::Dir;
use cap_std_ext::dirext::CapStdExtDirExt as _;
use once_cell::sync::OnceCell;
use ostree::glib;
use std::fs::File;

struct ConfigPaths {
    persistent: Utf8PathBuf,
    runtime: Utf8PathBuf,
    system: Option<Utf8PathBuf>,
}

/// Get the runtime and persistent config directories.  In the system (root) case, these
/// system(root) case:  /run/ostree           /etc/ostree        /usr/lib/ostree
/// user(nonroot) case: /run/user/$uid/ostree ~/.config/ostree   <none>
fn get_config_paths(root: bool) -> &'static ConfigPaths {
    if root {
        static PATHS_ROOT: OnceCell<ConfigPaths> = OnceCell::new();
        PATHS_ROOT.get_or_init(|| ConfigPaths::new("etc", "run", Some("usr/lib")))
    } else {
        static PATHS_USER: OnceCell<ConfigPaths> = OnceCell::new();
        PATHS_USER.get_or_init(|| {
            ConfigPaths::new(
                Utf8PathBuf::try_from(glib::user_config_dir()).unwrap(),
                Utf8PathBuf::try_from(glib::user_runtime_dir()).unwrap(),
                None,
            )
        })
    }
}

impl ConfigPaths {
    fn new<P: AsRef<Utf8Path>>(persistent: P, runtime: P, system: Option<P>) -> Self {
        fn relative_owned(p: &Utf8Path) -> Utf8PathBuf {
            p.as_str().trim_start_matches('/').into()
        }
        let mut r = ConfigPaths {
            persistent: relative_owned(persistent.as_ref()),
            runtime: relative_owned(runtime.as_ref()),
            system: system.as_ref().map(|s| relative_owned(s.as_ref())),
        };
        let path = "ostree";
        r.persistent.push(path);
        r.runtime.push(path);
        if let Some(system) = r.system.as_mut() {
            system.push(path);
        }
        r
    }

    /// Return the path and an open fd for a config file, if it exists.
    pub(crate) fn open_file(
        &self,
        root: &Dir,
        p: impl AsRef<Utf8Path>,
    ) -> Result<Option<(Utf8PathBuf, File)>> {
        let p = p.as_ref();
        let mut runtime = self.runtime.clone();
        runtime.push(p);
        if let Some(f) = root.open_optional(&runtime)?.map(|f| f.into_std()) {
            return Ok(Some((runtime, f)));
        }
        let mut persistent = self.persistent.clone();
        persistent.push(p);
        if let Some(f) = root.open_optional(&persistent)?.map(|f| f.into_std()) {
            return Ok(Some((persistent, f)));
        }
        if let Some(mut system) = self.system.clone() {
            system.push(p);
            if let Some(f) = root.open_optional(&system)?.map(|f| f.into_std()) {
                return Ok(Some((system, f)));
            }
        }
        Ok(None)
    }
}

/// Return the path to the global container authentication file, if it exists.
pub fn get_global_authfile(root: &Dir) -> Result<Option<(Utf8PathBuf, File)>> {
    let am_uid0 = rustix::process::getuid() == rustix::process::Uid::ROOT;
    get_global_authfile_impl(root, am_uid0)
}

/// Return the path to the global container authentication file, if it exists.
fn get_global_authfile_impl(root: &Dir, am_uid0: bool) -> Result<Option<(Utf8PathBuf, File)>> {
    let paths = get_config_paths(am_uid0);
    paths.open_file(root, "auth.json")
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    use camino::Utf8PathBuf;
    use cap_std_ext::{cap_std, cap_tempfile};

    fn read_authfile(root: &Dir, am_uid0: bool) -> Result<Option<(Utf8PathBuf, String)>> {
        let r = get_global_authfile_impl(root, am_uid0)?;
        if let Some((path, mut f)) = r {
            let mut s = String::new();
            f.read_to_string(&mut s)?;
            Ok(Some((path.try_into()?, s)))
        } else {
            Ok(None)
        }
    }

    #[test]
    fn test_config_paths() -> Result<()> {
        let root = &cap_tempfile::TempDir::new(cap_std::ambient_authority())?;
        assert!(read_authfile(root, true).unwrap().is_none());
        root.create_dir_all("etc/ostree")?;
        root.write("etc/ostree/auth.json", "etc ostree auth")?;
        let (p, authdata) = read_authfile(root, true).unwrap().unwrap();
        assert_eq!(p, "etc/ostree/auth.json");
        assert_eq!(authdata, "etc ostree auth");
        root.create_dir_all("usr/lib/ostree")?;
        root.write("usr/lib/ostree/auth.json", "usrlib ostree auth")?;
        // We should see /etc content still
        let (p, authdata) = read_authfile(root, true).unwrap().unwrap();
        assert_eq!(p, "etc/ostree/auth.json");
        assert_eq!(authdata, "etc ostree auth");
        // Now remove the /etc content, unveiling the /usr content
        root.remove_file("etc/ostree/auth.json")?;
        let (p, authdata) = read_authfile(root, true).unwrap().unwrap();
        assert_eq!(p, "usr/lib/ostree/auth.json");
        assert_eq!(authdata, "usrlib ostree auth");

        // Non-root
        let mut user_runtime_dir =
            Utf8Path::from_path(glib::user_runtime_dir().strip_prefix("/").unwrap())
                .unwrap()
                .to_path_buf();
        user_runtime_dir.push("ostree");
        root.create_dir_all(&user_runtime_dir)?;
        user_runtime_dir.push("auth.json");
        root.write(&user_runtime_dir, "usr_runtime_dir ostree auth")?;

        let mut user_config_dir =
            Utf8Path::from_path(glib::user_config_dir().strip_prefix("/").unwrap())
                .unwrap()
                .to_path_buf();
        user_config_dir.push("ostree");
        root.create_dir_all(&user_config_dir)?;
        user_config_dir.push("auth.json");
        root.write(&user_config_dir, "usr_config_dir ostree auth")?;

        // We should see runtime_dir content still
        let (p, authdata) = read_authfile(root, false).unwrap().unwrap();
        assert_eq!(p, user_runtime_dir);
        assert_eq!(authdata, "usr_runtime_dir ostree auth");

        // Now remove the runtime_dir content, unveiling the config_dir content
        root.remove_file(&user_runtime_dir)?;
        let (p, authdata) = read_authfile(root, false).unwrap().unwrap();
        assert_eq!(p, user_config_dir);
        assert_eq!(authdata, "usr_config_dir ostree auth");

        Ok(())
    }
}
