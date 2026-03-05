//! Integration tests.

use camino::Utf8PathBuf;
use cap_std_ext::cap_std::{self, fs::Dir};
use clap::Parser;

mod container;
mod hostpriv;
mod install;
mod runvm;
mod selinux;
mod system_reinstall;

#[derive(Debug, Parser)]
#[clap(name = "bootc-integration-tests", version, rename_all = "kebab-case")]
pub(crate) enum Opt {
    SystemReinstall {
        /// Source container image reference
        image: String,
        #[clap(flatten)]
        testargs: libtest_mimic::Arguments,
    },
    InstallAlongside {
        /// Source container image reference
        image: String,
        #[clap(flatten)]
        testargs: libtest_mimic::Arguments,
    },
    InstallFlat {
        /// Source container image reference
        image: String,
        #[clap(flatten)]
        testargs: libtest_mimic::Arguments,
    },
    HostPrivileged {
        image: String,
        #[clap(flatten)]
        testargs: libtest_mimic::Arguments,
    },
    /// Tests which should be executed inside an existing bootc container image.
    /// These should be nondestructive.
    Container {
        #[clap(flatten)]
        testargs: libtest_mimic::Arguments,
    },
    #[clap(subcommand)]
    RunVM(runvm::Opt),
    /// Extra helper utility to verify SELinux label presence
    #[clap(name = "verify-selinux")]
    VerifySELinux {
        /// Path to target root
        rootfs: Utf8PathBuf,
        #[clap(long)]
        warn: bool,
    },
}

fn main() {
    let opt = Opt::parse();
    let r = match opt {
        Opt::SystemReinstall { image, testargs } => system_reinstall::run(&image, testargs),
        Opt::InstallAlongside { image, testargs } => install::run_alongside(&image, testargs),
        Opt::InstallFlat { image, testargs } => install::run_flat(&image, testargs),
        Opt::HostPrivileged { image, testargs } => hostpriv::run_hostpriv(&image, testargs),
        Opt::Container { testargs } => container::run(testargs),
        Opt::RunVM(opts) => runvm::run(opts),
        Opt::VerifySELinux { rootfs, warn } => {
            let root = &Dir::open_ambient_dir(&rootfs, cap_std::ambient_authority()).unwrap();
            selinux::verify_selinux_recurse(root, warn)
        }
    };
    if let Err(e) = r {
        eprintln!("error: {e:?}");
        std::process::exit(1);
    }
}
