use anyhow::Result;
use bootc_kernel_cmdline;
use camino::Utf8Path;
use libtest_mimic::Trial;
use xshell::{cmd, Shell};

const BOOTED: &str = "<booted>";

fn outer_runner(image: &'static str) -> Vec<Trial> {
    [Trial::test("Basic", move || {
        let sh = &xshell::Shell::new()?;
        const NAME: &str = "bootc-composefs-bcvk-test";
        struct StopTestVM<'a>(&'a Shell);
        impl<'a> Drop for StopTestVM<'a> {
            fn drop(&mut self) {
                let _ = cmd!(self.0, "bcvk libvirt rm --stop --force {NAME}")
                    .ignore_status()
                    .ignore_stdout()
                    .ignore_stderr()
                    .quiet()
                    .run();
            }
        }
        // Clean up any leakage if e.g. the whole process died
        drop(StopTestVM(sh));
        // And also do so on drop
        let _guard = StopTestVM(sh);
        cmd!(
            sh,
            "bcvk libvirt run --name {NAME} --filesystem=ext4 --firmware=uefi-insecure {image}"
        )
        .run()?;
        for _ in 0..5 {
            if cmd!(sh, "bcvk libvirt ssh {NAME} -- true")
                .ignore_stderr()
                .run()
                .is_ok()
            {
                break;
            }
        }
        cmd!(
            sh,
            "bcvk libvirt ssh {NAME} -- bootc-integration-tests composefs-bcvk {BOOTED}"
        )
        .run()?;
        Ok(())
    })]
    .into_iter()
    .collect()
}

fn inner_tests() -> Vec<Trial> {
    [Trial::test("Basic", move || {
        let sh = &xshell::Shell::new()?;
        let st = cmd!(sh, "bootc status --json").read()?;
        let st: serde_json::Value = serde_json::from_str(&st)?;
        assert!(st.is_object());
        assert!(Utf8Path::new("/sysroot/composefs").try_exists()?);
        assert!(!Utf8Path::new("/sysroot/ostree").try_exists()?);

        let cmdline = bootc_kernel_cmdline::utf8::Cmdline::from_proc()?;

        let cfs = cmdline.find("composefs");
        assert!(cfs.is_some());
        let cfs = cfs.unwrap();

        let verity_from_cmdline = cfs.value();
        assert!(verity_from_cmdline.is_some());
        let verity_from_cmdline = verity_from_cmdline.unwrap();

        let verity_from_status = st
            .get("status")
            .and_then(|s| s.get("booted"))
            .and_then(|b| b.get("composefs"))
            .and_then(|c| c.get("verity"))
            .and_then(|v| v.as_str());

        assert!(verity_from_status.is_some());

        assert_eq!(verity_from_status.unwrap(), verity_from_cmdline);

        // Verify that we booted via systemd-gpt-auto-generator by checking
        // that /proc/cmdline does NOT contain a root= parameter
        let has_root_param = cmdline.iter().any(|entry| {
            entry.key() == "root".into()
        });
        assert!(!has_root_param, "Sealed composefs image should not have root= in kernel cmdline; systemd-gpt-auto-generator should discover the root partition via DPS");

        Ok(())
    })]
    .into_iter()
    .collect()
}

//#[context("Composefs+bcvk tests")]
pub(crate) fn run(image: &str, testargs: libtest_mimic::Arguments) -> Result<()> {
    // Just leak the image name so we get a static reference as required by the test framework
    let image: &'static str = String::from(image).leak();
    // Handy defaults

    let tests = if image == BOOTED {
        inner_tests()
    } else {
        outer_runner(image)
    };

    libtest_mimic::run(&testargs, tests.into()).exit()
}
