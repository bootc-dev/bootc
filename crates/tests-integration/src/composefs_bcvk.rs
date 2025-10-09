use anyhow::Result;
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
