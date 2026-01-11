use anyhow::{Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use clap::Subcommand;
use fn_error_context::context;
use xshell::{Shell, cmd};

const BUILDER_ANNOTATION: &str = "bootc.diskimage-builder";
const TEST_IMAGE: &str = "localhost/bootc";
const TESTVMDIR: &str = "testvm";
const DISK_CACHE: &str = "disk.qcow2";
const IMAGEID_XATTR: &str = "user.bootc.container-image-digest";

#[derive(Debug, Subcommand)]
#[clap(rename_all = "kebab-case")]
pub(crate) enum Opt {
    PrepareTmt {
        #[clap(long)]
        /// The container image to spawn, otherwise one will be built
        testimage: Option<String>,
    },
    CreateQcow2 {
        /// Input container image
        container: String,
        /// Write disk to this path
        disk: Utf8PathBuf,
    },
}

struct TestContext {
    sh: xshell::Shell,
    targetdir: Utf8PathBuf,
}

fn image_digest(sh: &Shell, cimage: &str) -> Result<String> {
    let key = "{{ .Digest }}";
    let r = cmd!(sh, "podman inspect --type image --format {key} {cimage}").read()?;
    Ok(r)
}

fn builder_from_image(sh: &Shell, cimage: &str) -> Result<String> {
    let mut inspect: serde_json::Value =
        serde_json::from_str(&cmd!(sh, "podman inspect --type image {cimage}").read()?)?;
    let inspect = inspect
        .as_array_mut()
        .and_then(|v| v.pop())
        .ok_or_else(|| anyhow::anyhow!("Failed to parse inspect output"))?;
    let config = inspect
        .get("Config")
        .ok_or_else(|| anyhow::anyhow!("Missing config"))?;
    let config: oci_spec::image::Config =
        serde_json::from_value(config.clone()).context("Parsing config")?;
    let builder = config
        .labels()
        .as_ref()
        .and_then(|l| l.get(BUILDER_ANNOTATION))
        .ok_or_else(|| anyhow::anyhow!("Missing {BUILDER_ANNOTATION}"))?;
    Ok(builder.to_owned())
}

#[context("Running bootc-image-builder")]
fn run_bib(sh: &Shell, cimage: &str, tmpdir: &Utf8Path, diskpath: &Utf8Path) -> Result<()> {
    let diskpath: Utf8PathBuf = sh.current_dir().join(diskpath).try_into()?;
    let digest = image_digest(sh, cimage)?;
    println!("{cimage} digest={digest}");
    if diskpath.try_exists()? {
        let mut buf = [0u8; 2048];
        if let Ok(n) = rustix::fs::getxattr(diskpath.as_std_path(), IMAGEID_XATTR, &mut buf)
            .context("Reading xattr")
        {
            let buf = String::from_utf8_lossy(&buf[0..n]);
            if &*buf == digest.as_str() {
                println!("Existing disk {diskpath} matches container digest {digest}");
                return Ok(());
            } else {
                println!("Cache miss; previous digest={buf}");
            }
        }
    }
    let builder = if let Ok(b) = std::env::var("BOOTC_BUILDER") {
        b
    } else {
        builder_from_image(sh, cimage)?
    };
    let _g = sh.push_dir(tmpdir);
    let bibwork = "bib-work";
    sh.remove_path(bibwork)?;
    sh.create_dir(bibwork)?;
    let _g = sh.push_dir(bibwork);
    let pwd = sh.current_dir();
    cmd!(sh, "podman run --rm --privileged -v /var/lib/containers/storage:/var/lib/containers/storage --security-opt label=type:unconfined_t -v {pwd}:/output {builder} --type qcow2 --local {cimage}").run()?;
    let tmp_disk: Utf8PathBuf = sh
        .current_dir()
        .join("qcow2/disk.qcow2")
        .try_into()
        .unwrap();
    rustix::fs::setxattr(
        tmp_disk.as_std_path(),
        IMAGEID_XATTR,
        digest.as_bytes(),
        rustix::fs::XattrFlags::empty(),
    )
    .context("Setting xattr")?;
    cmd!(sh, "mv -Tf {tmp_disk} {diskpath}").run()?;
    cmd!(sh, "rm -rf {bibwork}").run()?;
    Ok(())
}

/// Given the input container image reference, create a disk
/// image in the target directory.
#[context("Creating disk")]
fn create_disk(ctx: &TestContext, cimage: &str) -> Result<Utf8PathBuf> {
    let sh = &ctx.sh;
    let targetdir = ctx.targetdir.as_path();
    let _targetdir_guard = sh.push_dir(targetdir);
    sh.create_dir(TESTVMDIR)?;
    let output_disk: Utf8PathBuf = sh
        .current_dir()
        .join(TESTVMDIR)
        .join(DISK_CACHE)
        .try_into()
        .unwrap();

    let bibwork = "bib-work";
    sh.remove_path(bibwork)?;
    sh.create_dir(bibwork)?;

    run_bib(sh, cimage, bibwork.into(), &output_disk)?;

    Ok(output_disk)
}

pub(crate) fn run(opt: Opt) -> Result<()> {
    let ctx = &{
        let sh = xshell::Shell::new()?;
        let mut targetdir: Utf8PathBuf = cmd!(sh, "git rev-parse --show-toplevel").read()?.into();
        targetdir.push("target");
        TestContext { targetdir, sh }
    };
    match opt {
        Opt::PrepareTmt { mut testimage } => {
            let testimage = if let Some(i) = testimage.take() {
                i
            } else {
                let source_date_epoch = cmd!(&ctx.sh, "git log -1 --pretty=%ct").read()?;
                cmd!(
                    &ctx.sh,
                    "podman build --timestamp={source_date_epoch} --build-arg=variant=tmt -t {TEST_IMAGE} -f hack/Containerfile ."
                )
                .run()?;
                TEST_IMAGE.to_string()
            };

            let disk = create_disk(ctx, &testimage)?;
            println!("Created: {disk}");
            Ok(())
        }
        Opt::CreateQcow2 { container, disk } => {
            let g = ctx.sh.push_dir(&ctx.targetdir);
            ctx.sh.remove_path("tmp")?;
            ctx.sh.create_dir("tmp")?;
            drop(g);
            run_bib(&ctx.sh, &container, "tmp".into(), &disk)
        }
    }
}
