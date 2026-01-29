use std::{
    ffi::OsString,
    fs::{File, create_dir_all},
    io::BufWriter,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};

use rustix::fs::CWD;

use composefs_boot::{BootOps, write_boot};

use composefs::{
    dumpfile,
    fsverity::{FsVerityHashValue, Sha512HashValue},
    repository::Repository,
};

/// cfsctl
#[derive(Debug, Parser)]
#[clap(name = "cfsctl", version)]
pub struct App {
    #[clap(long, group = "repopath")]
    repo: Option<PathBuf>,
    #[clap(long, group = "repopath")]
    user: bool,
    #[clap(long, group = "repopath")]
    system: bool,

    /// Sets the repository to insecure before running any operation and
    /// prepend '?' to the composefs kernel command line when writing
    /// boot entry.
    #[clap(long)]
    insecure: bool,

    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum OciCommand {
    /// Stores a tar file as a splitstream in the repository.
    ImportLayer {
        digest: String,
        name: Option<String>,
    },
    /// Lists the contents of a tar stream
    LsLayer {
        /// the name of the stream
        name: String,
    },
    Dump {
        config_name: String,
        config_verity: Option<String>,
    },
    Pull {
        image: String,
        name: Option<String>,
    },
    ComputeId {
        config_name: String,
        config_verity: Option<String>,
        #[clap(long)]
        bootable: bool,
    },
    CreateImage {
        config_name: String,
        config_verity: Option<String>,
        #[clap(long)]
        bootable: bool,
        #[clap(long)]
        image_name: Option<String>,
    },
    Seal {
        config_name: String,
        config_verity: Option<String>,
    },
    Mount {
        name: String,
        mountpoint: String,
    },
    PrepareBoot {
        config_name: String,
        config_verity: Option<String>,
        #[clap(long, default_value = "/boot")]
        bootdir: PathBuf,
        #[clap(long)]
        entry_id: Option<String>,
        #[clap(long)]
        cmdline: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Take a transaction lock on the repository.
    /// This prevents garbage collection from occurring.
    Transaction,
    /// Reconstitutes a split stream and writes it to stdout
    Cat {
        /// the name of the stream to cat, either a content identifier or prefixed with 'ref/'
        name: String,
    },
    /// Perform garbage collection
    GC,
    /// Imports a composefs image (unsafe!)
    ImportImage {
        reference: String,
    },
    /// Commands for dealing with OCI layers
    Oci {
        #[clap(subcommand)]
        cmd: OciCommand,
    },
    /// Mounts a composefs, possibly enforcing fsverity of the image
    Mount {
        /// the name of the image to mount, either an fs-verity hash or prefixed with 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
    },
    /// Creates a composefs image from a filesystem
    CreateImage {
        path: PathBuf,
        #[clap(long)]
        bootable: bool,
        /// Don't copy /usr metadata to root directory (use if root already has well-defined metadata)
        #[clap(long)]
        no_propagate_usr_to_root: bool,
        image_name: Option<String>,
    },
    /// Computes the composefs image ID for a filesystem
    ComputeId {
        path: PathBuf,
        /// Write the dumpfile to the provided target
        #[clap(long)]
        write_dumpfile_to: Option<Utf8PathBuf>,
        #[clap(long)]
        bootable: bool,
        /// Don't copy /usr metadata to root directory (use if root already has well-defined metadata)
        #[clap(long)]
        no_propagate_usr_to_root: bool,
    },
    /// Outputs the composefs dumpfile format for a filesystem
    CreateDumpfile {
        path: PathBuf,
        #[clap(long)]
        bootable: bool,
        /// Don't copy /usr metadata to root directory (use if root already has well-defined metadata)
        #[clap(long)]
        no_propagate_usr_to_root: bool,
    },
    ImageObjects {
        name: String,
    },
}

fn verity_opt(opt: &Option<String>) -> Result<Option<Sha512HashValue>> {
    Ok(opt.as_ref().map(FsVerityHashValue::from_hex).transpose()?)
}

pub(crate) async fn run_from_iter<I>(args: I) -> Result<()>
where
    I: IntoIterator,
    I::Item: Into<OsString> + Clone,
{
    let args = App::parse_from(
        std::iter::once(OsString::from("cfs")).chain(args.into_iter().map(Into::into)),
    );

    let repo = if let Some(path) = &args.repo {
        let mut r = Repository::open_path(CWD, path)?;
        r.set_insecure(args.insecure);
        Arc::new(r)
    } else if args.user {
        let mut r = Repository::open_user()?;
        r.set_insecure(args.insecure);
        Arc::new(r)
    } else {
        if args.insecure {
            anyhow::bail!("Cannot override insecure state for system repo");
        }
        let system_store = crate::cli::get_storage().await?;
        system_store.get_ensure_composefs()?
    };
    let repo = &repo;

    match args.cmd {
        Command::Transaction => {
            // just wait for ^C
            loop {
                std::thread::park();
            }
        }
        Command::Cat { name } => {
            repo.merge_splitstream(&name, None, None, &mut std::io::stdout())?;
        }
        Command::ImportImage { reference } => {
            let image_id = repo.import_image(&reference, &mut std::io::stdin())?;
            println!("{}", image_id.to_id());
        }
        Command::Oci { cmd: oci_cmd } => match oci_cmd {
            OciCommand::ImportLayer { name, digest } => {
                let object_id = composefs_oci::import_layer(
                    repo,
                    &digest,
                    name.as_deref(),
                    &mut std::io::stdin(),
                )?;
                println!("{}", object_id.to_id());
            }
            OciCommand::LsLayer { name } => {
                composefs_oci::ls_layer(repo, &name)?;
            }
            OciCommand::Dump {
                ref config_name,
                ref config_verity,
            } => {
                let verity = verity_opt(config_verity)?;
                let fs =
                    composefs_oci::image::create_filesystem(repo, config_name, verity.as_ref())?;
                fs.print_dumpfile()?;
            }
            OciCommand::ComputeId {
                ref config_name,
                ref config_verity,
                bootable,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(repo)?;
                }
                let id = fs.compute_image_id();
                println!("{}", id.to_hex());
            }
            OciCommand::CreateImage {
                ref config_name,
                ref config_verity,
                bootable,
                ref image_name,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(repo, config_name, verity.as_ref())?;
                if bootable {
                    fs.transform_for_boot(repo)?;
                }
                let image_id = fs.commit_image(repo, image_name.as_deref())?;
                println!("{}", image_id.to_id());
            }
            OciCommand::Pull { ref image, name } => {
                let (digest, verity) =
                    composefs_oci::pull(repo, image, name.as_deref(), None).await?;

                println!("config {digest}");
                println!("verity {}", verity.to_hex());
            }
            OciCommand::Seal {
                ref config_name,
                ref config_verity,
            } => {
                let verity = verity_opt(config_verity)?;
                let (digest, verity) = composefs_oci::seal(repo, config_name, verity.as_ref())?;
                println!("config {digest}");
                println!("verity {}", verity.to_id());
            }
            OciCommand::Mount {
                ref name,
                ref mountpoint,
            } => {
                composefs_oci::mount(repo, name, mountpoint, None)?;
            }
            OciCommand::PrepareBoot {
                ref config_name,
                ref config_verity,
                ref bootdir,
                ref entry_id,
                ref cmdline,
            } => {
                let verity = verity_opt(config_verity)?;
                let mut fs =
                    composefs_oci::image::create_filesystem(repo, config_name, verity.as_ref())?;
                let entries = fs.transform_for_boot(repo)?;
                let id = fs.commit_image(repo, None)?;

                let Some(entry) = entries.into_iter().next() else {
                    anyhow::bail!("No boot entries!");
                };

                let cmdline_refs: Vec<&str> = cmdline.iter().map(String::as_str).collect();
                write_boot::write_boot_simple(
                    repo,
                    entry,
                    &id,
                    args.insecure,
                    bootdir,
                    None,
                    entry_id.as_deref(),
                    &cmdline_refs,
                )?;

                let state = args
                    .repo
                    .as_ref()
                    .map(|p: &PathBuf| p.parent().unwrap())
                    .unwrap_or(Path::new("/sysroot"))
                    .join("state/deploy")
                    .join(id.to_hex());

                create_dir_all(state.join("var"))?;
                create_dir_all(state.join("etc/upper"))?;
                create_dir_all(state.join("etc/work"))?;
            }
        },
        Command::ComputeId {
            ref path,
            write_dumpfile_to,
            bootable,
            no_propagate_usr_to_root,
        } => {
            let mut fs = if no_propagate_usr_to_root {
                composefs::fs::read_filesystem(CWD, path, Some(repo.as_ref()))?
            } else {
                composefs::fs::read_container_root(CWD, path, Some(repo.as_ref()))?
            };
            if bootable {
                fs.transform_for_boot(repo)?;
            }
            let id = fs.compute_image_id();
            println!("{}", id.to_hex());
            if let Some(path) = write_dumpfile_to.as_deref() {
                let mut w = File::create(path)
                    .with_context(|| format!("Opening {path}"))
                    .map(BufWriter::new)?;
                dumpfile::write_dumpfile(&mut w, &fs).context("Writing dumpfile")?;
            }
        }
        Command::CreateImage {
            ref path,
            bootable,
            no_propagate_usr_to_root,
            ref image_name,
        } => {
            let mut fs = if no_propagate_usr_to_root {
                composefs::fs::read_filesystem(CWD, path, Some(repo.as_ref()))?
            } else {
                composefs::fs::read_container_root(CWD, path, Some(repo.as_ref()))?
            };
            if bootable {
                fs.transform_for_boot(repo)?;
            }
            let id = fs.commit_image(repo, image_name.as_deref())?;
            println!("{}", id.to_id());
        }
        Command::CreateDumpfile {
            ref path,
            bootable,
            no_propagate_usr_to_root,
        } => {
            let mut fs = if no_propagate_usr_to_root {
                composefs::fs::read_filesystem(CWD, path, Some(repo.as_ref()))?
            } else {
                composefs::fs::read_container_root(CWD, path, Some(repo.as_ref()))?
            };
            if bootable {
                fs.transform_for_boot(repo)?;
            }
            fs.print_dumpfile()?;
        }
        Command::Mount { name, mountpoint } => {
            repo.mount_at(&name, &mountpoint)?;
        }
        Command::ImageObjects { name } => {
            let objects = repo.objects_for_image(&name)?;
            for object in objects {
                println!("{}", object.to_id());
            }
        }
        Command::GC => {
            repo.gc(&[])?;
        }
    }
    Ok(())
}
