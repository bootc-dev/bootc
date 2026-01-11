//! Code for bootc that goes into the initramfs.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use anyhow::Result;

use bootc_initramfs_setup::{Args, gpt_workaround, setup_root};
use clap::Parser;

fn main() -> Result<()> {
    let args = Args::parse();
    gpt_workaround()?;
    setup_root(args)
}
