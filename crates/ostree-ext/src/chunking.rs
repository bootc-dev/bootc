//! Split an OSTree commit into separate chunks

// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::borrow::{Borrow, Cow};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::hash::{Hash, Hasher};
use std::num::NonZeroU32;
use std::rc::Rc;
use std::time::Instant;

use crate::container::{COMPONENT_SEPARATOR, CONTENT_ANNOTATION};
use crate::objectsource::{ContentID, ObjectMeta, ObjectMetaMap, ObjectSourceMeta};
use crate::objgv::*;
use crate::statistics;
use anyhow::{anyhow, Result};
use camino::{Utf8Path, Utf8PathBuf};
use containers_image_proxy::oci_spec;
use gvariant::aligned_bytes::TryAsAligned;
use gvariant::{Marker, Structure};
use indexmap::IndexMap;
use ostree::{gio, glib};
use serde::{Deserialize, Serialize};

/// Maximum number of layers (chunks) we will use.
// We take half the limit of 128.
// https://github.com/ostreedev/ostree-rs-ext/issues/69
pub(crate) const MAX_CHUNKS: u32 = 64;
/// Minimum number of layers we can create in a "chunked" flow; otherwise
/// we will just drop down to one.
const MIN_CHUNKED_LAYERS: u32 = 4;

/// A convenient alias for a reference-counted, immutable string.
pub(crate) type RcStr = Rc<str>;
/// Maps from a checksum to its size and file names (multiple in the case of
/// hard links).
pub(crate) type ChunkMapping = BTreeMap<RcStr, (u64, Vec<Utf8PathBuf>)>;
// TODO type PackageSet = HashSet<RcStr>;

const LOW_PARTITION: &str = "2ls";
const HIGH_PARTITION: &str = "1hs";

#[derive(Debug, Default)]
pub(crate) struct Chunk {
    pub(crate) name: String,
    pub(crate) content: ChunkMapping,
    pub(crate) size: u64,
    pub(crate) packages: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
/// Object metadata, but with additional size data
pub struct ObjectSourceMetaSized {
    /// The original metadata
    #[serde(flatten)]
    pub meta: ObjectSourceMeta,
    /// Total size of associated objects
    pub size: u64,
}

impl Hash for ObjectSourceMetaSized {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.meta.identifier.hash(state);
    }
}

impl Eq for ObjectSourceMetaSized {}

impl PartialEq for ObjectSourceMetaSized {
    fn eq(&self, other: &Self) -> bool {
        self.meta.identifier == other.meta.identifier
    }
}

/// Extend content source metadata with sizes.
#[derive(Debug)]
pub struct ObjectMetaSized {
    /// Mapping from content object to source.
    pub map: ObjectMetaMap,
    /// Computed sizes of each content source
    pub sizes: Vec<ObjectSourceMetaSized>,
}

impl ObjectMetaSized {
    /// Given object metadata and a repo, compute the size of each content source.
    pub fn compute_sizes(repo: &ostree::Repo, meta: ObjectMeta) -> Result<ObjectMetaSized> {
        let cancellable = gio::Cancellable::NONE;
        // Destructure into component parts; we'll create the version with sizes
        let map = meta.map;
        let mut set = meta.set;
        // Maps content id -> total size of associated objects
        let mut sizes = BTreeMap::<&str, u64>::new();
        // Populate two mappings above, iterating over the object -> contentid mapping
        for (checksum, contentid) in map.iter() {
            let finfo = repo.query_file(checksum, cancellable)?.0;
            let sz = sizes.entry(contentid).or_default();
            *sz += finfo.size() as u64;
        }
        // Combine data from sizes and the content mapping.
        let sized: Result<Vec<_>> = sizes
            .into_iter()
            .map(|(id, size)| -> Result<ObjectSourceMetaSized> {
                set.take(id)
                    .ok_or_else(|| anyhow!("Failed to find {} in content set", id))
                    .map(|meta| ObjectSourceMetaSized { meta, size })
            })
            .collect();
        let mut sizes = sized?;
        sizes.sort_by(|a, b| b.size.cmp(&a.size));
        Ok(ObjectMetaSized { map, sizes })
    }
}

/// How to split up an ostree commit into "chunks" - designed to map to container image layers.
#[derive(Debug, Default)]
pub struct Chunking {
    pub(crate) metadata_size: u64,
    pub(crate) remainder: Chunk,
    pub(crate) chunks: Vec<Chunk>,

    pub(crate) max: u32,

    processed_mapping: bool,
    /// Number of components (e.g. packages) provided originally
    pub(crate) n_provided_components: u32,
    /// The above, but only ones with non-zero size
    pub(crate) n_sized_components: u32,
}

#[derive(Default)]
struct Generation {
    path: Utf8PathBuf,
    metadata_size: u64,
    dirtree_found: BTreeSet<RcStr>,
    dirmeta_found: BTreeSet<RcStr>,
}

fn push_dirmeta(repo: &ostree::Repo, gen: &mut Generation, checksum: &str) -> Result<()> {
    if gen.dirtree_found.contains(checksum) {
        return Ok(());
    }
    let checksum = RcStr::from(checksum);
    gen.dirmeta_found.insert(RcStr::clone(&checksum));
    let child_v = repo.load_variant(ostree::ObjectType::DirMeta, checksum.borrow())?;
    gen.metadata_size += child_v.data_as_bytes().as_ref().len() as u64;
    Ok(())
}

fn push_dirtree(
    repo: &ostree::Repo,
    gen: &mut Generation,
    checksum: &str,
) -> Result<glib::Variant> {
    let child_v = repo.load_variant(ostree::ObjectType::DirTree, checksum)?;
    if !gen.dirtree_found.contains(checksum) {
        gen.metadata_size += child_v.data_as_bytes().as_ref().len() as u64;
    } else {
        let checksum = RcStr::from(checksum);
        gen.dirtree_found.insert(checksum);
    }
    Ok(child_v)
}

fn generate_chunking_recurse(
    repo: &ostree::Repo,
    gen: &mut Generation,
    chunk: &mut Chunk,
    dt: &glib::Variant,
) -> Result<()> {
    let dt = dt.data_as_bytes();
    let dt = dt.try_as_aligned()?;
    let dt = gv_dirtree!().cast(dt);
    let (files, dirs) = dt.to_tuple();
    // A reusable buffer to avoid heap allocating these
    let mut hexbuf = [0u8; 64];
    for file in files {
        let (name, csum) = file.to_tuple();
        let fpath = gen.path.join(name.to_str());
        hex::encode_to_slice(csum, &mut hexbuf)?;
        let checksum = std::str::from_utf8(&hexbuf)?;
        let meta = repo.query_file(checksum, gio::Cancellable::NONE)?.0;
        let size = meta.size() as u64;
        let entry = chunk.content.entry(RcStr::from(checksum)).or_default();
        entry.0 = size;
        let first = entry.1.is_empty();
        if first {
            chunk.size += size;
        }
        entry.1.push(fpath);
    }
    for item in dirs {
        let (name, contents_csum, meta_csum) = item.to_tuple();
        let name = name.to_str();
        // Extend our current path
        gen.path.push(name);
        hex::encode_to_slice(contents_csum, &mut hexbuf)?;
        let checksum_s = std::str::from_utf8(&hexbuf)?;
        let dirtree_v = push_dirtree(repo, gen, checksum_s)?;
        generate_chunking_recurse(repo, gen, chunk, &dirtree_v)?;
        drop(dirtree_v);
        hex::encode_to_slice(meta_csum, &mut hexbuf)?;
        let checksum_s = std::str::from_utf8(&hexbuf)?;
        push_dirmeta(repo, gen, checksum_s)?;
        // We did a push above, so pop must succeed.
        assert!(gen.path.pop());
    }
    Ok(())
}

impl Chunk {
    fn new(name: &str) -> Self {
        Chunk {
            name: name.to_string(),
            ..Default::default()
        }
    }

    pub(crate) fn move_obj(&mut self, dest: &mut Self, checksum: &str) -> bool {
        // In most cases, we expect the object to exist in the source.  However, it's
        // conveneient here to simply ignore objects which were already moved into
        // a chunk.
        if let Some((name, (size, paths))) = self.content.remove_entry(checksum) {
            let v = dest.content.insert(name, (size, paths));
            debug_assert!(v.is_none());
            self.size -= size;
            dest.size += size;
            true
        } else {
            false
        }
    }

    pub(crate) fn move_path(&mut self, dest: &mut Self, checksum: &str, path: &Utf8Path) {
        if let Some((_size, paths)) = self.content.get_mut(checksum) {
            let path_index = paths.iter().position(|p| *p == path);
            if let Some(index) = path_index {
                let removed_path = paths.remove(index);

                let dest_entry = dest
                    .content
                    .entry(RcStr::from(checksum))
                    .or_insert((0, Vec::new()));
                dest_entry.1.push(removed_path);

                if paths.is_empty() {
                    self.content.remove(checksum);
                }
            }
        }
    }
}

impl Chunking {
    /// Creates a reverse map from content IDs to checksums
    fn create_content_id_map(
        map: &IndexMap<String, ContentID>,
    ) -> IndexMap<ContentID, Vec<&String>> {
        let mut rmap = IndexMap::<ContentID, Vec<&String>>::new();
        for (checksum, contentid) in map.iter() {
            rmap.entry(Rc::clone(contentid)).or_default().push(checksum);
        }
        rmap
    }

    /// Generate an initial single chunk.
    pub fn new(repo: &ostree::Repo, rev: &str) -> Result<Self> {
        // Find the target commit
        let rev = repo.require_rev(rev)?;

        // Load and parse the commit object
        let (commit_v, _) = repo.load_commit(&rev)?;
        let commit_v = commit_v.data_as_bytes();
        let commit_v = commit_v.try_as_aligned()?;
        let commit = gv_commit!().cast(commit_v);
        let commit = commit.to_tuple();

        // Load it all into a single chunk
        let mut gen = Generation {
            path: Utf8PathBuf::from("/"),
            ..Default::default()
        };
        let mut chunk: Chunk = Default::default();

        // Find the root directory tree
        let contents_checksum = &hex::encode(commit.6);
        let contents_v = repo.load_variant(ostree::ObjectType::DirTree, contents_checksum)?;
        push_dirtree(repo, &mut gen, contents_checksum)?;
        let meta_checksum = &hex::encode(commit.7);
        push_dirmeta(repo, &mut gen, meta_checksum.as_str())?;

        generate_chunking_recurse(repo, &mut gen, &mut chunk, &contents_v)?;

        let chunking = Chunking {
            metadata_size: gen.metadata_size,
            remainder: chunk,
            ..Default::default()
        };
        Ok(chunking)
    }

    /// Generate a chunking from an object mapping.
    pub fn from_mapping(
        repo: &ostree::Repo,
        rev: &str,
        meta: &ObjectMetaSized,
        max_layers: &Option<NonZeroU32>,
        prior_build_metadata: Option<&oci_spec::image::ImageManifest>,
        specific_contentmeta: Option<&BTreeMap<ContentID, Vec<(Utf8PathBuf, String)>>>,
    ) -> Result<Self> {
        let mut r = Self::new(repo, rev)?;
        r.process_mapping(meta, max_layers, prior_build_metadata, specific_contentmeta)?;
        Ok(r)
    }

    fn remaining(&self) -> u32 {
        self.max.saturating_sub(self.chunks.len() as u32)
    }

    /// Given metadata about which objects are owned by a particular content source,
    /// generate chunks that group together those objects.
    #[allow(clippy::or_fun_call)]
    pub fn process_mapping(
        &mut self,
        meta: &ObjectMetaSized,
        max_layers: &Option<NonZeroU32>,
        prior_build_metadata: Option<&oci_spec::image::ImageManifest>,
        specific_contentmeta: Option<&BTreeMap<ContentID, Vec<(Utf8PathBuf, String)>>>,
    ) -> Result<()> {
        self.max = max_layers
            .unwrap_or(NonZeroU32::new(MAX_CHUNKS).unwrap())
            .get();

        let sizes = &meta.sizes;
        // It doesn't make sense to handle multiple mappings
        assert!(!self.processed_mapping);
        self.processed_mapping = true;
        let remaining = self.remaining();
        if remaining == 0 {
            return Ok(());
        }

        // Create exclusive chunks first if specified
        let mut processed_specific_components = BTreeSet::new();
        if let Some(specific_meta) = specific_contentmeta {
            for (component, files) in specific_meta {
                let mut chunk = Chunk::new(&component);
                chunk.packages = vec![component.to_string()];

                // Move all objects belonging to this exclusive component
                for (path, checksum) in files {
                    self.remainder
                        .move_path(&mut chunk, checksum.as_str(), path);
                }

                self.chunks.push(chunk);
                processed_specific_components.insert(component.clone());
            }
        }

        // Safety: Let's assume no one has over 4 billion components.
        self.n_provided_components = meta.sizes.len().try_into().unwrap();
        self.n_sized_components = sizes
            .iter()
            .filter(|v| v.size > 0)
            .count()
            .try_into()
            .unwrap();

        // Filter out exclusive components for regular packing
        let regular_sizes: Vec<ObjectSourceMetaSized> = sizes
            .iter()
            .filter(|component| {
                !processed_specific_components.contains(&*component.meta.identifier)
            })
            .cloned()
            .collect();

        let rmap = Self::create_content_id_map(&meta.map);

        // Process regular components with bin packing if we have remaining layers
        if let Some(remaining) = NonZeroU32::new(self.remaining()) {
            let start = Instant::now();
            let packing = basic_packing(&regular_sizes, remaining, prior_build_metadata)?;
            let duration = start.elapsed();
            tracing::debug!("Time elapsed in packing: {:#?}", duration);

            for bin in packing.into_iter() {
                let name = match bin.len() {
                    0 => Cow::Borrowed("Reserved for new packages"),
                    1 => {
                        let first = bin[0];
                        let first_name = &*first.meta.identifier;
                        Cow::Borrowed(first_name)
                    }
                    2..=5 => {
                        let first = bin[0];
                        let first_name = &*first.meta.identifier;
                        let r = bin.iter().map(|v| &*v.meta.identifier).skip(1).fold(
                            String::from(first_name),
                            |mut acc, v| {
                                write!(acc, " and {v}").unwrap();
                                acc
                            },
                        );
                        Cow::Owned(r)
                    }
                    n => Cow::Owned(format!("{n} components")),
                };
                let mut chunk = Chunk::new(&name);
                chunk.packages = bin.iter().map(|v| String::from(&*v.meta.name)).collect();
                for szmeta in bin {
                    for &obj in rmap.get(&szmeta.meta.identifier).unwrap() {
                        self.remainder.move_obj(&mut chunk, obj.as_str());
                    }
                }
                self.chunks.push(chunk);
            }
        }

        // Check that all objects have been processed
        if !processed_specific_components.is_empty() || !regular_sizes.is_empty() {
            assert_eq!(self.remainder.content.len(), 0);
        }

        Ok(())
    }

    pub(crate) fn take_chunks(&mut self) -> Vec<Chunk> {
        let mut r = Vec::new();
        std::mem::swap(&mut self.chunks, &mut r);
        r
    }

    /// Print information about chunking to standard output.
    pub fn print(&self) {
        println!("Metadata: {}", glib::format_size(self.metadata_size));
        if self.n_provided_components > 0 {
            println!(
                "Components: provided={} sized={}",
                self.n_provided_components, self.n_sized_components
            );
        }
        for (n, chunk) in self.chunks.iter().enumerate() {
            let sz = glib::format_size(chunk.size);
            println!(
                "Chunk {}: \"{}\": objects:{} size:{}",
                n,
                chunk.name,
                chunk.content.len(),
                sz
            );
        }
        if !self.remainder.content.is_empty() {
            let sz = glib::format_size(self.remainder.size);
            println!(
                "Remainder: \"{}\": objects:{} size:{}",
                self.remainder.name,
                self.remainder.content.len(),
                sz
            );
        }
    }
}

#[cfg(test)]
fn components_size(components: &[&ObjectSourceMetaSized]) -> u64 {
    components.iter().map(|k| k.size).sum()
}

/// Compute the total size of a packing
#[cfg(test)]
fn packing_size(packing: &[Vec<&ObjectSourceMetaSized>]) -> u64 {
    packing.iter().map(|v| components_size(v)).sum()
}

/// Given a certain threshold, divide a list of packages into all combinations
/// of (high, medium, low) size and (high,medium,low) using the following
/// outlier detection methods:
/// - Median and Median Absolute Deviation Method
///   Aggressively detects outliers in size and classifies them by
///   high, medium, low. The high size and low size are separate partitions
///   and deserve bins of their own
/// - Mean and Standard Deviation Method
///   The medium partition from the previous step is less aggressively
///   classified by using mean for both size and frequency
///
/// Note: Assumes components is sorted by descending size
fn get_partitions_with_threshold<'a>(
    components: &[&'a ObjectSourceMetaSized],
    limit_hs_bins: usize,
    threshold: f64,
) -> Option<BTreeMap<String, Vec<&'a ObjectSourceMetaSized>>> {
    let mut partitions: BTreeMap<String, Vec<&ObjectSourceMetaSized>> = BTreeMap::new();
    let mut med_size: Vec<&ObjectSourceMetaSized> = Vec::new();
    let mut high_size: Vec<&ObjectSourceMetaSized> = Vec::new();

    let mut sizes: Vec<u64> = components.iter().map(|a| a.size).collect();
    let (median_size, mad_size) = statistics::median_absolute_deviation(&mut sizes)?;

    // We use abs here to ensure the lower limit stays positive
    let size_low_limit = 0.5 * f64::abs(median_size - threshold * mad_size);
    let size_high_limit = median_size + threshold * mad_size;

    for pkg in components {
        let size = pkg.size as f64;

        // high size (hs)
        if size >= size_high_limit {
            high_size.push(pkg);
        }
        // low size (ls)
        else if size <= size_low_limit {
            partitions
                .entry(LOW_PARTITION.to_string())
                .and_modify(|bin| bin.push(pkg))
                .or_insert_with(|| vec![pkg]);
        }
        // medium size (ms)
        else {
            med_size.push(pkg);
        }
    }

    // Extra high-size packages
    let mut remaining_pkgs: Vec<_> = if high_size.len() <= limit_hs_bins {
        Vec::new()
    } else {
        high_size.drain(limit_hs_bins..).collect()
    };
    assert!(high_size.len() <= limit_hs_bins);

    // Concatenate extra high-size packages + med_sizes to keep it descending sorted
    remaining_pkgs.append(&mut med_size);
    partitions.insert(HIGH_PARTITION.to_string(), high_size);

    // Ascending sorted by frequency, so each partition within medium-size is freq sorted
    remaining_pkgs.sort_by(|a, b| {
        a.meta
            .change_frequency
            .partial_cmp(&b.meta.change_frequency)
            .unwrap()
    });
    let med_sizes: Vec<u64> = remaining_pkgs.iter().map(|a| a.size).collect();
    let med_frequencies: Vec<u64> = remaining_pkgs
        .iter()
        .map(|a| a.meta.change_frequency.into())
        .collect();

    let med_mean_freq = statistics::mean(&med_frequencies)?;
    let med_stddev_freq = statistics::std_deviation(&med_frequencies)?;
    let med_mean_size = statistics::mean(&med_sizes)?;
    let med_stddev_size = statistics::std_deviation(&med_sizes)?;

    // We use abs to avoid the lower limit being negative
    let med_freq_low_limit = 0.5f64 * f64::abs(med_mean_freq - threshold * med_stddev_freq);
    let med_freq_high_limit = med_mean_freq + threshold * med_stddev_freq;
    let med_size_low_limit = 0.5f64 * f64::abs(med_mean_size - threshold * med_stddev_size);
    let med_size_high_limit = med_mean_size + threshold * med_stddev_size;

    for pkg in remaining_pkgs {
        let size = pkg.size as f64;
        let freq = pkg.meta.change_frequency as f64;

        let size_name;
        if size >= med_size_high_limit {
            size_name = "hs";
        } else if size <= med_size_low_limit {
            size_name = "ls";
        } else {
            size_name = "ms";
        }

        // Numbered to maintain order of partitions in a BTreeMap of hf, mf, lf
        let freq_name;
        if freq >= med_freq_high_limit {
            freq_name = "3hf";
        } else if freq <= med_freq_low_limit {
            freq_name = "5lf";
        } else {
            freq_name = "4mf";
        }

        let bucket = format!("{freq_name}_{size_name}");
        partitions
            .entry(bucket.to_string())
            .and_modify(|bin| bin.push(pkg))
            .or_insert_with(|| vec![pkg]);
    }

    for (name, pkgs) in &partitions {
        tracing::debug!("{:#?}: {:#?}", name, pkgs.len());
    }

    Some(partitions)
}

/// If the current rpm-ostree commit to be encapsulated is not the one in which packing structure changes, then
///  Flatten out prior_build_metadata to view all the packages in prior build as a single vec
///  Compare the flattened vector to components to see if pkgs added, updated,
///  removed or kept same
///  if pkgs added, then add them to the last bin of prior
///  if pkgs removed, then remove them from the prior[i]
///  iterate through prior[i] and make bins according to the name in nevra of pkgs to update
///  required packages
/// else if pkg structure to be changed || prior build not specified
///  Recompute optimal packaging structure (Compute partitions, place packages and optimize build)
fn basic_packing_with_prior_build<'a>(
    components: &'a [ObjectSourceMetaSized],
    bin_size: NonZeroU32,
    prior_build: &oci_spec::image::ImageManifest,
) -> Result<Vec<Vec<&'a ObjectSourceMetaSized>>> {
    let before_processing_pkgs_len = components.len();

    tracing::debug!("Keeping old package structure");

    // The first layer is the ostree commit, which will always be different for different builds,
    // so we ignore it.  For the remaining layers, extract the components/packages in each one.
    let curr_build: Result<Vec<Vec<String>>> = prior_build
        .layers()
        .iter()
        .skip(1)
        .map(|layer| -> Result<_> {
            let annotation_layer = layer
                .annotations()
                .as_ref()
                .and_then(|annos| annos.get(CONTENT_ANNOTATION))
                .ok_or_else(|| anyhow!("Missing {CONTENT_ANNOTATION} on prior build"))?;
            Ok(annotation_layer
                .split(COMPONENT_SEPARATOR)
                .map(ToOwned::to_owned)
                .collect())
        })
        .collect();
    let mut curr_build = curr_build?;

    // View the packages as unordered sets for lookups and differencing
    let prev_pkgs_set: BTreeSet<String> = curr_build
        .iter()
        .flat_map(|v| v.iter().cloned())
        .filter(|name| !name.is_empty())
        .collect();
    let curr_pkgs_set: BTreeSet<String> = components
        .iter()
        .map(|pkg| pkg.meta.name.to_string())
        .collect();

    // Added packages are included in the last bin which was reserved space.
    if let Some(last_bin) = curr_build.last_mut() {
        let added = curr_pkgs_set.difference(&prev_pkgs_set);
        last_bin.retain(|name| !name.is_empty());
        last_bin.extend(added.into_iter().cloned());
    } else {
        panic!("No empty last bin for added packages");
    }

    // Handle removed packages
    let removed: BTreeSet<&String> = prev_pkgs_set.difference(&curr_pkgs_set).collect();
    for bin in curr_build.iter_mut() {
        bin.retain(|pkg| !removed.contains(pkg));
    }

    // Handle updated packages
    let mut name_to_component: BTreeMap<String, &ObjectSourceMetaSized> = BTreeMap::new();
    for component in components.iter() {
        name_to_component
            .entry(component.meta.name.to_string())
            .or_insert(component);
    }
    let mut modified_build: Vec<Vec<&ObjectSourceMetaSized>> = Vec::new();
    for bin in curr_build {
        let mut mod_bin = Vec::new();
        for pkg in bin {
            // An empty component set can happen for the ostree commit layer; ignore that.
            if pkg.is_empty() {
                continue;
            }
            mod_bin.push(name_to_component[&pkg]);
        }
        modified_build.push(mod_bin);
    }

    // Verify all packages are included
    let after_processing_pkgs_len: usize = modified_build.iter().map(|b| b.len()).sum();
    assert_eq!(after_processing_pkgs_len, before_processing_pkgs_len);
    assert!(modified_build.len() <= bin_size.get() as usize);
    Ok(modified_build)
}

/// Given a set of components with size metadata (e.g. boxes of a certain size)
/// and a number of bins (possible container layers) to use, determine which components
/// go in which bin.  This algorithm is pretty simple:
/// Total available bins = n
///
/// 1 bin for all the u32_max frequency pkgs
/// 1 bin for all newly added pkgs
/// 1 bin for all low size pkgs
///
/// 60% of n-3 bins for high size pkgs
/// 40% of n-3 bins for medium size pkgs
///
/// If HS bins > limit, spillover to MS to package
/// If MS bins > limit, fold by merging 2 bins from the end
///
fn basic_packing<'a>(
    components: &'a [ObjectSourceMetaSized],
    bin_size: NonZeroU32,
    prior_build_metadata: Option<&oci_spec::image::ImageManifest>,
) -> Result<Vec<Vec<&'a ObjectSourceMetaSized>>> {
    const HIGH_SIZE_CUTOFF: f32 = 0.6;
    let before_processing_pkgs_len = components.len();

    anyhow::ensure!(bin_size.get() >= MIN_CHUNKED_LAYERS);

    // If we have a prior build, then use that
    if let Some(prior_build) = prior_build_metadata {
        return basic_packing_with_prior_build(components, bin_size, prior_build);
    }

    tracing::debug!("Creating new packing structure");

    // If there are fewer packages/components than there are bins, then we don't need to do
    // any "bin packing" at all; just assign a single component to each and we're done.
    if before_processing_pkgs_len < bin_size.get() as usize {
        let mut r = components.iter().map(|pkg| vec![pkg]).collect::<Vec<_>>();
        if before_processing_pkgs_len > 0 {
            let new_pkgs_bin: Vec<&ObjectSourceMetaSized> = Vec::new();
            r.push(new_pkgs_bin);
        }
        return Ok(r);
    }

    let mut r = Vec::new();
    // Split off the components which are "max frequency".
    let (components, max_freq_components) = components
        .iter()
        .partition::<Vec<_>, _>(|pkg| pkg.meta.change_frequency != u32::MAX);
    if !components.is_empty() {
        // Given a total number of bins (layers), compute how many should be assigned to our
        // partitioning based on size and frequency.
        let limit_ls_bins = 1usize;
        let limit_new_bins = 1usize;
        let _limit_new_pkgs = 0usize;
        let limit_max_frequency_pkgs = max_freq_components.len();
        let limit_max_frequency_bins = limit_max_frequency_pkgs.min(1);
        let low_and_other_bin_limit = limit_ls_bins + limit_new_bins + limit_max_frequency_bins;
        let limit_hs_bins = (HIGH_SIZE_CUTOFF
            * (bin_size.get() - low_and_other_bin_limit as u32) as f32)
            .floor() as usize;
        let limit_ms_bins =
            (bin_size.get() - (limit_hs_bins + low_and_other_bin_limit) as u32) as usize;
        let partitions = get_partitions_with_threshold(&components, limit_hs_bins, 2f64)
            .expect("Partitioning components into sets");

        // Compute how many low-sized package/components we have.
        let low_sized_component_count = partitions
            .get(LOW_PARTITION)
            .map(|p| p.len())
            .unwrap_or_default();

        // Approximate number of components we should have per medium-size bin.
        let pkg_per_bin_ms: usize = (components.len() - limit_hs_bins - low_sized_component_count)
            .checked_div(limit_ms_bins)
            .ok_or_else(|| anyhow::anyhow!("number of bins should be >= {}", MIN_CHUNKED_LAYERS))?;

        // Bins assignment
        for (partition, pkgs) in partitions.iter() {
            if partition == HIGH_PARTITION {
                for pkg in pkgs {
                    r.push(vec![*pkg]);
                }
            } else if partition == LOW_PARTITION {
                let mut bin: Vec<&ObjectSourceMetaSized> = Vec::new();
                for pkg in pkgs {
                    bin.push(*pkg);
                }
                r.push(bin);
            } else {
                let mut bin: Vec<&ObjectSourceMetaSized> = Vec::new();
                for (i, pkg) in pkgs.iter().enumerate() {
                    if bin.len() < pkg_per_bin_ms {
                        bin.push(*pkg);
                    } else {
                        r.push(bin.clone());
                        bin.clear();
                        bin.push(*pkg);
                    }
                    if i == pkgs.len() - 1 && !bin.is_empty() {
                        r.push(bin.clone());
                        bin.clear();
                    }
                }
            }
        }
        tracing::debug!("Bins before unoptimized build: {}", r.len());

        // Despite allocation certain number of pkgs per bin in medium-size partitions, the
        // hard limit of number of medium-size bins can be exceeded. This is because the pkg_per_bin_ms
        // is only upper limit and there is no lower limit. Thus, if a partition in medium-size has only 1 pkg
        // but pkg_per_bin_ms > 1, then the entire bin will have 1 pkg. This prevents partition
        // mixing.
        //
        // Addressing medium-size bins limit breach by mergin internal MS partitions
        // The partitions in medium-size are merged beginning from the end so to not mix high-frequency bins with low-frequency bins. The
        // bins are kept in this order: high-frequency, medium-frequency, low-frequency.
        while r.len() > (bin_size.get() as usize - limit_new_bins - limit_max_frequency_bins) {
            for i in (limit_ls_bins + limit_hs_bins..r.len() - 1)
                .step_by(2)
                .rev()
            {
                if r.len() <= (bin_size.get() as usize - limit_new_bins - limit_max_frequency_bins)
                {
                    break;
                }
                let prev = &r[i - 1];
                let curr = &r[i];
                let mut merge: Vec<&ObjectSourceMetaSized> = Vec::new();
                merge.extend(prev.iter());
                merge.extend(curr.iter());
                r.remove(i);
                r.remove(i - 1);
                r.insert(i, merge);
            }
        }
        tracing::debug!("Bins after optimization: {}", r.len());
    }

    if !max_freq_components.is_empty() {
        r.push(max_freq_components);
    }

    // Allocate an empty bin for new packages
    r.push(Vec::new());
    let after_processing_pkgs_len = r.iter().map(|b| b.len()).sum::<usize>();
    assert_eq!(after_processing_pkgs_len, before_processing_pkgs_len);
    assert!(r.len() <= bin_size.get() as usize);
    Ok(r)
}

#[cfg(test)]
mod test {
    use super::*;

    use oci_spec::image as oci_image;
    use std::str::FromStr;

    const FCOS_CONTENTMETA: &[u8] = include_bytes!("fixtures/fedora-coreos-contentmeta.json.gz");
    const SHA256_EXAMPLE: &str =
        "sha256:0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff";

    #[test]
    fn test_packing_basics() -> Result<()> {
        // null cases
        for v in [4, 7].map(|v| NonZeroU32::new(v).unwrap()) {
            assert_eq!(basic_packing(&[], v, None).unwrap().len(), 0);
        }
        Ok(())
    }

    #[test]
    fn test_packing_fcos() -> Result<()> {
        let contentmeta: Vec<ObjectSourceMetaSized> =
            serde_json::from_reader(flate2::read::GzDecoder::new(FCOS_CONTENTMETA))?;
        let total_size = contentmeta.iter().map(|v| v.size).sum::<u64>();

        let packing =
            basic_packing(&contentmeta, NonZeroU32::new(MAX_CHUNKS).unwrap(), None).unwrap();
        assert!(!contentmeta.is_empty());
        // We should fit into the assigned chunk size
        assert_eq!(packing.len() as u32, MAX_CHUNKS);
        // And verify that the sizes match
        let packed_total_size = packing_size(&packing);
        assert_eq!(total_size, packed_total_size);
        Ok(())
    }

    #[test]
    fn test_packing_one_layer() -> Result<()> {
        let contentmeta: Vec<ObjectSourceMetaSized> =
            serde_json::from_reader(flate2::read::GzDecoder::new(FCOS_CONTENTMETA))?;
        let r = basic_packing(&contentmeta, NonZeroU32::new(1).unwrap(), None);
        assert!(r.is_err());
        Ok(())
    }

    fn create_manifest(prev_expected_structure: Vec<Vec<&str>>) -> oci_spec::image::ImageManifest {
        use std::collections::HashMap;

        let mut p = prev_expected_structure
            .iter()
            .map(|b| {
                b.iter()
                    .map(|p| p.split('.').collect::<Vec<&str>>()[0].to_string())
                    .collect()
            })
            .collect();
        let mut metadata_with_ostree_commit = vec![vec![String::from("ostree_commit")]];
        metadata_with_ostree_commit.append(&mut p);

        let config = oci_spec::image::DescriptorBuilder::default()
            .media_type(oci_spec::image::MediaType::ImageConfig)
            .size(7023_u64)
            .digest(oci_image::Digest::from_str(SHA256_EXAMPLE).unwrap())
            .build()
            .expect("build config descriptor");

        let layers: Vec<oci_spec::image::Descriptor> = metadata_with_ostree_commit
            .iter()
            .map(|l| {
                let mut buf = [0; 8];
                let sep = COMPONENT_SEPARATOR.encode_utf8(&mut buf);
                oci_spec::image::DescriptorBuilder::default()
                    .media_type(oci_spec::image::MediaType::ImageLayerGzip)
                    .size(100_u64)
                    .digest(oci_image::Digest::from_str(SHA256_EXAMPLE).unwrap())
                    .annotations(HashMap::from([(
                        CONTENT_ANNOTATION.to_string(),
                        l.join(sep),
                    )]))
                    .build()
                    .expect("build layer")
            })
            .collect();

        oci_spec::image::ImageManifestBuilder::default()
            .schema_version(oci_spec::image::SCHEMA_VERSION)
            .config(config)
            .layers(layers)
            .build()
            .expect("build image manifest")
    }

    #[test]
    fn test_advanced_packing() -> Result<()> {
        // Step1 : Initial build (Packing structure computed)
        let contentmeta_v0: Vec<ObjectSourceMetaSized> = vec![
            vec![1, u32::MAX, 100000],
            vec![2, u32::MAX, 99999],
            vec![3, 30, 99998],
            vec![4, 100, 99997],
            vec![10, 51, 1000],
            vec![8, 50, 500],
            vec![9, 1, 200],
            vec![11, 100000, 199],
            vec![6, 30, 2],
            vec![7, 30, 1],
        ]
        .iter()
        .map(|data| ObjectSourceMetaSized {
            meta: ObjectSourceMeta {
                identifier: RcStr::from(format!("pkg{}.0", data[0])),
                name: RcStr::from(format!("pkg{}", data[0])),
                srcid: RcStr::from(format!("srcpkg{}", data[0])),
                change_time_offset: 0,
                change_frequency: data[1],
            },
            size: data[2] as u64,
        })
        .collect();

        let packing = basic_packing(
            &contentmeta_v0.as_slice(),
            NonZeroU32::new(6).unwrap(),
            None,
        )
        .unwrap();
        let structure: Vec<Vec<&str>> = packing
            .iter()
            .map(|bin| bin.iter().map(|pkg| &*pkg.meta.identifier).collect())
            .collect();
        let v0_expected_structure = vec![
            vec!["pkg3.0"],
            vec!["pkg4.0"],
            vec!["pkg6.0", "pkg7.0", "pkg11.0"],
            vec!["pkg9.0", "pkg8.0", "pkg10.0"],
            vec!["pkg1.0", "pkg2.0"],
            vec![],
        ];
        assert_eq!(structure, v0_expected_structure);

        // Step 2: Derive packing structure from last build

        let mut contentmeta_v1: Vec<ObjectSourceMetaSized> = contentmeta_v0;
        // Upgrade pkg1.0 to 1.1
        contentmeta_v1[0].meta.identifier = RcStr::from("pkg1.1");
        // Remove pkg7
        contentmeta_v1.remove(contentmeta_v1.len() - 1);
        // Add pkg5
        contentmeta_v1.push(ObjectSourceMetaSized {
            meta: ObjectSourceMeta {
                identifier: RcStr::from("pkg5.0"),
                name: RcStr::from("pkg5"),
                srcid: RcStr::from("srcpkg5"),
                change_time_offset: 0,
                change_frequency: 42,
            },
            size: 100000,
        });

        let image_manifest_v0 = create_manifest(v0_expected_structure);
        let packing_derived = basic_packing(
            &contentmeta_v1.as_slice(),
            NonZeroU32::new(6).unwrap(),
            Some(&image_manifest_v0),
        )
        .unwrap();
        let structure_derived: Vec<Vec<&str>> = packing_derived
            .iter()
            .map(|bin| bin.iter().map(|pkg| &*pkg.meta.identifier).collect())
            .collect();
        let v1_expected_structure = vec![
            vec!["pkg3.0"],
            vec!["pkg4.0"],
            vec!["pkg6.0", "pkg11.0"],
            vec!["pkg9.0", "pkg8.0", "pkg10.0"],
            vec!["pkg1.1", "pkg2.0"],
            vec!["pkg5.0"],
        ];

        assert_eq!(structure_derived, v1_expected_structure);

        // Step 3: Another update on derived where the pkg in the last bin updates

        let mut contentmeta_v2: Vec<ObjectSourceMetaSized> = contentmeta_v1;
        // Upgrade pkg5.0 to 5.1
        contentmeta_v2[9].meta.identifier = RcStr::from("pkg5.1");
        // Add pkg12
        contentmeta_v2.push(ObjectSourceMetaSized {
            meta: ObjectSourceMeta {
                identifier: RcStr::from("pkg12.0"),
                name: RcStr::from("pkg12"),
                srcid: RcStr::from("srcpkg12"),
                change_time_offset: 0,
                change_frequency: 42,
            },
            size: 100000,
        });

        let image_manifest_v1 = create_manifest(v1_expected_structure);
        let packing_derived = basic_packing(
            &contentmeta_v2.as_slice(),
            NonZeroU32::new(6).unwrap(),
            Some(&image_manifest_v1),
        )
        .unwrap();
        let structure_derived: Vec<Vec<&str>> = packing_derived
            .iter()
            .map(|bin| bin.iter().map(|pkg| &*pkg.meta.identifier).collect())
            .collect();
        let v2_expected_structure = vec![
            vec!["pkg3.0"],
            vec!["pkg4.0"],
            vec!["pkg6.0", "pkg11.0"],
            vec!["pkg9.0", "pkg8.0", "pkg10.0"],
            vec!["pkg1.1", "pkg2.0"],
            vec!["pkg5.1", "pkg12.0"],
        ];

        assert_eq!(structure_derived, v2_expected_structure);
        Ok(())
    }

    fn setup_exclusive_test(
        component_data: &[(u32, u32, u64)],
        max_layers: u32,
        num_fake_objects: Option<usize>,
    ) -> Result<(
        Vec<ObjectSourceMetaSized>,
        ObjectMetaSized,
        BTreeMap<ContentID, Vec<(Utf8PathBuf, String)>>,
        Chunking,
    )> {
        // Create content metadata from provided data
        let contentmeta: Vec<ObjectSourceMetaSized> = component_data
            .iter()
            .map(|&(id, freq, size)| ObjectSourceMetaSized {
                meta: ObjectSourceMeta {
                    identifier: RcStr::from(format!("pkg{id}.0")),
                    name: RcStr::from(format!("pkg{id}")),
                    srcid: RcStr::from(format!("srcpkg{id}")),
                    change_time_offset: 0,
                    change_frequency: freq,
                },
                size,
            })
            .collect();

        // Create object maps with fake checksums
        let mut object_map = IndexMap::new();

        for (i, component) in contentmeta.iter().enumerate() {
            let checksum = format!("checksum_{i}");
            object_map.insert(checksum, component.meta.identifier.clone());
        }

        let regular_meta = ObjectMetaSized {
            map: object_map,
            sizes: contentmeta.clone(),
        };

        // Create exclusive metadata (initially empty, to be populated by individual tests)
        let specific_contentmeta = BTreeMap::new();

        // Set up chunking with remainder chunk
        let mut chunking = Chunking::default();
        chunking.max = max_layers;
        chunking.remainder = Chunk::new("remainder");

        // Add fake objects to the remainder chunk if specified
        if let Some(num_objects) = num_fake_objects {
            for i in 0..num_objects {
                let checksum = format!("checksum_{i}");
                chunking.remainder.content.insert(
                    RcStr::from(checksum),
                    (
                        1000,
                        vec![Utf8PathBuf::from(format!("/path/to/checksum_{i}"))],
                    ),
                );
                chunking.remainder.size += 1000;
            }
        }

        Ok((contentmeta, regular_meta, specific_contentmeta, chunking))
    }

    #[test]
    fn test_exclusive_chunks() -> Result<()> {
        // Test that exclusive chunks are created first and get their own layers
        let component_data = [
            (1, 100, 50000),
            (2, 200, 40000),
            (3, 300, 30000),
            (4, 400, 20000),
            (5, 500, 10000),
        ];

        let (contentmeta, regular_meta, mut specific_contentmeta, mut chunking) =
            setup_exclusive_test(&component_data, 8, Some(5))?;

        // Create specific content metadata for pkg1 and pkg2
        specific_contentmeta.insert(
            contentmeta[0].meta.identifier.clone(),
            vec![(
                Utf8PathBuf::from("/path/to/checksum_0"),
                "checksum_0".to_string(),
            )],
        );
        specific_contentmeta.insert(
            contentmeta[1].meta.identifier.clone(),
            vec![(
                Utf8PathBuf::from("/path/to/checksum_1"),
                "checksum_1".to_string(),
            )],
        );

        chunking.process_mapping(
            &regular_meta,
            &Some(NonZeroU32::new(8).unwrap()),
            None,
            Some(&specific_contentmeta),
        )?;

        // Verify exclusive chunks are created first
        assert!(chunking.chunks.len() >= 2);
        assert_eq!(chunking.chunks[0].name, "pkg1.0");
        assert_eq!(chunking.chunks[1].name, "pkg2.0");
        assert_eq!(chunking.chunks[0].packages, vec!["pkg1.0".to_string()]);
        assert_eq!(chunking.chunks[1].packages, vec!["pkg2.0".to_string()]);

        Ok(())
    }

    #[test]
    fn test_exclusive_chunks_with_regular_packing() -> Result<()> {
        // Test that exclusive chunks are created first, then regular packing continues
        let component_data = [
            (1, 100, 50000), // exclusive
            (2, 200, 40000), // exclusive
            (3, 300, 30000), // regular
            (4, 400, 20000), // regular
            (5, 500, 10000), // regular
            (6, 600, 5000),  // regular
        ];

        let (contentmeta, regular_meta, mut specific_contentmeta, mut chunking) =
            setup_exclusive_test(&component_data, 8, Some(6))?;

        // Create specific content metadata for pkg1 and pkg2
        specific_contentmeta.insert(
            contentmeta[0].meta.identifier.clone(),
            vec![(
                Utf8PathBuf::from("/path/to/checksum_0"),
                "checksum_0".to_string(),
            )],
        );
        specific_contentmeta.insert(
            contentmeta[1].meta.identifier.clone(),
            vec![(
                Utf8PathBuf::from("/path/to/checksum_1"),
                "checksum_1".to_string(),
            )],
        );

        chunking.process_mapping(
            &regular_meta,
            &Some(NonZeroU32::new(8).unwrap()),
            None,
            Some(&specific_contentmeta),
        )?;

        // Verify exclusive chunks are created first
        assert!(chunking.chunks.len() >= 2);
        assert_eq!(chunking.chunks[0].name, "pkg1.0");
        assert_eq!(chunking.chunks[1].name, "pkg2.0");
        assert_eq!(chunking.chunks[0].packages, vec!["pkg1.0".to_string()]);
        assert_eq!(chunking.chunks[1].packages, vec!["pkg2.0".to_string()]);

        // Verify regular components are not in exclusive chunks
        for chunk in &chunking.chunks[2..] {
            assert!(!chunk.packages.contains(&"pkg1.0".to_string()));
            assert!(!chunk.packages.contains(&"pkg2.0".to_string()));
        }

        Ok(())
    }

    #[test]
    fn test_exclusive_chunks_isolation() -> Result<()> {
        // Test that exclusive chunks properly isolate components
        let component_data = [(1, 100, 50000), (2, 200, 40000), (3, 300, 30000)];

        let (contentmeta, regular_meta, mut specific_contentmeta, mut chunking) =
            setup_exclusive_test(&component_data, 8, Some(3))?;

        // Create specific content metadata for pkg1 only
        specific_contentmeta.insert(
            contentmeta[0].meta.identifier.clone(),
            vec![(
                Utf8PathBuf::from("/path/to/checksum_0"),
                "checksum_0".to_string(),
            )],
        );

        chunking.process_mapping(
            &regular_meta,
            &Some(NonZeroU32::new(8).unwrap()),
            None,
            Some(&specific_contentmeta),
        )?;

        // Verify pkg1 is in its own exclusive chunk
        assert!(!chunking.chunks.is_empty());
        assert_eq!(chunking.chunks[0].name, "pkg1.0");
        assert_eq!(chunking.chunks[0].packages, vec!["pkg1.0".to_string()]);

        // Verify pkg2 and pkg3 are in regular chunks, not mixed with pkg1
        let mut found_pkg2 = false;
        let mut found_pkg3 = false;
        for chunk in &chunking.chunks[1..] {
            if chunk.packages.contains(&"pkg2".to_string()) {
                found_pkg2 = true;
                assert!(!chunk.packages.contains(&"pkg1.0".to_string()));
            }
            if chunk.packages.contains(&"pkg3".to_string()) {
                found_pkg3 = true;
                assert!(!chunk.packages.contains(&"pkg1.0".to_string()));
            }
        }
        assert!(found_pkg2 && found_pkg3);

        Ok(())
    }

    #[test]
    fn test_process_mapping_specific_components_contain_correct_objects() -> Result<()> {
        // This test validates that specific components get their own dedicated layers
        // and that their objects are properly isolated from regular package layers

        // Setup: Create 5 packages
        // - pkg1, pkg2: Will be marked as "specific components" (get their own layers)
        // - pkg3, pkg4, pkg5: Regular packages (will be bin-packed together)
        let packages = [
            (1, 100, 50000), // pkg1 - SPECIFIC COMPONENT
            (2, 200, 40000), // pkg2 - SPECIFIC COMPONENT
            (3, 300, 30000), // pkg3 - regular package
            (4, 400, 20000), // pkg4 - regular package
            (5, 500, 10000), // pkg5 - regular package
        ];

        let (contentmeta, mut system_metadata, mut specific_contentmeta, mut chunking) =
            setup_exclusive_test(&packages, 8, None)?;

        // Create object mappings
        // - system_objects_map: Contains ALL objects in the system (both specific and regular)
        let mut system_objects_map = IndexMap::new();

        // SPECIFIC COMPONENT 1 (pkg1): owns 3 objects
        let pkg1_objects = ["checksum_1_a", "checksum_1_b", "checksum_1_c"];

        // SPECIFIC COMPONENT 2 (pkg2): owns 2 objects
        let pkg2_objects = ["checksum_2_a", "checksum_2_b"];

        // REGULAR PACKAGE 1 (pkg3): owns 2 objects
        let pkg3_objects = ["checksum_3_a", "checksum_3_b"];
        for obj in &pkg3_objects {
            system_objects_map.insert(obj.to_string(), contentmeta[2].meta.identifier.clone());
        }

        // REGULAR PACKAGE 2 (pkg4): owns 1 object
        let pkg4_objects = ["checksum_4_a"];
        for obj in &pkg4_objects {
            system_objects_map.insert(obj.to_string(), contentmeta[3].meta.identifier.clone());
        }

        // REGULAR PACKAGE 3 (pkg5): owns 3 objects
        let pkg5_objects = ["checksum_5_a", "checksum_5_b", "checksum_5_c"];
        for obj in &pkg5_objects {
            system_objects_map.insert(obj.to_string(), contentmeta[4].meta.identifier.clone());
        }

        // Set up metadata
        system_metadata.map = system_objects_map;

        // Create specific content metadata for pkg1 and pkg2
        specific_contentmeta.insert(
            contentmeta[0].meta.identifier.clone(),
            pkg1_objects
                .iter()
                .map(|obj| {
                    (
                        Utf8PathBuf::from(format!("/path/to/{obj}")),
                        obj.to_string(),
                    )
                })
                .collect(),
        );
        specific_contentmeta.insert(
            contentmeta[1].meta.identifier.clone(),
            pkg2_objects
                .iter()
                .map(|obj| {
                    (
                        Utf8PathBuf::from(format!("/path/to/{obj}")),
                        obj.to_string(),
                    )
                })
                .collect(),
        );

        // Initialize: Add ALL objects to the remainder chunk before processing
        // This includes both specific component objects and regular package objects
        // because process_mapping needs to move them from remainder to their final layers
        for (checksum, _) in &system_metadata.map {
            chunking.remainder.content.insert(
                RcStr::from(checksum.as_str()),
                (
                    1000,
                    vec![Utf8PathBuf::from(format!("/path/to/{checksum}"))],
                ),
            );
            chunking.remainder.size += 1000;
        }
        for paths in specific_contentmeta.values() {
            for (p, checksum) in paths {
                chunking
                    .remainder
                    .content
                    .insert(RcStr::from(checksum.as_str()), (1000, vec![p.clone()]));
            }
        }

        // Process the mapping
        // - system_metadata contains ALL objects in the system
        // - specific_contentmeta tells process_mapping which objects belong to specific components
        chunking.process_mapping(
            &system_metadata,
            &Some(NonZeroU32::new(8).unwrap()),
            None,
            Some(&specific_contentmeta),
        )?;

        // VALIDATION PART 1: Specific components get their own dedicated chunks
        assert!(
            chunking.chunks.len() >= 2,
            "Should have at least 2 chunks for specific components"
        );

        // Specific Component Layer 1: pkg1 only
        let specific_component_1_layer = &chunking.chunks[0];
        assert_eq!(specific_component_1_layer.name, "pkg1.0");
        assert_eq!(specific_component_1_layer.packages, vec!["pkg1.0"]);
        assert_eq!(specific_component_1_layer.content.len(), 3);
        for obj in &pkg1_objects {
            assert!(
                specific_component_1_layer.content.contains_key(*obj),
                "Specific component 1 layer should contain {obj}"
            );
        }

        // Specific Component Layer 2: pkg2 only
        let specific_component_2_layer = &chunking.chunks[1];
        assert_eq!(specific_component_2_layer.name, "pkg2.0");
        assert_eq!(specific_component_2_layer.packages, vec!["pkg2.0"]);
        assert_eq!(specific_component_2_layer.content.len(), 2);
        for obj in &pkg2_objects {
            assert!(
                specific_component_2_layer.content.contains_key(*obj),
                "Specific component 2 layer should contain {obj}"
            );
        }

        // VALIDATION PART 2: Specific component layers contain NO regular package objects
        for specific_layer in &chunking.chunks[0..2] {
            for obj in pkg3_objects
                .iter()
                .chain(&pkg4_objects)
                .chain(&pkg5_objects)
            {
                assert!(
                    !specific_layer.content.contains_key(*obj),
                    "Specific component layer '{}' should NOT contain regular package object {}",
                    specific_layer.name,
                    obj
                );
            }
        }

        // VALIDATION PART 3: Regular package layers contain NO specific component objects
        let regular_package_layers = &chunking.chunks[2..];
        for regular_layer in regular_package_layers {
            for obj in pkg1_objects.iter().chain(&pkg2_objects) {
                assert!(
                    !regular_layer.content.contains_key(*obj),
                    "Regular package layer should NOT contain specific component object {obj}"
                );
            }
        }

        // VALIDATION PART 4: All regular package objects are in some regular layer
        let mut found_regular_objects = BTreeSet::new();
        for regular_layer in regular_package_layers {
            for obj in regular_layer.content.keys() {
                found_regular_objects.insert(obj.as_ref());
            }
        }

        for obj in pkg3_objects
            .iter()
            .chain(&pkg4_objects)
            .chain(&pkg5_objects)
        {
            assert!(
                found_regular_objects.contains(*obj),
                "Regular package object {obj} should be in some regular layer"
            );
        }

        // VALIDATION PART 5: All objects moved from remainder
        assert_eq!(
            chunking.remainder.content.len(),
            0,
            "All objects should be moved from remainder"
        );
        assert_eq!(chunking.remainder.size, 0, "Remainder size should be 0");

        Ok(())
    }
}
