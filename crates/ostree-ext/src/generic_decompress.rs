//! This module primarily contains the `Decompressor` struct which is
//! used to decompress a stream based on its OCI media type.
//!
//! It also contains the `ReadWithGetInnerMut` trait and related
//! concrete implementations thereof.  These provide a means for each
//! specific decompressor to give mutable access to the inner reader.
//!
//! For example, the GzipDecompressor would give the underlying
//! compressed stream.
//!
//! We need a common way to access this stream so that we can flush
//! the data during cleanup.
//!
//! See: <https://github.com/bootc-dev/bootc/issues/1407>

use std::io::Read;

use crate::oci_spec::image as oci_image;

/// The legacy MIME type returned by the skopeo/(containers/storage) code
/// when we have local uncompressed docker-formatted image.
/// TODO: change the skopeo code to shield us from this correctly
const DOCKER_TYPE_LAYER_TAR: &str = "application/vnd.docker.image.rootfs.diff.tar";

/// Extends the `Read` trait with another method to get mutable access to the inner reader
trait ReadWithGetInnerMut: Read + Send + 'static {
    fn get_inner_mut(&mut self) -> &mut dyn Read;
}

// TransparentDecompressor

struct TransparentDecompressor<R: Read + Send + 'static>(R);

impl<R: Read + Send + 'static> Read for TransparentDecompressor<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl<R: Read + Send + 'static> ReadWithGetInnerMut for TransparentDecompressor<R> {
    fn get_inner_mut(&mut self) -> &mut dyn Read {
        &mut self.0
    }
}

// GzipDecompressor

struct GzipDecompressor<R: std::io::BufRead>(flate2::bufread::GzDecoder<R>);

impl<R: std::io::BufRead + Send + 'static> Read for GzipDecompressor<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl<R: std::io::BufRead + Send + 'static> ReadWithGetInnerMut for GzipDecompressor<R> {
    fn get_inner_mut(&mut self) -> &mut dyn Read {
        self.0.get_mut()
    }
}

// ZstdDecompressor

struct ZstdDecompressor<'a, R: std::io::BufRead>(zstd::stream::read::Decoder<'a, R>);

impl<'a: 'static, R: std::io::BufRead + Send + 'static> Read for ZstdDecompressor<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl<'a: 'static, R: std::io::BufRead + Send + 'static> ReadWithGetInnerMut
    for ZstdDecompressor<'a, R>
{
    fn get_inner_mut(&mut self) -> &mut dyn Read {
        self.0.get_mut()
    }
}

pub(crate) struct Decompressor {
    inner: Box<dyn ReadWithGetInnerMut>,
    finished: bool,
}

impl Read for Decompressor {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Drop for Decompressor {
    fn drop(&mut self) {
        if self.finished {
            return;
        }

        // Ideally we should not get here; users should call
        // `finish()` to clean up the stream.  But in reality there's
        // codepaths that can and will short-circuit error out while
        // processing the stream, and the Decompressor will get
        // dropped before it's finished in those cases.  We'll give
        // best-effort to clean things up nonetheless.  If things go
        // wrong, then panic, because we're in a bad state and it's
        // likely that we end up with a broken pipe error or a
        // deadlock.
        self._finish()
            .expect("Failed to flush pipe while dropping Decompressor")
    }
}

impl Decompressor {
    /// Create a decompressor for this MIME type, given a stream of input.
    pub(crate) fn new(
        media_type: &oci_image::MediaType,
        src: impl Read + Send + 'static,
    ) -> anyhow::Result<Self> {
        let r: Box<dyn ReadWithGetInnerMut> = match media_type {
            oci_image::MediaType::ImageLayerZstd => {
                Box::new(ZstdDecompressor(zstd::stream::read::Decoder::new(src)?))
            }
            oci_image::MediaType::ImageLayerGzip => Box::new(GzipDecompressor(
                flate2::bufread::GzDecoder::new(std::io::BufReader::new(src)),
            )),
            oci_image::MediaType::ImageLayer => Box::new(TransparentDecompressor(src)),
            oci_image::MediaType::Other(t) if t.as_str() == DOCKER_TYPE_LAYER_TAR => {
                Box::new(TransparentDecompressor(src))
            }
            o => anyhow::bail!("Unhandled layer type: {}", o),
        };
        Ok(Self {
            inner: r,
            finished: false,
        })
    }

    pub(crate) fn finish(mut self) -> anyhow::Result<()> {
        self._finish()
    }

    fn _finish(&mut self) -> anyhow::Result<()> {
        self.finished = true;

        // We need to make sure to flush out the decompressor and/or
        // tar stream here.  For tar, we might not read through the
        // entire stream, because the archive has zero-block-markers
        // at the end; or possibly because the final entry is filtered
        // in filter_tar so we don't advance to read the data.  For
        // decompressor, zstd:chunked layers will have
        // metadata/skippable frames at the end of the stream.  That
        // data isn't relevant to the tar stream, but if we don't read
        // it here then on the skopeo proxy we'll block trying to
        // write the end of the stream.  That in turn will block our
        // client end trying to call FinishPipe, and we end up
        // deadlocking ourselves through skopeo.
        //
        // https://github.com/bootc-dev/bootc/issues/1204

        let mut sink = std::io::sink();
        let n = std::io::copy(self.inner.get_inner_mut(), &mut sink)?;

        if n > 0 {
            tracing::debug!("Read extra {n} bytes at end of decompressor stream");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BrokenPipe;

    impl Read for BrokenPipe {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            std::io::Result::Err(std::io::ErrorKind::BrokenPipe.into())
        }
    }

    #[test]
    #[should_panic(expected = "Failed to flush pipe while dropping Decompressor")]
    fn test_drop_decompressor_with_finish_error_should_panic() {
        let broken = BrokenPipe;
        let d = Decompressor::new(&oci_image::MediaType::ImageLayer, broken).unwrap();
        drop(d)
    }

    #[test]
    fn test_drop_decompressor_with_successful_finish() {
        let empty = std::io::empty();
        let d = Decompressor::new(&oci_image::MediaType::ImageLayer, empty).unwrap();
        drop(d)
    }

    #[test]
    fn test_drop_decompressor_with_incomplete_gzip_data() {
        let empty = std::io::empty();
        let d = Decompressor::new(&oci_image::MediaType::ImageLayerGzip, empty).unwrap();
        drop(d)
    }

    #[test]
    fn test_drop_decompressor_with_incomplete_zstd_data() {
        let empty = std::io::empty();
        let d = Decompressor::new(&oci_image::MediaType::ImageLayerZstd, empty).unwrap();
        drop(d)
    }

    #[test]
    fn test_gzip_decompressor_with_garbage_input() {
        let garbage = b"This is not valid gzip data";
        let mut d = Decompressor::new(&oci_image::MediaType::ImageLayerGzip, &garbage[..]).unwrap();
        let mut buf = [0u8; 32];
        let e = d.read(&mut buf).unwrap_err();
        assert!(matches!(e.kind(), std::io::ErrorKind::InvalidInput));
        assert_eq!(e.to_string(), "invalid gzip header".to_string());
        drop(d)
    }

    #[test]
    fn test_zstd_decompressor_with_garbage_input() {
        let garbage = b"This is not valid zstd data";
        let mut d = Decompressor::new(&oci_image::MediaType::ImageLayerZstd, &garbage[..]).unwrap();
        let mut buf = [0u8; 32];
        let e = d.read(&mut buf).unwrap_err();
        assert!(matches!(e.kind(), std::io::ErrorKind::Other));
        assert_eq!(e.to_string(), "Unknown frame descriptor".to_string());
        drop(d)
    }
}
