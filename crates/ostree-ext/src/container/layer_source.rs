//! Abstraction over where the bytes of the image layers come from.

use anyhow::Result;
use containers_image_proxy::oci_spec::image as oci_image;
use containers_image_proxy::{ConvertedLayerInfo, ImageProxy, OpenedImage, Transport};
use futures_util::future::BoxFuture;
use tokio::io::AsyncBufRead;
use tokio::sync::{OnceCell, watch::Sender};

use super::store::LayerProgress;
use super::unencapsulate::fetch_layer;

/// A layer opened for reading: its bytes, a driver future which must be polled
/// alongside reading them, and the media type of those bytes. The media type is
/// not necessarily the one in the layer descriptor, as some transports store
/// layers uncompressed regardless of what the manifest says.
pub type FetchedLayer<'a> = (
    Box<dyn AsyncBufRead + Send + Unpin>,
    BoxFuture<'a, Result<()>>,
    oci_image::MediaType,
);

/// Abstraction for layer blob data.
///
/// Typically ProxyLayerSource which pulls from a registry, but for deltas
/// we reconstruct data directly from the delta.
pub trait LayerSource: std::fmt::Debug + Send + Sync {
    /// Open one layer of `manifest` for reading.
    fn fetch_layer<'a>(
        &'a self,
        manifest: &'a oci_image::ImageManifest,
        layer: &'a oci_image::Descriptor,
        progress: Option<&'a Sender<Option<LayerProgress>>>,
    ) -> BoxFuture<'a, Result<FetchedLayer<'a>>>;

    /// Release the source, at most once and after the last
    /// [`Self::fetch_layer`].
    ///
    /// This is only reached when the import succeeds; an import that fails
    /// part way through drops the source instead. Anything that must be
    /// cleaned up either way belongs in a [`Drop`] impl.
    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<()>>;
}

/// Implementation of LayerSource via containers-image-proxy.
#[derive(Debug)]
pub(crate) struct ProxyLayerSource {
    proxy: ImageProxy,
    img: OpenedImage,
    transport: Transport,
    layer_info: OnceCell<Option<Vec<ConvertedLayerInfo>>>,
}

impl ProxyLayerSource {
    pub(crate) fn new(proxy: ImageProxy, img: OpenedImage, transport: Transport) -> Self {
        Self {
            proxy,
            img,
            transport,
            layer_info: OnceCell::new(),
        }
    }
}

impl LayerSource for ProxyLayerSource {
    fn fetch_layer<'a>(
        &'a self,
        manifest: &'a oci_image::ImageManifest,
        layer: &'a oci_image::Descriptor,
        progress: Option<&'a Sender<Option<LayerProgress>>>,
    ) -> BoxFuture<'a, Result<FetchedLayer<'a>>> {
        Box::pin(async move {
            let layer_info = self
                .layer_info
                .get_or_try_init(|| self.proxy.get_layer_info(&self.img))
                .await?;
            let (blob, driver, media_type) = fetch_layer(
                &self.proxy,
                &self.img,
                manifest,
                layer,
                progress,
                layer_info.as_ref(),
                self.transport,
            )
            .await?;
            Ok((blob, Box::pin(driver) as BoxFuture<'a, _>, media_type))
        })
    }

    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<()>> {
        Box::pin(async move {
            let Self { proxy, img, .. } = *self;
            // TODO change the imageproxy API to ensure this happens automatically when
            // the image reference is dropped
            proxy.close_image(&img).await?;
            proxy.finalize().await?;
            Ok(())
        })
    }
}
