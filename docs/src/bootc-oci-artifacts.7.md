# How does the use of OCI artifacts intersect with this effort?

The "bootc compatible" images are OCI container images; they do not rely on the [OCI artifact specification](https://github.com/opencontainers/image-spec/blob/main/artifacts-guidance.md) or [OCI referrers API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#enabling-the-referrers-api).

It is foreseeable that users will need to produce "traditional" disk images (i.e. raw disk images, qcow2 disk images, Amazon AMIs, etc.) from the "bootc compatible" container images using additional tools. Therefore, it is reasonable that some users may want to encapsulate those disk images as an OCI artifact for storage and distribution. However, it is not a goal to use `bootc` to produce these "traditional" disk images nor to facilitate the encapsulation of those disk images as OCI artifacts.
