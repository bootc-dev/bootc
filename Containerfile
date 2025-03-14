FROM quay.io/centos/centos:stream9 as build
COPY hack/build.sh /build.sh
COPY ./contrib/packaging/bootc.spec ./contrib/packaging/bootc.spec
RUN /build.sh && rm -v /build.sh
COPY . /build
WORKDIR /build
RUN mkdir -p /build/target/dev-rootfs  # This can hold arbitrary extra content
# See https://www.reddit.com/r/rust/comments/126xeyx/exploring_the_problem_of_faster_cargo_docker/
# We aren't using the full recommendations there, just the simple bits.
RUN --mount=type=cache,target=/build/target --mount=type=cache,target=/var/roothome make test-bin-archive && mkdir -p /out && cp target/bootc.tar /out
RUN mkdir -p /build/target/dev-rootfs  # This can hold arbitrary extra content

FROM quay.io/otuchfel/bootc:seed2 as seed

# ____________________________________________________________________________

FROM quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:5b1124faf4b73753b4679085604dd8cb810c4a7a2e659978f5c80183bb165f94

LABEL com.openshift.lifecycle-agent.seed_format_version=4

RUN mkdir -p /usr/lib/bootc/install

COPY --from=seed --exclude=ostree.tgz / /usr/lib/openshift/seed

COPY --from=build /out/bootc.tar /tmp

COPY baseimage/base/usr/lib/ostree/prepare-root.conf /usr/lib/ostree/prepare-root.conf

RUN tar -C / -xvf /tmp/bootc.tar && rm -vrf /tmp/*
RUN sed -i '/PermitRootLogin no/d' /etc/ssh/sshd_config.d/40-rhcos-defaults.conf
