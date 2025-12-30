#!/bin/bash
# Assumes that the current environment is a privileged container
# with the host mounted at /run/host.  We can basically write
# whatever we want, however we can't actually *reboot* the host.
set -euo pipefail

# https://github.com/ostreedev/ostree-rs-ext/issues/417
mkdir -p /var/tmp

sysroot=/run/host
repo="${sysroot}/ostree/repo"
# Current stable image fixture
image=quay.io/fedora/fedora-coreos:testing-devel
imgref=ostree-unverified-registry:${image}
stateroot=testos

# This image was generated manually; TODO auto-generate in quay.io/coreos-assembler or better start sigstore signing our production images
FIXTURE_SIGSTORE_SIGNED_FCOS_IMAGE=quay.io/rh_ee_rsaini/coreos

cd $(mktemp -d -p /var/tmp)

set -x

if test '!' -e "${sysroot}/ostree"; then
    ostree admin init-fs --modern "${sysroot}"
    ostree config --repo $sysroot/ostree/repo set sysroot.bootloader none
fi
if test '!' -d "${sysroot}/ostree/deploy/${stateroot}"; then
    ostree admin os-init "${stateroot}" --sysroot "${sysroot}"
fi
# Should be no images pruned
ostree container image prune-images --sysroot "${sysroot}"
# Test the syntax which uses full imgrefs.
ostree container image deploy --sysroot "${sysroot}" \
    --stateroot "${stateroot}" --imgref "${imgref}"
ostree admin --sysroot="${sysroot}" status
ostree container image metadata --repo "${sysroot}/ostree/repo" registry:"${image}" > manifest.json
jq '.schemaVersion' < manifest.json
ostree container image remove --repo "${sysroot}/ostree/repo" registry:"${image}"
ostree admin --sysroot="${sysroot}" undeploy 0
# Now test the new syntax which has a nicer --image that defaults to registry.
ostree container image deploy --transport registry --sysroot "${sysroot}" \
    --stateroot "${stateroot}" --image "${image}"
ostree admin --sysroot="${sysroot}" status
ostree admin --sysroot="${sysroot}" undeploy 0
if ostree container image deploy --transport registry --sysroot "${sysroot}" \
    --stateroot "${stateroot}" --image "${image}" --enforce-container-sigpolicy 2>err.txt; then
    echo "Deployment with enforced verification succeeded unexpectedly" 1>&2
    exit 1
fi
if ! grep -Ee 'insecureAcceptAnything.*refusing usage' err.txt; then
    echo "unexpected error" 1>&2
    cat err.txt
fi
# Now we should prune it
ostree container image prune-images --sysroot "${sysroot}"
ostree container image list --repo "${sysroot}/ostree/repo" > out.txt
test $(stat -c '%s' out.txt) = 0

for img in "${image}"; do
    ostree container image deploy --sysroot "${sysroot}" \
        --stateroot "${stateroot}" --imgref ostree-unverified-registry:"${img}"
    ostree admin --sysroot="${sysroot}" status
    initial_refs=$(ostree --repo="${sysroot}/ostree/repo" refs | wc -l)
    ostree container image remove --repo "${sysroot}/ostree/repo" registry:"${img}"
    pruned_refs=$(ostree --repo="${sysroot}/ostree/repo" refs | wc -l)
    # Removing the image should only drop the image reference, not its layers
    test "$(($initial_refs - 1))" = "$pruned_refs"
    ostree admin --sysroot="${sysroot}" undeploy 0
    # TODO: when we fold together ostree and ostree-ext, automatically prune layers
    n_commits=$(find ${sysroot}/ostree/repo -name '*.commit' | wc -l)
    test "${n_commits}" -gt 0
    # But right now this still doesn't prune *content*
    ostree container image prune-layers --repo="${sysroot}/ostree/repo"
    ostree --repo="${sysroot}/ostree/repo" refs > refs.txt
    if test "$(wc -l < refs.txt)" -ne 0; then
        echo "found refs"
        cat refs.txt
        exit 1
    fi
    # And this one should GC the objects too
    ostree container image prune-images --full --sysroot="${sysroot}" > out.txt
    n_commits=$(find ${sysroot}/ostree/repo -name '*.commit' | wc -l)
    test "${n_commits}" -eq 0
done

# Verify we have systemd journal messages
nsenter -m -t 1 journalctl _COMM=bootc > logs.txt
if ! grep 'layers already present: ' logs.txt; then
    cat logs.txt
    exit 1
fi

podman pull ${image}
ostree --repo="${sysroot}/ostree/repo" init --mode=bare-user
ostree container image pull ${sysroot}/ostree/repo ostree-unverified-image:containers-storage:${image}
echo "ok pulled from containers storage"

ostree container compare ${imgref} ${imgref} > compare.txt
grep "Removed layers: *0 *Size: 0 bytes" compare.txt
grep "Added layers: *0 *Size: 0 bytes" compare.txt

mkdir build
cd build
cat >Dockerfile << EOF
FROM ${image}
RUN touch /usr/share/somefile
EOF
systemd-run -dP --wait podman build -t localhost/fcos-derived .
derived_img=oci:/var/tmp/derived.oci
derived_img_dir=dir:/var/tmp/derived.dir
systemd-run -dP --wait skopeo copy containers-storage:localhost/fcos-derived "${derived_img}"
systemd-run -dP --wait skopeo copy "${derived_img}" "${derived_img_dir}"

images=$(ostree container image list --repo "${repo}" | wc -l)
test "${images}" -eq 1
ostree container image deploy --sysroot "${sysroot}" \
        --stateroot "${stateroot}" --imgref ostree-unverified-image:"${derived_img}"
imgref=$(ostree refs --repo=${repo} ostree/container/image | head -1)
img_commit=$(ostree --repo=${repo} rev-parse ostree/container/image/${imgref})
ostree container image remove --repo "${repo}" "${derived_img}"

ostree container image deploy --sysroot "${sysroot}" \
        --stateroot "${stateroot}" --imgref ostree-unverified-image:"${derived_img}"
img_commit2=$(ostree --repo=${repo} rev-parse ostree/container/image/${imgref})
test "${img_commit}" = "${img_commit2}"
echo "ok deploy derived container identical revs"

ostree container image deploy --sysroot "${sysroot}" \
        --stateroot "${stateroot}" --imgref ostree-unverified-image:"${derived_img_dir}"
echo "ok deploy derived container from local dir"
ostree container image remove --repo "${repo}" "${derived_img_dir}"
rm -rf /var/tmp/derived.dir

# Verify policy

mkdir -p /etc/pki/containers
#Ensure Wrong Public Key fails
cat > /etc/pki/containers/fcos.pub << EOF
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPw/TzXY5FQ00LT2orloOuAbqoOKv
relAN0my/O8tziGvc16PtEhF6A7Eun0/9//AMRZ8BwLn2cORZiQsGd5adA==
-----END PUBLIC KEY-----
EOF

cat > /etc/containers/registries.d/default.yaml << EOF
docker:
  ${FIXTURE_SIGSTORE_SIGNED_FCOS_IMAGE}:
    use-sigstore-attachments: true
EOF

cat > /etc/containers/policy.json << EOF
{
    "default": [
        {
            "type": "reject"
        }
    ],
    "transports": {
        "docker": {
            "quay.io/fedora/fedora-coreos": [
                {
                    "type": "insecureAcceptAnything"
                }
            ],
            "${FIXTURE_SIGSTORE_SIGNED_FCOS_IMAGE}": [
                {
                    "type": "sigstoreSigned",
                    "keyPath": "/etc/pki/containers/fcos.pub",
                    "signedIdentity": {
                        "type": "matchRepository"
                    }
                }
            ]

        }
    }
}
EOF

if ostree container image pull ${repo} ostree-image-signed:docker://${FIXTURE_SIGSTORE_SIGNED_FCOS_IMAGE} 2> error; then
  echo "unexpectedly pulled image" 1>&2
  exit 1
else
  grep -q "invalid signature" error
fi

#Ensure Correct Public Key succeeds
cat > /etc/pki/containers/fcos.pub << EOF
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEREpVb8t/Rp/78fawILAodC6EXGCG
rWNjJoPo7J99cBu5Ui4oCKD+hAHagop7GTi/G3UBP/dtduy2BVdICuBETQ==
-----END PUBLIC KEY-----
EOF
ostree container image pull ${repo} ostree-image-signed:docker://${FIXTURE_SIGSTORE_SIGNED_FCOS_IMAGE}
ostree container image history --repo ${repo} docker://${FIXTURE_SIGSTORE_SIGNED_FCOS_IMAGE}

echo ok privileged integration
