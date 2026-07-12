#!/bin/bash

set -eo pipefail

PROJECT=`git remote get-url origin | sed -E 's#\.git$##' | sed -E 's#.*[:/]([^/]+/[^/]+)$#\1#'`
PRG=`basename "$PROJECT"`
IMAGE="${IMAGE:-$PROJECT}"
REPO="${REPO:-""}"

if [ "$REPO" != "" ] ; then
    IMAGE="$REPO/$IMAGE"
fi


# Docker images only run linux, so darwin is dropped from build_dist.sh's
# platform list; mips64le is also dropped since the alpine base image (used
# by Dockerfile.prod) has no linux/mips64le variant.
PLATFORM="${PLATFORM:-linux/amd64 linux/arm64 linux/ppc64le linux/riscv64}"
PUSH="${PUSH:-true}"
SIGN=${SIGN:-"true"}
COSIGN_KEY=${COSIGN_KEY:-"./cosign.key"}
BUILDER="${BUILDER:-$PRG-deploy}"

if [ -z "$VERSION" ] ; then
    VERSION=$(git describe --tags --always --dirty)
fi

# Rebuild the per-arch binaries Dockerfile.prod packages, restricted to the
# platforms this script deploys.
PLATFORM="$PLATFORM" VERSION="$VERSION" ./scripts/build_dist.sh

DOCKER_PLATFORMS=$(echo "$PLATFORM" | tr ' ' ',')

# Ask for the cosign key password up front (skipped if COSIGN_PASSWORD is
# already set), so the build doesn't stall on a prompt at the end.
if [[ "${PUSH}" == "true" && "${SIGN}" == "true" ]]; then
    if [[ -z "${COSIGN_PASSWORD:-}" ]]; then
        read -r -s -p "Password for ${COSIGN_KEY}: " COSIGN_PASSWORD
        echo
        export COSIGN_PASSWORD
    fi
    # Verify the password by decrypting the key before the (long) build.
    if ! cosign public-key --key "${COSIGN_KEY}" >/dev/null 2>&1; then
        echo "ERROR: cannot decrypt ${COSIGN_KEY} - wrong password?" >&2
        exit 1
    fi
fi

if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
    docker buildx create --name "$BUILDER" --use
else
    docker buildx use "$BUILDER"
fi

ARGS=(--platform "$DOCKER_PLATFORMS" -f Dockerfile.prod -t "$IMAGE:$VERSION")

# Only float :latest for a clean, tagged build so a dev/dirty build never
# clobbers it.
case "$VERSION" in
    *-dirty) ;;
    *) ARGS+=(-t "$IMAGE:latest") ;;
esac

if [ "$PUSH" = "true" ] ; then
    ARGS+=(--push)
else
    ARGS+=(--output type=cacheonly)
fi

echo "Deploying $IMAGE:$VERSION for $DOCKER_PLATFORMS"
docker buildx build "${ARGS[@]}" .

if [[ "${PUSH}" == "true" && "${SIGN}" == "true" ]]; then
    DIGEST=$(docker buildx imagetools inspect "${IMAGE}" --format '{{.Manifest.Digest}}')
    echo "Signing ${IMAGE}@${DIGEST}"
    cosign sign --yes --recursive --key "${COSIGN_KEY}" "${IMAGE}@${DIGEST}"
fi
