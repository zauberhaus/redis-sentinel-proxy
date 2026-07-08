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
BUILDER="${BUILDER:-$PRG-deploy}"

if [ -z "$VERSION" ] ; then
    VERSION=$(git describe --tags --always --dirty)
fi

# Rebuild the per-arch binaries Dockerfile.prod packages, restricted to the
# platforms this script deploys.
PLATFORM="$PLATFORM" VERSION="$VERSION" ./scripts/build_dist.sh

DOCKER_PLATFORMS=$(echo "$PLATFORM" | tr ' ' ',')

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
