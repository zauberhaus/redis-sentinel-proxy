#!/bin/bash

set -eo pipefail

PRG=`git remote get-url origin | xargs basename -s .git`
PLATFORM="${PLATFORM:-linux/arm64 linux/amd64 darwin/amd64 darwin/arm64 linux/riscv64 linux/ppc64le}"
GO_IMAGE="${GO_IMAGE:-golang:1.26.5}"

DIFF=`git diff --stat`
NOW="`date +%Y-%m-%dT%T%z`"
COMMIT=`git rev-parse HEAD`

mkdir -p ./dist

CACHE_DIR="${CACHE_DIR:-$HOME/.cache/$PRG-build-dist}"
mkdir -p "$CACHE_DIR/gomodcache" "$CACHE_DIR/gocache"

if [ -z "$VERSION" ] ; then
    VERSION=$(git describe --tags --always --dirty)
fi

FLAGS="-X 'main.gitCommit=$COMMIT' -X 'main.buildTime=$NOW' -X 'main.treeState=$STATE' -X 'main.tag=$VERSION' -w -s -extldflags \"-static\""

BUILD_SCRIPT="git config --global --add safe.directory /src"$'\n'

for P in $PLATFORM ; do
    IFS='/' read -r -a parts <<< "$P"

    GOOS=${parts[0]}
    arch=${parts[1]}

    if expr "$arch" : "armv6$" 1>/dev/null; then
        GOARCH=arm
        GOARM=6
    elif expr "$arch" : "armv7$" 1>/dev/null; then
        GOARCH=arm
        GOARM=7
    else
        GOARCH=$arch
        GOARM=
    fi

    BUILD_SCRIPT+="echo 'Build $PRG-$GOOS-$arch $VERSION'"$'\n'
    BUILD_SCRIPT+="GOOS=$GOOS GOARCH=$GOARCH GOARM=$GOARM go build -tags prod -o ./dist/$PRG-$GOOS-$arch -ldflags \"$FLAGS\""$'\n'
done

docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e CGO_ENABLED=0 \
    -e HOME=/tmp \
    -e GOCACHE=/tmp/gocache \
    -e GOMODCACHE=/tmp/gomodcache \
    -v "$PWD":/src \
    -v "$CACHE_DIR/gomodcache":/tmp/gomodcache \
    -v "$CACHE_DIR/gocache":/tmp/gocache \
    -w /src \
    "$GO_IMAGE" \
    sh -c "$BUILD_SCRIPT"