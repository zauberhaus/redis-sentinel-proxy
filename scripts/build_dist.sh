#!/bin/bash

set -eo pipefail

PRG=`git remote get-url origin | xargs basename -s .git`
PLATFORM="${PLATFORM:-linux/arm64 linux/amd64 darwin/amd64 darwin/arm64 linux/riscv64 linux/mips64le linux/ppc64le}"

DIFF=`git diff --stat`
NOW="`date +%Y-%m-%dT%T%z`"
COMMIT=`git rev-parse HEAD`

mkdir -p ./dist

if [ -z "$VERSION" ] ; then
    VERSION=$(git describe --tags --always --dirty)
fi 

FLAGS="-X 'main.gitCommit=$COMMIT' -X 'main.buildTime=$NOW' -X 'main.treeState=$STATE' -X 'main.tag=$VERSION' -w -s -extldflags \"-static\""
export CGO_ENABLED=0

for P in $PLATFORM ; do
    IFS='/' read -r -a parts <<< "$P"

    export GOOS=${parts[0]}
    export arch=${parts[1]}

    if expr "$arch" : "armv6$" 1>/dev/null; then
        export GOARCH=arm 
        export GOARM=6
    elif expr "$arch" : "armv7$" 1>/dev/null; then
        export GOARCH=arm
        export GOARM=7
    else 
        export GOARCH=$arch
    fi

    echo "Build $PRG-$GOOS-$arch $VERSION" 
    go build -tags prod -o ./dist/$PRG-$GOOS-$arch -ldflags "$FLAGS"
done