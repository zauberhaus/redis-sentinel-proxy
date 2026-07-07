#!/bin/bash

set -eo pipefail

PRG=`git remote get-url origin | xargs basename -s .git`
PLATFORM="${PLATFORM:-linux/arm64 linux/amd64 darwin/amd64 darwin/arm64 linux/riscv64 linux/mips64le linux/ppc64le}"

DIFF=`git diff --stat`
NOW="`date +%Y-%m-%dT%T%z`"
COMMIT=`git rev-parse HEAD`

if [ -z "$VERSION" ] ; then
    VERSION=$(git describe --tags --always --dirty)
fi 

FLAGS="-X 'main.gitCommit=$COMMIT' -X 'main.buildTime=$NOW' -X 'main.treeState=$STATE' -X 'main.tag=$VERSION' -w -s -extldflags \"-static\""
export CGO_ENABLED=0

echo "Build $PRG $VERSION" 
go build -tags prod -ldflags "$FLAGS"

