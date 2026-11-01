#!/usr/bin/env bash
# Rename the Go module path before the first push.
#
#   hack/rename-module.sh github.com/<owner>/acra
#
# Updates go.mod and every Go import, then tidies and builds.
set -euo pipefail

NEW="${1:?usage: hack/rename-module.sh github.com/<owner>/<repo>}"
OLD="github.com/acra-project/acra"
cd "$(dirname "$0")/.."

# Replace the module path in all Go files and go.mod (perl -i is Mac/Linux-portable).
find . -name '*.go' -not -path './.git/*' -exec perl -i -pe "s|\Q${OLD}\E|${NEW}|g" {} +
perl -i -pe "s|\Q${OLD}\E|${NEW}|g" go.mod
# Drop the now-stale placeholder note on line 1 of go.mod, if present.
perl -i -ne 'print unless $. == 1 && /placeholder/' go.mod

go mod tidy
go build ./...
echo "module renamed: ${OLD} -> ${NEW}"
