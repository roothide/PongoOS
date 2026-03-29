#! /bin/sh
set -e
set -x

basepath=$(dirname "$0")

make -C "$basepath" all
make -C "$basepath"/checkra1n/kpf-test all

rm -f "$basepath"/../kernels/arm64/*.patched

find "$basepath"/../kernels/arm64 -type f -not -name '.*' -print0 | while IFS= read -r -d '' file; do
    if ! "$basepath"/checkra1n/kpf-test/kpf-test.macos "$file"; then
        echo "*** Failed to handle kernel file: $file"
        exit 1
    fi
done

rm -f "$basepath"/../kernels/arm64/*.patched

echo "**************** all done **************"

