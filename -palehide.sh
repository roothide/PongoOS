#! /bin/sh
set -e
set -x

basepath=$(dirname "$0")
~/Documents/iostools/palera1n-macos-universal --boot-args "xargs -v serial=3" -l $1 -k "$basepath"/build/Pongo.bin -K "$basepath"/build/checkra1n-kpf-pongo -o "$basepath"/../palehide-jbinit/.theos/_/usr/local/bin/jbinit

if [ "$1" = "-P" ]; then
    "$basepath"/scripts/pongoterm
fi
