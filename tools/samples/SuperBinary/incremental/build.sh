#!/bin/bash
set -e
cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )

if [ ! -f intermediate_update.bin ]; then
    echo "The 'intermediate_update.bin' file does not exists."
    echo "Prepare application intermediate version as described"
    echo "in the documentation."
    exit 1
fi

if [ ! -f ../../../../samples/simple/build/zephyr/app_update.bin ]; then
    echo "The '../../../../samples/simple/build/zephyr/app_update.bin' file"
    echo "does not exists. Prepare an application image as described"
    echo "in the documentation."
    exit 1
fi

mkdir -p build
cp intermediate_update.bin build/
cp ../../../../samples/simple/build/zephyr/app_update.bin build/

python3 ../../../ncsfmntools SuperBinary    \
	SuperBinary.plist                   \
	--out-plist build/SuperBinary.plist \
	--out-uarp build/SuperBinary.uarp   \
	--metadata build/MetaData.plist     \
	--payloads-dir build                \
	--release-notes ../ReleaseNotes

