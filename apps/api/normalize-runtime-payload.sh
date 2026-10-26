#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
    echo "usage: normalize-runtime-payload.sh RUNTIME_ROOT" >&2
    exit 64
fi

runtime_root=$1
for payload in kodesec_api advisor_connector static; do
    payload_root=$runtime_root/$payload
    if [ ! -d "$payload_root" ]; then
        echo "missing runtime payload directory: $payload_root" >&2
        exit 66
    fi
    if find "$payload_root" -type l -print -quit | grep -q .; then
        echo "runtime payload must not contain symbolic links: $payload_root" >&2
        exit 65
    fi
done

for payload in kodesec_api advisor_connector static; do
    payload_root=$runtime_root/$payload
    find "$payload_root" -type d -exec chmod 0555 {} +
    find "$payload_root" -type f -exec chmod 0444 {} +
done
