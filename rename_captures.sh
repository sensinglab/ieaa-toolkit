#!/usr/bin/env bash
set -euo pipefail

folder="/home/kali/Detection_Testing/Data"

for file in "$folder"/*.pcap; do
    [[ -f "$file" ]] || continue

    filename=$(basename "$file")

    # Extract prefix before the first '-20'
    prefix="${filename%%-20*}"
    # Remove the 'Capture' part
    prefix="${prefix#Capture}"

    # Remove the extension '.pcap'
    channel="${filename%.pcap}"
    # Remove everything left of the last '-'
    channel="${channel##*-}"

    # Build new name
    new_name="${prefix}-${channel}.pcap"

    mv -i "$file" "$folder/$new_name"
done
