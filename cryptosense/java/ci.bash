#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

main() {
    echo "Project id is set to $CS_PROJECT_ID.";
    echo "Profile ID is set to $CS_PROFILE_ID.";
    echo "Root URL is set to '$CS_ROOT_URL'";
    
    local time=$(date --utc +"%H:%M:%S")
    local trace_name="java_${GITHUB_RUN_ID}_${time}.cst"
    echo "Appending the traces."
    find -name '*.cst.gz' | xargs zcat -f >> $trace_name
    gzip "$trace_name"
    echo "Done."
    
    python3 cryptosense/upload.py "${trace_name}.gz" "$CS_PROJECT_ID" "$CS_PROFILE_ID"
}

main
