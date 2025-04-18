#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Check IMSM Raid array health and bring up failed/missing disk members
#
# Copyright (C) 2025 Oracle Corporation
# Author: Richard Li <tianqi.li@oracle.com>

mdadm_output=$(/usr/sbin/mdadm --detail --scan --export)
export MDADM_INFO="$mdadm_output"

lines=$(echo "$MDADM_INFO" | grep '^MD_')

arrays=()
array_indexes=()
index=0
current=()

# Parse mdadm_output into arrays
while IFS= read -r line; do
    if [[ $line == MD_LEVEL=* ]]; then
        if [[ ${#current[@]} -gt 0 ]]; then
            arrays[index]="${current[*]}"
            array_indexes+=($index)
            current=()
            index=$((index + 1))
        fi
    fi
    current+=("$line")
done <<< "$lines"

if [[ ${#current[@]} -gt 0 ]]; then
    arrays[index]="${current[*]}"
    array_indexes+=($index)
fi

# Parse containers and map them to disks
container_names=()
container_disks=()

for i in "${array_indexes[@]}"; do
    IFS=' ' read -r -a props <<< "${arrays[$i]}"

    level=""
    devname=""
    disks=""

    for entry in "${props[@]}"; do
        key="${entry%%=*}"
        val="${entry#*=}"

        case "$key" in
            MD_LEVEL) level="$val" ;;
            MD_DEVNAME) devname="$val" ;;
            MD_DEVICE_dev*_DEV) disks+=" $val" ;;
        esac
    done

    if [[ "$level" == "container" && -n "$devname" ]]; then
        container_names+=("$devname")
        container_disks+=("${disks# }")
    fi
done

# Check and find missing disks of each container and their subarrays
containers_with_missing_disks_in_subarray=()
missing_disks_list=()

for i in "${array_indexes[@]}"; do
    IFS=' ' read -r -a props <<< "${arrays[$i]}"

    level=""
    container_path=""
    devname=""
    devices=""
    present=()

    for entry in "${props[@]}"; do
        key="${entry%%=*}"
        val="${entry#*=}"

        case "$key" in
            MD_LEVEL) level="$val" ;;
            MD_DEVNAME) devname="$val" ;;
            MD_DEVICES) devices="$val" ;;
            MD_CONTAINER) container_path="$val" ;;
            MD_DEVICE_dev*_DEV) present+=("$val") ;;
        esac
    done

    if [[ "$level" == "container" || -z "$devices" ]]; then
        continue
    fi

    present_count="${#present[@]}"
    if (( present_count < devices )); then
        container_name=$(basename "$container_path")
        # if MD_CONTAINER is empty, then it's a regular raid
        if [[ -z "$container_name" ]]; then
            continue
        fi

        container_real=$(realpath "$container_path")

        if [[ -z "$container_real" ]]; then
            continue
        fi

        # Find disks in container
        container_idx=-1
        for j in "${!container_names[@]}"; do
            if [[ "${container_names[$j]}" == "$container_name" ]]; then
                container_idx=$j
                break
            fi
        done

        if (( container_idx >= 0 )); then
            container_disk_line="${container_disks[$container_idx]}"
            container_missing=()

            for dev in $container_disk_line; do
                found=false
                for pd in "${present[@]}"; do
                    [[ "$pd" == "$dev" ]] && found=true && break
                done
                $found || container_missing+=("$dev")
            done

            if (( ${#container_missing[@]} > 0 )); then
                containers_with_missing_disks_in_subarray+=("$container_real")
                missing_disks_list+=("${container_missing[*]}")
            fi
        fi
    fi
done

# Perform a hot remove-and-re-add cycle to bring missing disks back
for idx in "${!containers_with_missing_disks_in_subarray[@]}"; do
    container="${containers_with_missing_disks_in_subarray[$idx]}"
    missing_disks="${missing_disks_list[$idx]}"

    for dev in $missing_disks; do
        id_path=$(udevadm info --query=property --name="$dev" | grep '^ID_PATH=' | cut -d= -f2)

        if [[ -z "$id_path" ]]; then
            continue
        fi

        /usr/sbin/mdadm -If "$dev" --path "$id_path"
        /usr/sbin/mdadm --add --run --export "$container" "$dev"
    done
done
