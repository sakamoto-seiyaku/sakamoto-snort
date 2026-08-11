#!/usr/bin/env bash

# Shared helpers for S61 protocol-identification probes. These helpers only
# write generated throwaway probe files under the caller-provided build root.

protocol_identification_probe_source_tree_sha256() {
    local search_root="$1"
    (
        cd -- "$search_root"
        find . -type f -print0 | sort -z | xargs -0 -r sha256sum
    ) | sha256sum | awk '{print $1}'
}

protocol_identification_probe_count_matching_sources() {
    local search_root="$1"
    local pattern="$2"
    find "$search_root" -type f -path "$pattern" | wc -l | tr -d ' '
}

protocol_identification_probe_write_vpp_utils_shim() {
    local generated_include_dir="$1"
    mkdir -p "$generated_include_dir/vlib/utils"
    cat >"$generated_include_dir/vlib/utils/utils.h" <<'H'
#pragma once

#include <stdlib.h>

#ifndef ALLOC
#define ALLOC(type, number) ((type *) calloc((number), sizeof(type)))
#endif

#ifndef FREE
#define FREE(p)                                                               \
    do                                                                        \
    {                                                                         \
        if ((p) != NULL)                                                       \
        {                                                                     \
            free((void *)(p));                                                 \
            (p) = NULL;                                                        \
        }                                                                     \
    } while (0)
#endif
H
}
