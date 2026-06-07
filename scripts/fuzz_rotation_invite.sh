#!/usr/bin/env bash
# INVITE rotation: legacy -> ims_specific -> parser_breaker -> iphone_ims,
# 300 cases each, non-overlapping seeds, 100 rounds. See fuzz_rotation.sh.
exec "$(dirname "$0")/fuzz_rotation.sh" INVITE
