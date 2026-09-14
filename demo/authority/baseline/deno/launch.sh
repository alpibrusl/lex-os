#!/usr/bin/env bash
# The launcher — the artifact that actually carries the authority.
#
# This is the file a reviewer would have to remember to open, and the
# file nothing forces them to update. It is unchanged between v1 and v2.
exec deno run \
  --allow-net=results.demo.internal \
  "$@"
