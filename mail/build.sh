#!/usr/bin/env sh
# Copyright (c) Privasys. All rights reserved.
# Licensed under the GNU Affero General Public License v3.0.
#
# Builds the measured image with the manifest read from its one source.
#
# Never `docker build` this directory directly: the tool catalogue reaches the
# control plane as an image LABEL, and pasting a second copy of it into the
# Dockerfile is how a catalogue starts advertising tools the service does not
# serve.
set -eu

IMAGE="${IMAGE:-ghcr.io/privasys/mail-connector}"
TAG="${TAG:-dev}"

cd "$(dirname "$0")"

# Fail before building rather than shipping an image whose catalogue is broken.
if ! command -v jq >/dev/null 2>&1; then
  MANIFEST=$(tr -d '\n\r' < privasys.json)
else
  MANIFEST=$(jq -c . privasys.json)
fi
case "$MANIFEST" in
  '{'*'}') ;;
  *) echo "privasys.json is not a JSON object" >&2; exit 1 ;;
esac

echo "building $IMAGE:$TAG"
docker build \
  --build-arg "MANIFEST=$MANIFEST" \
  -t "$IMAGE:$TAG" \
  "$@" \
  .

echo
echo "digest:"
docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE:$TAG" 2>/dev/null || \
  echo "  (not pushed yet; the digest that matters is the one the registry returns)"
