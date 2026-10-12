#!/usr/bin/env bash
set -euo pipefail

CPU_LIMIT="${CPU_LIMIT:-1}"
MEMORY_LIMIT="${MEMORY_LIMIT:-512m}"
IMAGE_NAME="${IMAGE_NAME:-quanto-test}"

cd "$(dirname "$0")/.."

echo "building test image..."
docker build -f Dockerfile.test -t "${IMAGE_NAME}" .

echo "running tests with --cpus=${CPU_LIMIT} --memory=${MEMORY_LIMIT} (parallelism=1) ..."
docker run --rm \
  --cpus="${CPU_LIMIT}" \
  --memory="${MEMORY_LIMIT}" \
  "${IMAGE_NAME}" \
  go test -p 1 -v ./...

echo "tests completed"
