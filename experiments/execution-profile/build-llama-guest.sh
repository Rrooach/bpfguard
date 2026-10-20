#!/usr/bin/env bash
set -euo pipefail
cd /opt/profile-validation/inference
printf '%s  %s\n' \
  21e88c79dbbec249a91b093b56f375a3248a9bbe80c5fb19d42c0849f148aa66 llama-b4514.tar.gz \
  66967fbece6dbe97886593fdbb73589584927e29119ec31f08090732d1861739 stories15M-q4_0.gguf | sha256sum -c
PROFILE_LLAMA_SOURCE=llama.cpp-ec7f3ac9ab33e46b136eb5ab6a76c4d81f57c7f1
if [[ -e "$PROFILE_LLAMA_SOURCE" || -e build ]]; then
  printf 'Fresh build directories are required.\n' >&2
  exit 1
fi
tar -xzf llama-b4514.tar.gz
patch --batch -p1 -d "$PROFILE_LLAMA_SOURCE" < llama-runtime-hooks.patch
cp native_events.hpp "$PROFILE_LLAMA_SOURCE/examples/server/native_events.hpp"
cmake -S "$PROFILE_LLAMA_SOURCE" -B build \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
  -DGGML_CUDA=OFF -DGGML_VULKAN=OFF -DGGML_BLAS=OFF -DGGML_OPENMP=OFF \
  -DGGML_NATIVE=OFF -DLLAMA_CURL=OFF -DLLAMA_BUILD_TESTS=OFF \
  -DLLAMA_BUILD_EXAMPLES=ON -DLLAMA_BUILD_SERVER=ON
cmake --build build --target llama-server -j4
sha256sum build/bin/llama-server llama-b4514.tar.gz stories15M-q4_0.gguf llama-runtime-hooks.patch native_events.hpp
build/bin/llama-server --version
