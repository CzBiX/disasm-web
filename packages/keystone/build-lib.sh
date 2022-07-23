#!/usr/bin/env bash

set -eu

EMSDK=~/emsdk
EMSCRIPTEN=$EMSDK/upstream/emscripten
GENERATED_DIR=$(realpath src/generated)
OUTPUT_NAME=keystone

ARCHS=(
  AArch64
  ARM
  X86
)

BUILD_FLAGS=(
  -D BUILD_LIBS_ONLY=ON
 
  -D LLVM_TARGETS_TO_BUILD=$(IFS=';'; echo "${ARCHS[*]}")
)

EXPORTED_FUNCTIONS=(
  free
  malloc

  ks_open
  ks_asm
  ks_free
  ks_close
  ks_option
  ks_errno
  ks_version
  ks_arch_supported
  ks_strerror
)
EXPORTED_FUNCTIONS=$(echo -n "${EXPORTED_FUNCTIONS[*]}" | jq -cR 'split(" ") | map("_" + .)')

EMSCRIPTEN_SETTINGS=(
  -s MODULARIZE
  -s EXPORT_ES6
  # -s WASM_BIGINT
  -s EXPORTED_FUNCTIONS=$EXPORTED_FUNCTIONS
  -s EXPORTED_RUNTIME_METHODS=ccall,cwrap,getValue,UTF8ToString
  -s EXPORT_NAME=$OUTPUT_NAME
  -s ENVIRONMENT=web,node
  # -s ASSERTIONS
)

cd native
$EMSCRIPTEN/emcmake cmake -B build ${BUILD_FLAGS[*]} -DCMAKE_BUILD_TYPE=Release

cd build
cmake --build . -j --target $OUTPUT_NAME

$EMSCRIPTEN/emcc llvm/lib/lib$OUTPUT_NAME.a -Os --minify 0 ${EMSCRIPTEN_SETTINGS[*]} -o $OUTPUT_NAME.mjs
cp $OUTPUT_NAME.mjs $OUTPUT_NAME.wasm $GENERATED_DIR

cd ../..
./generator.py const > "$GENERATED_DIR/const.ts"