#!/usr/bin/env bash

set -eu

EMSDK=~/emsdk
EMSCRIPTEN=$EMSDK/upstream/emscripten
GENERATED_DIR=$(realpath src/generated)
OUTPUT_NAME=capstone

ARCHS=(
  ARM
  ARM64
  X86
)

BUILD_FLAGS=(
  -D CAPSTONE_BUILD_TESTS=OFF
  -D CAPSTONE_BUILD_CSTOOL=OFF
 
  -D CAPSTONE_ARCHITECTURE_DEFAULT=OFF
  -D CAPSTONE_INSTALL=OFF
)

EXPORTED_FUNCTIONS=(
  free
  malloc

  cs_open
  cs_disasm
  cs_malloc
  cs_free
  cs_close
  cs_option
  cs_reg_name
  cs_op_count
  cs_op_index
  cs_insn_name
  cs_group_name
  cs_insn_group
  cs_reg_read
  cs_reg_write
  cs_errno
  cs_version
  cs_support
  cs_strerror
  cs_regs_access
)
EXPORTED_FUNCTIONS=$(echo -n "${EXPORTED_FUNCTIONS[*]}" | jq -cR 'split(" ") | map("_" + .)')

EMSCRIPTEN_SETTINGS=(
  -s MODULARIZE
  -s EXPORT_ES6
  -s WASM_BIGINT
  -s EXPORTED_FUNCTIONS=$EXPORTED_FUNCTIONS
  -s EXPORTED_RUNTIME_METHODS=ccall,cwrap,getValue,UTF8ToString
  -s INCOMING_MODULE_JS_API=[]
  -s EXPORT_NAME=$OUTPUT_NAME
  # -s ASSERTIONS
)

for ARCH in "${ARCHS[@]}"; do
  BUILD_FLAGS+=(
    -DCAPSTONE_${ARCH}_SUPPORT=ON
  )
done

cd native
$EMSCRIPTEN/emcmake cmake -B build ${BUILD_FLAGS[*]} -DCMAKE_BUILD_TYPE=Release

cd build
cmake --build . -j

$EMSCRIPTEN/emcc lib$OUTPUT_NAME.a -Os --minify 0 ${EMSCRIPTEN_SETTINGS[*]} -o $OUTPUT_NAME.mjs
cp $OUTPUT_NAME.mjs $OUTPUT_NAME.wasm $GENERATED_DIR

cd ../..
./generator.py const > "$GENERATED_DIR/const.ts"