<script setup lang="ts">
import { toHexStringWithPrefix, toHexString } from '../utils/hex-string'

const props = defineProps<{
  value: Uint8Array,
  address: number,
}>()

function* getBytes() {
  let offset = 0
  while (offset < props.value.length) {
    yield {
      address: props.address + offset,
      bytes: props.value.subarray(offset, offset + 16),
    }
    offset += 16
  }
}

function* getHeaders() {
  for (let i = 0; i < 0x10; i++) {
    yield i
  }
}
</script>

<template>
  <div class="overflow-auto">
    <div class="pl-10ch sticky top-0 bg-inherit">
      <span
        v-for="i in getHeaders()"
        :key="i"
        class="ml-1ch whitespace-pre"
      >{{ i.toString(16).toUpperCase().padStart(2) }}</span>
    </div>
    <ol>
      <li
        v-for="(bytesLine, lineIndex) in getBytes()"
        :key="lineIndex"
      >
        <span class="mr-2 color-neutral-500">{{ toHexStringWithPrefix(bytesLine.address, 8) }}</span>
        <span class="inline-block mr-2">{{ toHexString(bytesLine.bytes) }}</span>
      </li>
    </ol>
  </div>
</template>
