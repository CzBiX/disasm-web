<script setup lang="ts">
import { computed } from 'vue'
import { toHexStringWithPrefix, toHexString } from '../utils/hex-string'
import PanelToolbar from './ui/PanelToolbar.vue'

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

const hexContent = computed(() => [...getBytes()].map((bytes) => toHexString(bytes.bytes)).join('\n'))

function handleCopyHex() {
  navigator.clipboard.writeText(hexContent.value)
}

defineExpose({
  hexContent,
})
</script>

<template>
  <div class="overflow-auto relative">
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
    <PanelToolbar>
      <button
        class="i-carbon:copy"
        title="Copy Hex"
        @click="handleCopyHex"
      />
    </PanelToolbar>
  </div>
</template>
