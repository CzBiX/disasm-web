<script setup lang="ts">
import { computed } from 'vue'
import { toHexStringWithPrefix, toHexString } from '../utils/hex-string'
import PanelToolbar from './ui/PanelToolbar.vue'
import type { Insn } from '../types'

const props = defineProps<{
  value: Insn[]
}>()

const hexContent = computed(() => props.value.map((insn) => toHexString(insn.bytes)).join('\n'))
const asmContent = computed(() => props.value.map((insn) => insn.str).join('\n'))

function handleCopyHex() {
  navigator.clipboard.writeText(hexContent.value)
}

function handleCopyASM() {
  navigator.clipboard.writeText(asmContent.value)
}

defineExpose({
  asmContent,
  hexContent,
})
</script>

<template>
  <div class="overflow-auto relative">
    <ol class="children:flex">
      <li
        v-for="(insn, index) of value"
        :key="index"
      >
        <span class="mr-2 color-neutral-500">{{ toHexStringWithPrefix(insn.address, 8) }}</span>
        <span class="inline-block w-11ch mr-2">{{ toHexString(insn.bytes) }}</span>
        <span class="color-sky-500">{{ insn.str }}</span>
      </li>
    </ol>
    <PanelToolbar>
      <button
        class="i-carbon:data-blob"
        title="Copy Hex"
        @click="handleCopyHex"
      />
      <button
        class="i-carbon:copy"
        title="Copy ASM"
        @click="handleCopyASM"
      />
    </PanelToolbar>
  </div>
</template>
