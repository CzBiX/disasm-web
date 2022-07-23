<script setup lang="ts">
import type { Insn } from 'capstone-wasm'
import { computed } from 'vue'
import { toHexStringWithPrefix, toHexString } from '../utils/hex-string'
import PanelToolbar from './ui/PanelToolbar.vue'

const props = defineProps<{
  value: Insn[]
}>()

function handleCopyHex() {
  const text = props.value.map((insn) => toHexString(insn.bytes)).join('\n')
  navigator.clipboard.writeText(text)
}

function convertInsnToStr(insn: Insn) {
  const { mnemonic, opStr } = insn
  if (opStr) {
    return `${mnemonic} ${opStr}`
  }

  return mnemonic
}

const asmContent = computed(() => props.value.map(convertInsnToStr).join('\n'))
defineExpose({
  asmContent,
})

function handleCopyASM() {
  navigator.clipboard.writeText(asmContent.value)
}
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
        <span class="color-sky-500">{{ convertInsnToStr(insn) }}</span>
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
