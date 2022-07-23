<script setup lang="ts">
import type { Insn } from 'capstone-wasm'
import { toHexStringWithPrefix, toHexString } from '../utils/hex-string'

defineProps<{
  value: Insn[]
}>()
</script>

<template>
  <div class="overflow-auto">
    <ol>
      <li
        v-for="(insn, index) of value"
        :key="index"
      >
        <span class="mr-2 color-neutral-500">{{ toHexStringWithPrefix(insn.address, 8) }}</span>
        <span class="inline-block w-11ch mr-2">{{ toHexString(insn.bytes) }}</span>
        <span class="color-sky-500">{{ insn.mnemonic }} {{ insn.opStr }}</span>
      </li>
    </ol>
  </div>
</template>
