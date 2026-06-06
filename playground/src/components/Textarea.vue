<script setup lang="ts">
import { useVModel } from '@vueuse/core'

const props = defineProps<{
  modelValue: string;
}>()
const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void;
}>()

const content = useVModel(props, 'modelValue', emit)
</script>

<template>
  <textarea
    v-model="content"
    class="resize-none overflow-hidden min-h-full"
    style="field-sizing: content"
    spellcheck="false"
  />
</template>
