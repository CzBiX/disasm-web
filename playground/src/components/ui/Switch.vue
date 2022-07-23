<script setup lang="ts">
import { useVModel } from '@vueuse/core'

const props = defineProps<{
  modelValue: boolean
  disabled: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void
}>()

const checked = useVModel(props, 'modelValue', emit)
</script>

<template>
  <input
    v-model="checked"
    :disabled="disabled"
    type="checkbox"
    class="
    appearance-none bg-sky-500 inline-block w-12 h-6 rounded-(l-4 r-4) flex
    after:(bg-current block mx-1 w-4 h-4 content-empty my-auto rounded-full flex-none)
    before:(content-empty block w-0 transition-width)
    checked-before:w-full"
  >
</template>
