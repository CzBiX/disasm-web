<!-- eslint-disable no-bitwise -->
<script setup lang="ts">
import { computed } from 'vue'
import Switch from './ui/Switch.vue'

export type ArchMode = {
  arch: 'arm'
  mode: 'arm' | 'thumb'
} | {
  arch: 'arm64'
  mode: 'arm'
} | {
  arch: 'x86'
  mode: '16' | '32' | '64'
}

export interface Options {
  archMode: ArchMode
  extraModes: ExtraModeKey[]
  address: number
  asmMode: boolean
}

const props = defineProps<{
  modelValue: Options
  disabled: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: Options): void
}>()

const ALL_OPTIONS: {
  name: string
  arch: ArchMode['arch']
  defaultMode?: number
  modes:
  {
    name: string
    mode: ArchMode['mode']
  }[]
}[] = [
  {
    name: 'ARM',
    arch: 'arm',
    defaultMode: 1,
    modes: [
      {
        name: 'Thumb',
        mode: 'thumb',
      },
      {
        name: 'ARM',
        mode: 'arm',
      },
    ],
  },
  {
    name: 'ARM64',
    arch: 'arm64',
    modes: [
      {
        name: 'ARM',
        mode: 'arm',
      },
    ],
  },
  {
    name: 'x86',
    arch: 'x86',
    defaultMode: 1,
    modes: [
      {
        name: '16-bit',
        mode: '16',
      },
      {
        name: '32-bit',
        mode: '32',

      },
      {
        name: '64-bit',
        mode: '64',
      },
    ],
  },
]

const allowedExtraModes = computed(() => {
  const { archMode } = props.modelValue

  const modes = []
  switch (archMode.arch) {
    case 'arm':
      modes.push(ExtraModeKey.V8)
      modes.push(ExtraModeKey.BIG_ENDIAN)
      break
    case 'arm64':
    case 'x86':
      break
    default:
      break
  }

  return modes
})

function emitUpdate(value: Partial<Options>) {
  emit('update:modelValue', {
    ...props.modelValue,
    ...value,
  })
}

const asmMode = computed({
  get() {
    return props.modelValue.asmMode
  },
  set(v) {
    emitUpdate({ asmMode: v })
  },
})

function getSelectedArch(arch: string) {
  return ALL_OPTIONS.find((a) => a.arch === arch)!
}

function setArch(event: Event) {
  const arch = (event.target as HTMLSelectElement).value as ArchMode['arch']
  const targetArch = getSelectedArch(arch)
  const { mode } = targetArch.modes[targetArch.defaultMode || 0]
  const extraModes = allowedExtraModes.value.filter((m) => props.modelValue.extraModes.includes(m))

  emitUpdate({
    archMode: {
      arch,
      mode,
    } as ArchMode,
    extraModes,
  })
}

function getExtraMode(mode: ExtraModeKey) {
  return props.modelValue.extraModes.includes(mode)
}

function setExtraMode(mode: ExtraModeKey, value: boolean) {
  emitUpdate({
    extraModes: value ? [...props.modelValue.extraModes, mode] : props.modelValue.extraModes.filter((m) => m !== mode),
  })
}

function setMode(event: Event) {
  const mode = (event.target as HTMLSelectElement).value as ArchMode['mode']
  emitUpdate({
    archMode: {
      ...props.modelValue.archMode,
      mode,
    } as ArchMode,
  })
}

function setAddress(event: Event) {
  // eslint-disable-next-line radix
  const address = parseInt((event.target as HTMLInputElement).value)
  emitUpdate({
    address: Number.isNaN(address) ? 0x1000 : address,
  })
}

function formatHex(n: number) {
  return `0x${n.toString(16)}`
}
</script>

<script lang="ts">
export enum ExtraModeKey {
  BIG_ENDIAN = 'big-endian',
  V8 = 'v8',
}

const EXTRA_MODES = [
  {
    key: ExtraModeKey.BIG_ENDIAN,
    name: 'Big Endian',
  },
  {
    key: ExtraModeKey.V8,
    name: 'V8',
  },
]
</script>

<template>
  <div class="bg-dark-50 flex items-center p-4 gap-4 text-white">
    <h1 class="text-xl">
      Disasm Playground
    </h1>
    <div class="flex gap-4 all-[input]:bg-dark-300 all-[select]:bg-dark-300 all-[select]:w-24">
      <label class="flex items-center">
        Disasm
        <Switch
          v-model="asmMode"
          class="mx-2"
          :disabled="disabled"
        />
        Asm
      </label>
      <label>
        Arch:
        <select
          :value="modelValue.archMode.arch"
          :disabled="disabled"
          @input="setArch"
        >
          <option
            v-for="arch in ALL_OPTIONS"
            :key="arch.arch"
            :value="arch.arch"
          >
            {{ arch.name }}
          </option>
        </select>
      </label>
      <label>
        Mode:
        <select
          :value="modelValue.archMode.mode"
          :disabled="disabled"
          @input="setMode"
        >
          <option
            v-for="mode in getSelectedArch(modelValue.archMode.arch).modes"
            :key="mode.mode"
            :value="mode.mode"
          >
            {{ mode.name }}
          </option>
        </select>
      </label>
      <label>
        Address:
        <input
          :disabled="disabled"
          :value="formatHex(modelValue.address)"
          class="w-12ch text-right"
          @change="setAddress"
        >
      </label>
      <template
        v-for="extraMode in EXTRA_MODES"
        :key="extraMode.key"
      >
        <label v-if="allowedExtraModes.includes(extraMode.key)">
          <input
            type="checkbox"
            :disabled="disabled"
            :value="getExtraMode(extraMode.key)"
            @input="setExtraMode(extraMode.key, ($event.target as HTMLInputElement).checked)"
          >
          {{ extraMode.name }}
        </label>
      </template>
    </div>
    <div class="ml-auto flex">
      <a
        href="https://github.com/CzBiX/disasm-web"
        target="_blank"
        class="p-3 i-carbon:logo-github"
      >
        GitHub
      </a>
    </div>
  </div>
</template>
