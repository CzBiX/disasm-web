<script setup lang="ts">
/* eslint-disable no-bitwise */
import {
  Const as CapstoneConst, Capstone, loadCapstone, Insn,
} from 'capstone-wasm'
import {
  Const as KeystoneConst, Keystone, loadKeystone,
} from 'keystone-wasm'

import { onBeforeMount, ref, watch } from 'vue'
import { useLocalStorage, watchThrottled } from '@vueuse/core'
import { ArchMode, ExtraModeKey, Options } from './components/Toolbar.vue'
import Textarea from './components/Textarea.vue'
import { parseHexString, toHexString } from './utils/hex-string'
import DisasmResult from './components/DisasmResult.vue'
import AsmResult from './components/AsmResult.vue'
import ReloadPrompt from './components/ReloadPrompt.vue'

const DEFAULT_OPTIONS: Readonly<Options> = Object.freeze({
  archMode: {
    arch: 'x86',
    mode: '32',
  } as ArchMode,
  extraModes: [],
  address: 0x1000,
})

const options = useLocalStorage('options', {
  ...DEFAULT_OPTIONS,
})
const asmMode = ref(false)

let capstone: Capstone
let keystone: Keystone

const loaded = ref(false)
const content = useLocalStorage('content', '55 8b ec 83 c4 0c c3')
const statusStr = ref<string>('Loading engine...')

const disasmResult = ref<Insn[]>([])
const asmResult = ref<Uint8Array>(new Uint8Array())

function disasm() {
  const bytes = parseHexString(content.value)
  if (bytes.length === 0) {
    disasmResult.value = []
    return
  }

  try {
    disasmResult.value = capstone.disasm(bytes, {
      address: options.value.address,
    })
  } catch (e: any) {
    statusStr.value = e.message
  }
}

function asm() {
  if (content.value.length === 0) {
    asmResult.value = new Uint8Array()
    return
  }

  try {
    asmResult.value = keystone.asm(content.value, {
      address: options.value.address,
    })
  } catch (e: any) {
    statusStr.value = e.message
  }
}

function updateResult() {
  if (!loaded.value) {
    return
  }

  statusStr.value = ''
  if (asmMode.value) {
    asm()
  } else {
    disasm()
  }
}

interface EngineOptions {
  arch: number
  mode: number
}

function getCapstoneOptions({ archMode, extraModes }: Options): EngineOptions {
  const arch = {
    arm: CapstoneConst.CS_ARCH_ARM,
    arm64: CapstoneConst.CS_ARCH_ARM64,
    x86: CapstoneConst.CS_ARCH_X86,
  }[archMode.arch]
  let mode = {
    arm: CapstoneConst.CS_MODE_ARM,
    thumb: CapstoneConst.CS_MODE_THUMB,
    16: CapstoneConst.CS_MODE_16,
    32: CapstoneConst.CS_MODE_32,
    64: CapstoneConst.CS_MODE_64,
  }[archMode.mode]

  const extraModesMap: Record<ExtraModeKey, number> = {
    [ExtraModeKey.BIG_ENDIAN]: CapstoneConst.CS_MODE_BIG_ENDIAN,
    [ExtraModeKey.V8]: CapstoneConst.CS_MODE_V8,
  }
  extraModes.forEach((m) => {
    mode |= extraModesMap[m]
  })

  return {
    arch, mode,
  }
}

function getKeystoneOptions({ archMode, extraModes }: Options): EngineOptions {
  const arch = {
    arm: KeystoneConst.KS_ARCH_ARM,
    arm64: KeystoneConst.KS_ARCH_ARM64,
    x86: KeystoneConst.KS_ARCH_X86,
  }[archMode.arch]
  let mode = {
    arm: KeystoneConst.KS_MODE_ARM,
    thumb: KeystoneConst.KS_MODE_THUMB,
    16: KeystoneConst.KS_MODE_16,
    32: KeystoneConst.KS_MODE_32,
    64: KeystoneConst.KS_MODE_64,
  }[archMode.mode]
  if (arch === KeystoneConst.KS_ARCH_ARM64) {
    mode &= ~KeystoneConst.KS_MODE_ARM
  }

  const extraModesMap: Record<ExtraModeKey, number> = {
    [ExtraModeKey.BIG_ENDIAN]: KeystoneConst.KS_MODE_BIG_ENDIAN,
    [ExtraModeKey.V8]: KeystoneConst.KS_MODE_V8,
  }
  extraModes.forEach((m) => {
    mode |= extraModesMap[m]
  })

  return {
    arch, mode,
  }
}

function updateEngineOptions(
  engineType: 'capstone' | 'keystone',
  optionConvertor: (_: Options) => EngineOptions,
  newOptions: Options,
  oldOptions: Options,
) {
  const {
    arch: newArch,
    mode: newMode,
  } = optionConvertor(newOptions)
  const {
    arch: oldArch,
    mode: oldMode,
  } = optionConvertor(oldOptions)
  const engine = engineType === 'capstone' ? capstone : keystone

  if (newArch !== oldArch) {
    engine.close()
    if (engineType === 'capstone') {
      capstone = new Capstone(newArch, newMode)
    } else {
      keystone = new Keystone(newArch, newMode)
    }

    return
  }

  if (newMode !== oldMode) {
    if (engineType === 'keystone') {
      keystone.close()
      keystone = new Keystone(newArch, newMode)
      return
    }

    engine.setOption(CapstoneConst.CS_OPT_MODE, newMode)
  }
}

watch(options, (newOptions, oldOptions) => {
  updateEngineOptions('capstone', getCapstoneOptions, newOptions, oldOptions)
  updateEngineOptions('keystone', getKeystoneOptions, newOptions, oldOptions)

  updateResult()
})
watch(asmMode, (value) => {
  if (value) {
    content.value = disasmResult.value.map((insn) => `${insn.mnemonic} ${insn.opStr}`).join('\n')
  } else {
    content.value = toHexString(asmResult.value)
  }
})

watchThrottled(content, () => {
  updateResult()
}, {
  throttle: 200,
})

onBeforeMount(async () => {
  try {
    await Promise.all([
      loadCapstone(),
      loadKeystone(),
    ])
  } catch (e: any) {
    statusStr.value = e.message
    return
  }

  const capstoneOptions = getCapstoneOptions(options.value)
  capstone = new Capstone(capstoneOptions.arch, capstoneOptions.mode)

  const keystoneOptions = getKeystoneOptions(options.value)
  keystone = new Keystone(keystoneOptions.arch, keystoneOptions.mode)

  loaded.value = true
  statusStr.value = ''
  updateResult()
})
</script>

<template>
  <main class="flex flex-col h-screen">
    <Toolbar
      v-model="options"
      v-model:asm-mode="asmMode"
      :disabled="!loaded"
    />
    <div
      class="
    flex
    flex-1
    min-h-0
    bg-dark-300
    font-mono
    color-neutral-300
    children:(flex-1 border border-gray-500 p-2 bg-dark-100 m-2)"
    >
      <Textarea v-model="content" />

      <AsmResult
        v-if="asmMode"
        :address="options.address"
        :value="asmResult!"
      />
      <DisasmResult
        v-else
        :value="disasmResult"
      />
    </div>
    <div class="h-8 bg-dark-50 color-red px-2 flex items-center">
      {{ statusStr }}
    </div>
  </main>
  <ReloadPrompt />
</template>
