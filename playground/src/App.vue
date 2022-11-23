<script setup lang="ts">
/* eslint-disable no-bitwise */
import {
  Const as CapstoneConst, Capstone, loadCapstone,
} from 'capstone-wasm'
import {
  Const as KeystoneConst, Keystone, loadKeystone,
} from 'keystone-wasm'

import { onBeforeMount, ref, watch } from 'vue'
import { useLocalStorage, watchThrottled } from '@vueuse/core'
import { ArchMode, ExtraModeKey, Options } from './components/Toolbar.vue'
import Textarea from './components/Textarea.vue'
import { parseHexString } from './utils/hex-string'
import DisasmResult from './components/DisasmResult.vue'
import ReloadPrompt from './components/ReloadPrompt.vue'
import type { Insn } from './types'

const DEFAULT_OPTIONS: Readonly<Options> = Object.freeze({
  archMode: {
    arch: 'x86',
    mode: '32',
  } as ArchMode,
  extraModes: [],
  address: 0x1000,
  asmMode: false,
})

const options = useLocalStorage('options', {
  ...DEFAULT_OPTIONS,
})

let capstone: Capstone
let keystone: Keystone

const loaded = ref(false)
const content = useLocalStorage('content', '55 8b ec 83 c4 0c c3')
const statusStr = ref<string>('Loading engine...')

const disasmResult = ref<Insn[]>([])
const disasmPanel = ref<typeof DisasmResult>()

function convertInsnToStr(mnemonic: string, opStr: string) {
  if (opStr) {
    return `${mnemonic} ${opStr}`
  }

  return mnemonic
}

function disasm() {
  const bytes = parseHexString(content.value)
  if (bytes.length === 0) {
    disasmResult.value = []
    return
  }

  try {
    disasmResult.value = capstone.disasm(bytes, {
      address: options.value.address,
    }).map((insn) => ({
      address: insn.address,
      bytes: insn.bytes,
      str: convertInsnToStr(insn.mnemonic, insn.opStr),
    }))
  } catch (e: any) {
    statusStr.value = e.message
  }
}

function asm() {
  if (content.value.length === 0) {
    disasmResult.value = []
    return
  }

  let offset = 0
  const lines = content.value.split('\n')
  const insns: Insn[] = Array(lines.length)

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    try {
      const { address } = options.value
      const bytes = keystone.asm(line, {
        address: address + offset,
      })

      insns[i] = {
        address: address + offset,
        bytes,
        str: line,
      }
      offset += bytes.length
    } catch (e: any) {
      statusStr.value = `Line ${i + 1}: ${e.message}`
      insns.splice(i)
      break
    }
  }

  disasmResult.value = insns
}

function updateResult() {
  if (!loaded.value) {
    return
  }

  statusStr.value = ''
  if (options.value.asmMode) {
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

  if (newOptions.asmMode !== oldOptions.asmMode) {
    content.value = newOptions.asmMode ? disasmPanel.value!.asmContent : disasmPanel.value!.hexContent
  } else {
    updateResult()
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

      <DisasmResult
        ref="disasmPanel"
        :value="disasmResult"
      />
    </div>
    <div class="h-8 bg-dark-50 color-red px-2 flex items-center">
      {{ statusStr }}
    </div>
  </main>
  <ReloadPrompt />
</template>
