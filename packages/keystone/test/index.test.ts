import {
  it, expect, describe, afterEach,
} from 'vitest'
import { readFile } from 'fs/promises'
import { loadKeystone, Keystone, Const } from '../src/index'

await loadKeystone({
  wasmBinary: await readFile('./dist/keystone.wasm'),
})

it('version', () => {
  expect(Keystone.version()).toEqual({
    major: Const.KS_API_MAJOR,
    minor: Const.KS_API_MINOR,
  })
})

it('support', () => {
  expect(Keystone.archSupported(Const.KS_ARCH_X86)).toBeTruthy()

  expect(Keystone.archSupported(Const.KS_ARCH_MAX)).toBeFalsy()
})

it('strError', () => {
  expect(Keystone.strError(Const.KS_ERR_NOMEM)).toMatchInlineSnapshot('"No memory available or memory not present (KS_ERR_NOMEM)"')
})

describe('class', () => {
  let keystone: Keystone
  function createKeystone(arch = Const.KS_ARCH_X86, mode = Const.KS_MODE_32) {
    keystone = new Keystone(arch, mode)
  }
  afterEach(() => {
    if (keystone) {
      keystone.close()
      keystone = null as any
    }
  })

  it('success', () => {
    createKeystone()
  })

  describe('asm', () => {
    it('normal', () => {
      const data = `push ebp
mov ebp, esp
add esp, 0xc
ret`

      createKeystone()

      expect(keystone.asm(data)).toEqual(Uint8Array.from([
        0x55, 0x89, 0xe5, 0x83, 0xc4, 0x0c, 0xc3,
      ]))
    })

    it('address', () => {
      const address = 0x1000
      const data = 'jmp 0x2000'

      createKeystone()

      expect(keystone.asm(data, { address })).toEqual(Uint8Array.from([
        0xE9, 0xFB, 0x0F, 0x00, 0x00,
      ]))
    })

    it('64bit address', () => {
      const address = 0x4_1234_1234
      const data = 'jmp 0x412342234'

      createKeystone(Const.KS_ARCH_X86, Const.KS_MODE_64)

      expect(keystone.asm(data, { address })).toEqual(Uint8Array.from([
        0xE9, 0xFB, 0x0F, 0x00, 0x00,
      ]))
    })

    it('arm', () => {
      const data = `mov r0, #3
str r1, [r0]`

      createKeystone(Const.KS_ARCH_ARM, Const.KS_MODE_ARM)

      expect(keystone.asm(data)).toEqual(Uint8Array.from([
        0x03, 0x00, 0xa0, 0xe3, 0x00, 0x10, 0x80, 0xe5,
      ]))
    })
  })
})
