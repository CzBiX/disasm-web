import {
  it, expect, describe, afterEach,
} from 'vitest'
import { readFile } from 'fs/promises'
import { loadCapstone, Capstone, Const } from '../src/index'

await loadCapstone({
  wasmBinary: await readFile('./dist/capstone.wasm'),
})

it('version', () => {
  expect(Capstone.version()).toEqual({
    major: Const.CS_API_MAJOR,
    minor: Const.CS_API_MINOR,
  })
})

it('support', () => {
  expect(Capstone.support(Const.CS_ARCH_X86)).toBeTruthy()

  expect(Capstone.support(Const.CS_ARCH_MAX)).toBeFalsy()
})

it('strError', () => {
  expect(Capstone.strError(Const.CS_ERR_MEM)).toMatchInlineSnapshot('"Out of memory (CS_ERR_MEM)"')
})

describe('class', () => {
  let capstone: Capstone
  function createCapstone(arch = Const.CS_ARCH_X86, mode = Const.CS_MODE_32) {
    capstone = new Capstone(arch, mode)
  }
  afterEach(() => {
    if (capstone) {
      capstone.close()
      capstone = null as any
    }
  })

  it('success', () => {
    createCapstone()
  })

  it('setOption', () => {
    createCapstone()
    expect(capstone.setOption(Const.CS_OPT_DETAIL, Const.CS_OPT_ON)).toBe(Const.CS_ERR_OK)
  })

  describe('disasm', () => {
    const data = [0x55, 0x8b, 0xec, 0x83, 0xc4, 0x0c, 0xc3]

    it('normal', () => {
      createCapstone()

      expect(capstone.disasm(data)).toMatchObject([
        {
          mnemonic: 'push',
          opStr: 'ebp',
        },
        {
          mnemonic: 'mov',
          opStr: 'ebp, esp',
        },
        {
          mnemonic: 'add',
          opStr: 'esp, 0xc',
        },
        {
          mnemonic: 'ret',
        },
      ])
    })

    it('arm', () => {
      // eslint-disable-next-line @typescript-eslint/no-shadow
      const data = [0x03, 0x00, 0xa0, 0xe3, 0x00, 0x10, 0x80, 0xe5]
      createCapstone(Const.CS_ARCH_ARM, Const.CS_MODE_ARM)

      expect(capstone.disasm(data)).toMatchObject([
        {
          mnemonic: 'mov',
          opStr: 'r0, #3',
        },
        {
          mnemonic: 'str',
          opStr: 'r1, [r0]',
        },
      ])
    })

    it('address argument', () => {
      createCapstone()

      const address = 0x1000
      const insnList = capstone.disasm(data, {
        address,
      })
      expect(insnList[0]).toMatchObject({
        address,
      })
    })

    it('64bit address argument', () => {
      createCapstone()

      const address = 0x4_1234_1234
      const insnList = capstone.disasm(data, {
        address,
      })
      expect(insnList[0]).toMatchObject({
        address,
      })
    })

    it('count argument', () => {
      createCapstone()

      const count = 1
      const insnList = capstone.disasm(data, {
        count,
      })
      expect(insnList).toHaveLength(count)
    })
  })
})
