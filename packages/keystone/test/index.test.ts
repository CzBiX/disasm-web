import {
  it, vi, expect, describe, afterEach,
} from 'vitest'
import { readFile } from 'fs/promises'
import { loadKeystone, Keystone, Const } from '../src/index'

function mockNodeFetch() {
  vi.stubGlobal('fetch', async (url: string) => {
    if (!url.startsWith('file://')) {
      throw new Error(`Unsupported url: ${url}`)
    }

    const content = await readFile(url.substring(7))
    return new Response(content, {
      headers: {
        'Content-Type': 'application/wasm',
      },
    })
  })
}
mockNodeFetch()

await loadKeystone()

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
    const data = `push ebp
mov ebp, esp
add esp, 0xc
ret`

    it('normal', () => {
      createKeystone()

      expect(keystone.asm(data)).toEqual(Uint8Array.from([
        0x55, 0x89, 0xe5, 0x83, 0xc4, 0x0c, 0xc3,
      ]))
    })

    it('arm', () => {
      // eslint-disable-next-line @typescript-eslint/no-shadow
      const data = `mov r0, #3
str r1, [r0]`

      createKeystone(Const.KS_ARCH_ARM, Const.KS_MODE_ARM)

      expect(keystone.asm(data)).toEqual(Uint8Array.from([
        0x03, 0x00, 0xa0, 0xe3, 0x00, 0x10, 0x80, 0xe5,
      ]))
    })
  })
})
