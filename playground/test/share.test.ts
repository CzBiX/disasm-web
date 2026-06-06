import { describe, expect, it } from 'vitest'
import { encodeShareState, decodeShareState } from '../src/utils/share'
import type { Options } from '../src/components/Toolbar.vue'

const defaultOptions: Options = {
  archMode: { arch: 'x86', mode: '32' },
  extraModes: [],
  address: 0x400000,
  asmMode: true,
}

describe('encodeShareState + decodeShareState', () => {
  it('round-trips default options', () => {
    const content = 'push ebp\nnop\nret'
    const hash = encodeShareState(defaultOptions, content)
    const result = decodeShareState(hash)

    expect(result).not.toBeNull()
    expect(result!.options).toEqual(defaultOptions)
    expect(result!.content).toBe(content)
  })

  it('round-trips ARM with extra modes', () => {
    const options: Options = {
      archMode: { arch: 'arm', mode: 'thumb' },
      extraModes: ['big-endian', 'v8'],
      address: 0x1000,
      asmMode: false,
    }
    const content = 'mov r0, #1'
    const hash = encodeShareState(options, content)
    const result = decodeShareState(hash)

    expect(result).not.toBeNull()
    expect(result!.options).toEqual(options)
    expect(result!.content).toBe(content)
  })

  it('handles multiline content', () => {
    const content = 'push ebp\nmov ebp, esp\nsub esp, 0x10\nret'
    const hash = encodeShareState(defaultOptions, content)
    const result = decodeShareState(hash)

    expect(result!.content).toBe(content)
  })

  it('handles empty content', () => {
    const hash = encodeShareState(defaultOptions, '')
    const result = decodeShareState(hash)

    expect(result!.content).toBe('')
  })
})

describe('decodeShareState', () => {
  it('returns null for empty string', () => {
    expect(decodeShareState('')).toBeNull()
  })

  it('returns null for invalid base64', () => {
    expect(decodeShareState('!!!invalid!!!')).toBeNull()
  })

  it('returns null for valid base64 but not JSON', () => {
    const hash = btoa('not json')
    expect(decodeShareState(hash)).toBeNull()
  })

  it('returns null for JSON missing required fields', () => {
    const hash = btoa(JSON.stringify({ x: 1 }))
    expect(decodeShareState(hash)).toBeNull()
  })

  it('returns null for invalid arch', () => {
    const hash = btoa(JSON.stringify({ a: 'mips', m: '32', c: 'nop' }))
    expect(decodeShareState(hash)).toBeNull()
  })

  it('returns null for invalid mode', () => {
    const hash = btoa(JSON.stringify({ a: 'x86', m: '128', c: 'nop' }))
    expect(decodeShareState(hash)).toBeNull()
  })

  it('applies defaults for missing optional fields', () => {
    const hash = btoa(JSON.stringify({ a: 'x86', m: '64', c: 'nop' }))
    const result = decodeShareState(hash)

    expect(result).not.toBeNull()
    expect(result!.options.extraModes).toEqual([])
    expect(result!.options.address).toBe(0x400000)
    expect(result!.options.asmMode).toBe(true)
  })
})
