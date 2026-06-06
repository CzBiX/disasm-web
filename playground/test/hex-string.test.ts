import { describe, expect, it } from 'vitest'
import { toHexString, parseHexString, formatPretty } from '../src/utils/hex-string'

it('toHexString', () => {
  const bytes = new Uint8Array([0xef, 0x0f])
  const result = toHexString(bytes)
  expect(result).toBe('EF 0F')
})

describe('parseHexString', () => {
  it('plain', () => {
    const result = parseHexString('ef0f')
    expect(result).toEqual([0xef, 0x0f])
  })

  it('with spaces', () => {
    const result = parseHexString('ef 0f')
    expect(result).toEqual([0xef, 0x0f])
  })

  it('with comma', () => {
    const result = parseHexString('ef,0f')
    expect(result).toEqual([0xef, 0x0f])
  })

  it('with newline', () => {
    const result = parseHexString('ef\n0f')
    expect(result).toEqual([0xef, 0x0f])
  })

  it('with hex prefix', () => {
    const result = parseHexString('0xef 0x0f')
    expect(result).toEqual([0xef, 0x0f])
  })
})

describe('formatPretty', () => {
  it('aligns columns by longest hex', () => {
    const insns = [
      { address: 0x400000, bytes: new Uint8Array([0x55]), str: 'push rbp' },
      { address: 0x400001, bytes: new Uint8Array([0x48, 0x89, 0xe5]), str: 'mov rbp, rsp' },
      { address: 0x400004, bytes: new Uint8Array([0xc9]), str: 'leave' },
    ]
    const result = formatPretty(insns)
    expect(result).toBe([
      '0x00400000  55        push rbp',
      '0x00400001  48 89 E5  mov rbp, rsp',
      '0x00400004  C9        leave',
    ].join('\n'))
  })

  it('handles single instruction', () => {
    const insns = [
      { address: 0x0, bytes: new Uint8Array([0x90]), str: 'nop' },
    ]
    expect(formatPretty(insns)).toBe('0x00000000  90  nop')
  })

  it('aligns with long instructions (10 bytes)', () => {
    const insns = [
      { address: 0x400000, bytes: new Uint8Array([0x55]), str: 'push rbp' },
      { address: 0x400001, bytes: new Uint8Array([0x48, 0x89, 0xe5]), str: 'mov rbp, rsp' },
      { address: 0x400004, bytes: new Uint8Array([0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]), str: 'movabs rax, 0x7fffffffffffffff' },
      { address: 0x40000e, bytes: new Uint8Array([0xc3]), str: 'ret' },
    ]
    const result = formatPretty(insns)
    expect(result).toBe([
      '0x00400000  55                             push rbp',
      '0x00400001  48 89 E5                       mov rbp, rsp',
      '0x00400004  48 B8 FF FF FF FF FF FF FF 7F  movabs rax, 0x7fffffffffffffff',
      '0x0040000E  C3                             ret',
    ].join('\n'))
  })

  it('returns empty string for empty input', () => {
    expect(formatPretty([])).toBe('')
  })
})
