import { describe, expect, it } from 'vitest'
import { toHexString, parseHexString } from '../src/utils/hex-string'

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
