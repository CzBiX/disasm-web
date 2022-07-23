export function parseHexString(hexString: string) {
  const result: number[] = []
  const reHex = /(?:0x)?([\da-f]{2})/sig

  while (true) {
    const m = reHex.exec(hexString)
    if (m) {
      result.push(parseInt(m[1], 16))
    } else {
      break
    }
  }

  return result
}

export function toHexString(bytes: Uint8Array): string {
  const result: string[] = []
  bytes.forEach((byte, index) => {
    if (index > 0 && index % 16 === 0) {
      result.push('\n')
    }
    result.push(byte.toString(16).toUpperCase().padStart(2, '0'))
  })

  return result.join(' ')
}

export function toHexStringWithPrefix(n: number, length = 0): string {
  const result = n.toString(16).toUpperCase().padStart(length, '0')
  return `0x${result}`
}
