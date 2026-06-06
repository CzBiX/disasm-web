import type { ArchMode, Options } from '../components/Toolbar.vue'

interface SharePayload {
  a: string
  m: string
  e?: string[]
  d?: number
  s?: boolean
  c: string
}

const VALID_ARCHS = new Set(['arm', 'arm64', 'x86'])
const VALID_MODES = new Set(['arm', 'thumb', '16', '32', '64'])

export function encodeShareState(options: Options, content: string): string {
  const payload: SharePayload = {
    a: options.archMode.arch,
    m: options.archMode.mode,
    e: options.extraModes.length > 0 ? options.extraModes : undefined,
    d: options.address !== 0x400000 ? options.address : undefined,
    s: options.asmMode ? undefined : false,
    c: content,
  }

  const json = JSON.stringify(payload)
  const bytes = new TextEncoder().encode(json)
  const base64 = btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(''))

  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function decodeShareState(hash: string): { options: Options; content: string } | null {
  if (!hash) return null

  try {
    const base64 = hash.replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
    const decoded = atob(padded)
    const bytes = Uint8Array.from(decoded, (c) => c.charCodeAt(0))
    const json = new TextDecoder().decode(bytes)
    const payload: SharePayload = JSON.parse(json)

    if (!VALID_ARCHS.has(payload.a) || !VALID_MODES.has(payload.m) || typeof payload.c !== 'string') {
      return null
    }

    return {
      options: {
        archMode: { arch: payload.a, mode: payload.m } as ArchMode,
        extraModes: payload.e ?? [],
        address: payload.d ?? 0x400000,
        asmMode: payload.s ?? true,
      },
      content: payload.c,
    }
  } catch {
    return null
  }
}
