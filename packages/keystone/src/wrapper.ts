/* eslint-disable no-underscore-dangle, max-classes-per-file */

import getKeystone from 'keystone'
import * as Const from './generated/const'
import {
  NativeModule, defineMethods, POINTER_SIZE,
} from './native-utils'

const METHODS_TYPES = defineMethods({
  ks_open: { returnType: 'number', argTypes: ['number', 'number', 'number'] },
  ks_asm: { returnType: 'number', argTypes: ['number', 'string', 'number', 'number', 'number', 'number'] },
  ks_free: { returnType: null, argTypes: ['number'] },
  ks_close: { returnType: 'number', argTypes: ['number'] },
  ks_option: { returnType: 'number', argTypes: ['number', 'number', 'number'] },

  ks_errno: { returnType: 'number', argTypes: ['number'] },
  ks_version: { returnType: 'number', argTypes: ['number', 'number'] },
  ks_arch_supported: { returnType: 'boolean', argTypes: ['number'] },
  ks_strerror: { returnType: 'string', argTypes: ['number'] },

  malloc: { returnType: 'number', argTypes: ['number'] },
  free: { returnType: null, argTypes: ['number'] },
})

type MethodName = keyof typeof METHODS_TYPES

let keystone: NativeModule

export class Keystone {
  arch: number

  mode: number

  handle_ptr: number | null

  constructor(arch: number, mode: number) {
    this.arch = arch
    this.mode = mode

    this.handle_ptr = Keystone.call('malloc', POINTER_SIZE)
    const ret = Keystone.call('ks_open', arch, mode, this.handle_ptr)
    if (ret !== Const.KS_ERR_OK) {
      throw new Error(`Failed to initialize keystone: ${Keystone.strError(ret)}`)
    }
  }

  get handle(): number {
    return keystone.getValue(this.handle_ptr!, '*')
  }

  setOption(opt: number, value: any): number {
    return Keystone.call('ks_option', this.handle, opt, value)
  }

  close() {
    const ret = Keystone.call('ks_close', this.handle)
    if (ret !== Const.KS_ERR_OK) {
      throw new Error(`Failed to close keystone: ${Keystone.strError(ret)}`)
    }

    this.handle_ptr = null
  }

  asm(data: string, options: {
    address?: number | bigint,
  } = {}) {
    const {
      address = 0,
    } = options

    const bytesPtrPtr = Keystone.call('malloc', POINTER_SIZE)
    const bytesLenPtr = Keystone.call('malloc', POINTER_SIZE)
    const statCountPtr = Keystone.call('malloc', POINTER_SIZE)

    const errNo = Keystone.call(
      'ks_asm',
      this.handle,
      data,
      BigInt(address),
      bytesPtrPtr,
      bytesLenPtr,
      statCountPtr,
    )

    try {
      if (errNo !== Const.KS_ERR_OK) {
        throw new Error(`Failed to assemble, error: ${Keystone.strError(this.errNo())}`)
      }

      const bytesPtr = keystone.getValue(bytesPtrPtr, '*')
      const bytesLen = keystone.getValue(bytesLenPtr, 'i32')
      const bytes = keystone.HEAPU8.slice(bytesPtr, bytesPtr + bytesLen)
      Keystone.call('ks_free', bytesPtr)

      return bytes
    } finally {
      Keystone.call('free', bytesPtrPtr)
      Keystone.call('free', bytesLenPtr)
      Keystone.call('free', statCountPtr)
    }
  }

  errNo(): number {
    return Keystone.call('ks_errno', this.handle)
  }

  static call(name: MethodName, ...args: any[]) {
    const methodType = METHODS_TYPES[name]
    return keystone.ccall(name, methodType.returnType, methodType.argTypes, args)
  }

  static version() {
    const int = this.call('ks_version')

    /* eslint-disable no-bitwise */
    return {
      major: int >> 8,
      minor: int & 0xff,
    }
    /* eslint-enable no-bitwise */
  }

  static archSupported(query: number): boolean {
    return this.call('ks_arch_supported', query)
  }

  static strError(errNo: number): string {
    return this.call('ks_strerror', errNo)
  }
}

async function factory(args?: Record<string, unknown>) {
  if (keystone) {
    return
  }

  keystone = await getKeystone(args)
}

export default factory
