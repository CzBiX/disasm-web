/* eslint-disable no-underscore-dangle, max-classes-per-file */

import getCapstone from 'capstone'
import * as Const from './generated/const'
import {
  FieldInfo,
  NativeModule,
  defineMethods,
  POINTER_SIZE,
  readStruct,
  sizeOfStruct,
} from './native-utils'

const METHODS_TYPES = defineMethods({
  cs_open: { returnType: 'number', argTypes: ['number', 'number', 'number'] },
  cs_disasm: { returnType: 'number', argTypes: ['number', 'array', 'number', 'number', 'number', 'number'] },
  cs_free: { returnType: null, argTypes: ['number', 'number'] },
  cs_close: { returnType: 'number', argTypes: ['number'] },
  cs_option: { returnType: 'number', argTypes: ['number', 'number', 'number'] },

  cs_reg_name: { returnType: 'string', argTypes: ['number', 'number'] },
  cs_op_count: { returnType: 'number', argTypes: ['number', 'number', 'number'] },
  cs_op_index: { returnType: 'number', argTypes: ['number', 'number', 'number', 'number'] },

  cs_insn_name: { returnType: 'string', argTypes: ['number', 'number'] },
  cs_group_name: { returnType: 'string', argTypes: ['number', 'number'] },
  cs_insn_group: { returnType: 'boolean', argTypes: ['number', 'number', 'number'] },
  cs_reg_read: { returnType: 'boolean', argTypes: ['number', 'number', 'number'] },
  cs_reg_write: { returnType: 'boolean', argTypes: ['number', 'number', 'number'] },

  cs_errno: { returnType: 'number', argTypes: ['number'] },
  cs_version: { returnType: 'number', argTypes: ['number', 'number'] },
  cs_support: { returnType: 'boolean', argTypes: ['number'] },
  cs_strerror: { returnType: 'string', argTypes: ['number'] },
  cs_regs_access: { returnType: 'number', argTypes: ['number', 'number', 'number', 'number', 'number', 'number'] },

  malloc: { returnType: 'number', argTypes: ['number'] },
  free: { returnType: null, argTypes: ['number'] },
})

type MethodName = keyof typeof METHODS_TYPES

let capstone: NativeModule

export interface Insn {
  id: number;
  address: number | bigint;
  size: number;
  bytes: Uint8Array;
  mnemonic: string;
  opStr: string;
}

const INSN_FIELDS: FieldInfo<Insn>[] = [
  {
    name: 'id',
    type: 'i32',
  },
  {
    name: 'address',
    type: 'i64',
  },
  {
    name: 'size',
    type: 'i16',
  },
  {
    name: 'bytes',
    type: 'bytes',
    size: 24,
  },
  {
    name: 'mnemonic',
    type: 'string',
    size: 32,
  },
  {
    name: 'opStr',
    type: 'string',
    size: 160,
  },
  {
    // detail pointer
    type: 'i32',
  },
]
const INSN_SIZE = sizeOfStruct(INSN_FIELDS)

export class Capstone {
  arch: number

  mode: number

  handle_ptr: number | null

  constructor(arch: number, mode: number) {
    this.arch = arch
    this.mode = mode

    this.handle_ptr = Capstone.call('malloc', POINTER_SIZE)
    const ret = Capstone.call('cs_open', arch, mode, this.handle_ptr)
    if (ret !== Const.CS_ERR_OK) {
      throw new Error(`Failed to initialize capstone: ${Capstone.strError(ret)}`)
    }
  }

  get handle(): number {
    return capstone.getValue(this.handle_ptr!, '*')
  }

  setOption(opt: number, value: any): number {
    return Capstone.call('cs_option', this.handle, opt, value)
  }

  close() {
    const ret = Capstone.call('cs_close', this.handle_ptr)
    if (ret !== Const.CS_ERR_OK) {
      throw new Error(`Failed to close capstone: ${Capstone.strError(ret)}`)
    }

    this.handle_ptr = null
  }

  private static readInsn(insnPtr: number) {
    const insn = readStruct<Insn>(capstone, insnPtr, INSN_FIELDS)
    insn.bytes = insn.bytes.subarray(0, insn.size)

    return insn
  }

  disasm(data: number[] | Uint8Array, options: {
    address?: number | bigint,
    count?: number,
  } = {}) {
    const {
      address = 0,
      count: maxCount = 0,
    } = options

    const insnPtrPtr = Capstone.call('malloc', POINTER_SIZE)
    const count = Capstone.call(
      'cs_disasm',
      this.handle,
      data,
      data.length,
      BigInt(address),
      maxCount,
      insnPtrPtr,
    )

    if (count === 0) {
      Capstone.call('free', insnPtrPtr)
      throw new Error(`Failed to disassemble, error: ${Capstone.strError(this.errNo())}`)
    }

    const insnPtr = capstone.getValue(insnPtrPtr, '*')
    const instructions: Insn[] = []

    for (let i = 0; i < count; i++) {
      const insn = Capstone.readInsn(insnPtr + i * INSN_SIZE)
      if (insn.address <= Number.MAX_SAFE_INTEGER) {
        insn.address = Number(insn.address)
      }
      instructions.push(insn)
    }

    Capstone.call('cs_free', insnPtr, count)
    Capstone.call('free', insnPtrPtr)

    return instructions
  }

  getRegName(id: number): string {
    return Capstone.call('cs_reg_name', this.handle, id)
  }

  getInsnName(id: number): string {
    return Capstone.call('cs_insn_name', this.handle, id)
  }

  getGroupName(id: number): string {
    return Capstone.call('cs_group_name', this.handle, id)
  }

  errNo(): number {
    return Capstone.call('cs_errno', this.handle)
  }

  static call(name: MethodName, ...args: any[]) {
    const methodType = METHODS_TYPES[name]
    return capstone.ccall(name, methodType.returnType, methodType.argTypes, args)
  }

  static version() {
    const int = this.call('cs_version')

    /* eslint-disable no-bitwise */
    return {
      major: int >> 8,
      minor: int & 0xff,
    }
    /* eslint-enable no-bitwise */
  }

  static support(query: number): boolean {
    return this.call('cs_support', query)
  }

  static strError(errNo: number): string {
    return this.call('cs_strerror', errNo)
  }
}

async function factory() {
  if (capstone) {
    return
  }

  capstone = await getCapstone()
}

export default factory
