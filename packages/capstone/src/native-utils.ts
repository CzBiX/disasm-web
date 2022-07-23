export const POINTER_SIZE = 4

export type NativeType =
  | '*'
  | 'i1'
  | 'i8'
  | 'i16'
  | 'i32'
  | 'i64'
  | 'float'
  | 'double'
  | 'string'
  | 'boolean'
  | 'bytes'
  | null

export type CallType = 'string' | 'boolean' | 'number' | 'array' | null

export function defineMethods<TKey extends string>(obj: Record<TKey, {
  returnType: CallType;
  argTypes: CallType[]
}>) {
  return obj
}

export interface NativeModule {
  ccall(name: string, retType: CallType, argTypes: CallType[], ...args: any[]): any;
  getValue(ptr: number, type: NativeType): any;
  UTF8ToString(ptr: number, size: number): string;

  HEAPU8: Uint8Array;
  HEAPU32: Uint32Array;
}

export function getNativeTypeSize(type: NativeType) {
  switch (type) {
    case '*': return POINTER_SIZE
    case 'i1': case 'i8': return 1
    case 'i16': return 2
    case 'i32': return 4
    case 'i64': return 8
    case 'float': return 4
    case 'double': return 8
    default: {
      throw new Error(`Unsupported type: ${type}`)
    }
  }
}

export interface FieldInfo<T extends object = any> {
  name?: keyof T;
  type: NativeType;
  size?: number;
}

function getFieldSize(field: FieldInfo) {
  if (field.type === 'string' || field.type === 'bytes') {
    return field.size!
  }

  return getNativeTypeSize(field.type)
}

function getStructFieldPadding(offset: number, size: number) {
  const remainder = offset % size
  if (remainder) {
    return size - remainder
  }

  return 0
}

export function sizeOfStruct(fields: FieldInfo[]) {
  return fields.reduce((acc, field) => {
    const size = getFieldSize(field)
    const padding = (field.type === 'string' || field.type === 'bytes') ? 0 : getStructFieldPadding(acc, size)
    return acc + padding + size
  }, 0)
}

export function readStruct<T extends object>(
  module: NativeModule,
  ptr: number,
  fields: FieldInfo<T>[],
) {
  let offset = 0

  return fields.reduce((obj, field) => {
    let value
    let size
    if (field.type === 'string') {
      size = field.size!
      value = module.UTF8ToString(ptr + offset, size)
    } else if (field.type === 'bytes') {
      size = field.size!
      value = module.HEAPU8.slice(ptr + offset, ptr + offset + size)
    } else {
      size = getNativeTypeSize(field.type)
      offset += getStructFieldPadding(offset, size)
      value = module.getValue(ptr + offset, field.type)
    }

    offset += size
    if (field.name) {
      return {
        ...obj,
        [field.name]: value,
      }
    }

    return obj
  }, {} as T)
}
