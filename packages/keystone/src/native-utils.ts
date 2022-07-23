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
