# disasm-web
[![npm](https://img.shields.io/npm/v/capstone-wasm?label=capstone-wasm)](https://www.npmjs.com/package/capstone-wasm)
[![npm](https://img.shields.io/npm/v/keystone-wasm?label=keystone-wasm)](https://www.npmjs.com/package/keystone-wasm)

Online Assembler and Disassembler.

This project ported [capstone](https://github.com/capstone-engine/capstone) and [keystone](https://github.com/keystone-engine/keystone) into the browser via [emscripten](https://emscripten.org/).

Playground: https://disasm.czbix.com/ (support offline usage)

## NPM packages
There are two packages available: [`capstone-wasm`](https://www.npmjs.com/package/capstone-wasm) and [`keystone-wasm`](https://www.npmjs.com/package/keystone-wasm).

### Usage

```js
import {
  Const, Capstone, loadCapstone,
} from 'capstone-wasm'

await loadCapstone()

const capstone = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_32)
// the code can be bytes array or Uint8Array
const code = [0x55, 0x8b, 0xec, 0x83, 0xc4, 0x0c, 0xc3]
const insns = capstone.disasm(code, {
  address: 0x1000,
})

insns.forEach(insn => {
  console.log(insn.mnemonic, insn.opStr)
})
```

```js
import {
  Const, Keystone, loadKeystone,
} from 'keystone-wasm'

await loadKeystone()

const capstone = new Keystone(Const.KS_ARCH_X86, Const.KS_MODE_32)
// can separate code by `\n` or `;`
const code = `push ebp
mov ebp, esp
add esp, 0xc
ret`
// bytes is a Uint8Array
const bytes = keystone.asm(code, {
  address: 0x1000,
})
```

## Cons
Not support detail feature(`CS_OPT_DETAIL`) yet.