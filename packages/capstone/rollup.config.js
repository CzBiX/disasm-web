import { defineConfig } from 'rollup'
import alias from '@rollup/plugin-alias'
import typesript from '@rollup/plugin-typescript'
import swc from '@rollup/plugin-swc'

export default defineConfig({
  plugins: [
    alias({
      entries: {
        capstone: 'src/generated/capstone.mjs',
      },
    }),
    typesript({
      compilerOptions: {
        sourceMap: false,
        declaration: false,
      },
    }),
    swc({
      minify: false,
      minifyIdentifiers: true,
      minifySyntax: true,
      minifyWhitespace: false,
      treeShaking: true,
    }),
  ],
  external: ['module'],
  input: 'src/index.ts',
  output: [
    {
      file: 'dist/index.mjs',
      format: 'es',
    },
    {
      file: 'dist/index.cjs',
      format: 'cjs',
    },
  ],
})
