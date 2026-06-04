import { defineConfig, presetIcons, presetWind } from 'unocss'
import transformerVariantGroup from '@unocss/transformer-variant-group'

export default defineConfig({
  presets: [
    presetWind(),
    presetIcons({
      extraProperties: {
        color: 'currentColor',
      },
    }),
  ],
  transformers: [
    transformerVariantGroup(),
  ],
})
