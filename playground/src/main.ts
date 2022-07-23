import { createApp } from 'vue'
import App from './App.vue'

// eslint-disable-next-line import/no-extraneous-dependencies
import '@unocss/reset/tailwind.css'
import './styles/main.css'
import 'uno.css'

const app = createApp(App)
app.mount('#app')
