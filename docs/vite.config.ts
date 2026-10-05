import { defineConfig } from 'vite'
import { holocron } from '@holocron.so/vite'

export default defineConfig({
  plugins: [holocron()],
  server: {
    port: 3334,
    host: true,
  },
})
