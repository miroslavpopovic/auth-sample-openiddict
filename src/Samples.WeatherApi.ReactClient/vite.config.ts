import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
    server: {
      watch: {
        usePolling: true
      },
      host: true, // needed for Docker container port mapping
      strictPort: true,
      port: 7216
    }
})
