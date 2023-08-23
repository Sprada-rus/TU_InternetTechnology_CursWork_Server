import { defineConfig } from 'vite'
export default defineConfig(({command}) => {
  if (command === 'build') {
    return {
      build: {
        outDir: 'build',
        manifest: false,
        rollupOptions: {
          input: '/src/main.tsx'
        }
      }
    }
  }
})
