import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// One document. The wizard is one page with one job, and splitting it would
// only buy a second network round trip on a LAN where the whole point is that
// nothing is on the network.
export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist' },
  server: {
    port: 5200,
    // The setup daemon's own port. Its routes all sit under /api, so nothing
    // else is proxied and a mistake in this line cannot silently shadow a page.
    proxy: { '/api': { target: 'http://127.0.0.1:8799', changeOrigin: true } },
  },
});
