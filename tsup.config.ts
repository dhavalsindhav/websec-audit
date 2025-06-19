import { defineConfig } from 'tsup';

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/frontend/index.ts',
    'src/backend/index.ts',
  ],
  format: ['cjs', 'esm'],
  // Skip DTS generation through tsup and use tsc separately
  dts: false,
  splitting: false,
  sourcemap: true,
  clean: false, // Don't clean so we preserve .d.ts files from tsc
  bundle: true,
  treeshake: true,
  platform: 'node', // Support Node.js built-in modules
  esbuildOptions(options) {
    options.resolveExtensions = ['.ts', '.js', '.mjs', '.json'];
  },
  noExternal: ['wappalyzer-core', 'retire']
});
