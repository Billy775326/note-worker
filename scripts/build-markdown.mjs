import { build } from 'esbuild';
import { readFile, writeFile } from 'node:fs/promises';
const result = await build({ entryPoints: ['src/markdown-browser.js'], bundle: true, minify: true, format: 'iife', platform: 'browser', write: false, legalComments: 'inline' });
const bundle = result.outputFiles[0].text.replace(/<\/script/gi, '<\\/script');
const declaration = '// MARKDOWN_VENDOR_START\nconst markdownVendor = ' + JSON.stringify(bundle) + ';\n// MARKDOWN_VENDOR_END\n';
let worker = await readFile('worker.js', 'utf8');
if (worker.includes('// MARKDOWN_VENDOR_START')) {
  const start = worker.indexOf('// MARKDOWN_VENDOR_START');
  const end = worker.indexOf('// MARKDOWN_VENDOR_END', start) + '// MARKDOWN_VENDOR_END'.length;
  worker = worker.slice(0, start) + declaration + worker.slice(end);
} else {
  worker = worker.replace('const htmlContent = `', () => declaration + '\nconst htmlContent = `');
  worker = worker.replace(/    <script>\r?\n/, '    <script>\n        ${markdownVendor}\n');
}
await writeFile('worker.js', worker);
console.log('Embedded Markdown renderer and sanitizer in worker.js');
