// Renders scene.html frame by frame in headless Chromium and encodes
// demo.mp4 (here) and ../demo.gif (the one README.md shows). See README.md.
import { chromium } from 'playwright-core';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const dir = path.dirname(fileURLToPath(import.meta.url));
const FPS = 30, DUR = 60.5; // keep DUR in step with the end card in scene.html
const mp4 = path.join(dir, 'demo.mp4'), gif = path.join(dir, '..', 'demo.gif');

function ffmpeg(args, opts) {
  const p = spawn('ffmpeg', ['-y', '-loglevel', 'error', ...args], opts);
  const done = new Promise((ok, fail) => p.on('close', c => c === 0 ? ok() : fail(new Error(`ffmpeg exited ${c}`))));
  return { p, done };
}

const enc = ffmpeg(['-f', 'image2pipe', '-framerate', String(FPS), '-c:v', 'mjpeg', '-i', '-',
  '-c:v', 'libx264', '-preset', 'slow', '-crf', '18', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', mp4],
  { stdio: ['pipe', 'inherit', 'inherit'] });

// CHROMIUM overrides the browser; otherwise the one `npx playwright-core
// install chromium` fetched.
const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });
await page.goto('file://' + path.join(dir, 'scene.html'));
const frames = Math.round(DUR * FPS);
for (let f = 0; f < frames; f++) {
  await page.evaluate(t => window.render(t), f / FPS);
  const buf = await page.screenshot({ type: 'jpeg', quality: 95 });
  if (!enc.p.stdin.write(buf)) await new Promise(r => enc.p.stdin.once('drain', r));
  if (f % 300 === 0) process.stderr.write(`frame ${f}/${frames}\n`);
}
enc.p.stdin.end();
await browser.close();
await enc.done;

// 1280 px keeps the phone's text readable; Bayer dithering keeps the
// background gradient from banding.
await ffmpeg(['-i', mp4, '-vf',
  'fps=10,scale=1280:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=full[p];' +
  '[b][p]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle', gif], { stdio: 'inherit' }).done;
console.log(`wrote ${mp4} and ${gif}`);
