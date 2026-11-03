# The README demo

`../demo.gif` is a re-enactment, not a screen recording: `scene.html`
draws an agent's terminal next to the approver's phone and moves through
a fixed timeline, and `render.mjs` steps it frame by frame in headless
Chromium. Names, hosts and times are made up.

The approval messages and CLI output are copied by hand from
`internal/telegram/render.go` and `cmd/nyyrikki/main.go`. When those
change, update `scene.html` to match and render again.

## Rendering

Needs Node 20 or newer and ffmpeg.

```sh
cd docs/assets/demo
npm ci
npx playwright-core install chromium   # or set CHROMIUM=/path/to/chrome
npm run render
```

It takes a few minutes and writes `demo.mp4` here (not committed) and
`../demo.gif`.

To look at one moment, open `scene.html?t=24` in a browser; `t` is
seconds into the timeline.
