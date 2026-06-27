# MCP-S Intro Video

Motion Canvas source for the MCP-S intro video: an ~8s title **preamble** (the
"new kid on the protocol block" cold open) followed by a ~100s narrated
**animatic** explaining MCP-S. Final cut is 1920×1080 @ 60fps.

```txt
[ preamble + braam SFX ]  ->  [ narrated animatic + voiceover ]  =  dist/mcps-intro-final.mp4
```

There are two Motion Canvas projects in one app:

- `src/project.ts`  — `mcps-intro`, the narrated animatic.
- `src/preamble.ts` — `mcps-preamble`, the title preamble.

## Setup

```sh
npm install
```

The preamble can also be rendered headlessly (see below), which needs Pillow:

```sh
python3 -m venv .venv && .venv/bin/pip install pillow
```

## Editor

```sh
npm run preview
```

With two projects registered, the editor serves an index at
`http://localhost:9000/` and each project at its own route:

- `http://localhost:9000/src/project`  — the animatic
- `http://localhost:9000/src/preamble` — the preamble

Rendering uses the FFmpeg exporter (`@motion-canvas/ffmpeg`), configured in each
project's `.meta`. Exports land in `dist/`.

## Audio

**Voiceover** (`assets/audio/voiceover.wav`) — generated from the script via
OpenAI TTS:

```sh
OPENAI_API_KEY=... npm run voiceover:cedar   # or voiceover:marin
```

The script is `voiceover/script.md`; section timing is `voiceover/timing.md`
(the timing master). Motion Canvas references the WAV as the project audio so
the timeline can be checked against narration. Section transitions are anchored
to the audio with `waitUntil()` time events stored in `src/scenes/*.meta`.

> Note: the narration has two hand-inserted pauses (the "concrete risk" section)
> added with ffmpeg after TTS. That edit is not yet baked into the voiceover
> script, so `voiceover.wav` is the one artifact not fully reproducible from
> source.

**Braam SFX** (`assets/audio/intro-analog-to-quantum.wav`) — the preamble's
data-click → snap → analog-saw braam, synthesised deterministically:

```sh
python3 scripts/gen-intro-sfx.py
```

Generated audio is git-ignored; rebuild it with the scripts above.

## Build the final video

```sh
# 1. voiceover + SFX
OPENAI_API_KEY=... npm run voiceover:cedar
python3 scripts/gen-intro-sfx.py

# 2. export the silent animatic from the editor (mcps-intro project, FFmpeg
#    exporter) and save it as dist/mcps-intro-silent.mp4

# 3. mux the voiceover onto the silent animatic -> dist/mcps-intro-with-voice.mp4
npm run render:final

# 4. render the preamble headlessly -> dist/preamble.mp4
.venv/bin/python scripts/render-preamble.py

# 5. assemble preamble + animatic (+ SFX) -> dist/mcps-intro-final.mp4
npm run build:final
```

`build:final` re-encodes to a single constant-frame-rate H.264/AAC file so the
preamble→animatic seam plays cleanly in every player.

## Publishing

`publish/` holds the version-controlled release assets:

- `publish/mcps-intro-final.srt` — captions (preamble text + corrected narration).
- `publish/youtube-metadata.txt` — title, description, chapters, pinned comment.

The rendered `dist/mcps-intro-final.mp4` itself is git-ignored (it lives on
YouTube / is rebuildable from the steps above).

## Structure

- `src/project.ts`, `src/preamble.ts` — the two Motion Canvas projects.
- `src/scenes/mcps-intro.tsx` — the narrated animatic.
- `src/scenes/preamble.tsx` — the title preamble (materialize → deadpan → reveal).
- `src/scenes/*.meta` — `waitUntil()` time events (audio sync; treated as source).
- `src/components/` — reusable visual components.
- `voiceover/` — narration script and timing reference.
- `scripts/generate-voiceover.mjs` — OpenAI TTS → `voiceover.wav`.
- `scripts/gen-intro-sfx.py` — the braam SFX.
- `scripts/render-preamble.py` — headless preamble render (Pillow → ffmpeg).
- `scripts/mux-final.mjs` — silent animatic + voiceover → `mcps-intro-with-voice.mp4`.
- `scripts/build-intro-final.mjs` — preamble + animatic → `mcps-intro-final.mp4`.
