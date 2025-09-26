# commucat-media

Media utilities and abstractions used by the CommuCat server and clients.

## Features

- Voice codecs: Opus and raw PCM, support for VBR, FEC, DTX and on-the-fly codec switching.
- Video codecs: VP8/VP9 (libvpx) and pass-tru for RAW I420; AV1/H264 presets with profile configuration.
- Unified configuration model with `commucat-media-types': declare available codecs, source modes (raw/encoded/hybrid) and hardware acceleration preferences.
- Call Pipeline: ready-made encoder/decoder bundle with dynamic codec and PLC selection.
- Audio capture via `cpal` with i16 conversion and inline colback.

## Extension

- Optional-fiches `codec-av1`, `codec-h264` are provided for AV1/H264. They declare dependencies (`rav1e`, `openh264`) and allow to connect corresponding backends without changing API.
- Common codec descriptors are placed in `commucat-media-types`, which simplifies the exchange of features between `proto`, server and clients.

## Testing

```bash
cargo test --package commucat-media --all-features
```
