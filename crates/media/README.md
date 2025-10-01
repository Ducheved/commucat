# commucat-media

Media primitives shared by the CommuCat server and operational tools.

## Features

- Safe wrappers for [audiopus] and [env-libvpx] to encode/decode Opus and VP8/VP9 frames.
- `CallMediaPipeline` (feature `pipeline`) – synchronous Opus encode/decode loop with frame duration control for smoke testing.
- `voice` module – encoders/decoders, signal level helpers, integration with `commucat-media-types`.
- `video` module – RAW I420 → VP8/VP9 encoding, optional AV1/H.264 support through the `codec-av1` and `codec-h264` features.
- `capture` (feature `audio-io`) – PCM capture via [cpal] producing `i16` frames.

## Limitations

- Adaptive bitrate, forward error correction and SVC are only partially implemented and not wired into end-to-end flows yet.
- AV1/H.264 rely on native libraries (`rav1e`, `openh264`); enabling the features pulls the corresponding build dependencies.
- No GPU/accelerated codec bindings are provided.

[audiopus]: https://crates.io/crates/audiopus
[env-libvpx]: https://crates.io/crates/env-libvpx-sys
[cpal]: https://crates.io/crates/cpal