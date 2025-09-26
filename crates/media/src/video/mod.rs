#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::similar_names)]
#![allow(clippy::manual_div_ceil)]

use crate::{MediaError, MediaResult};
use commucat_media_types::{HardwareAcceleration, MediaSourceMode, VideoCodec};
use env_libvpx_sys as vpx;
use std::convert::TryFrom;
use std::fmt;
use std::mem::MaybeUninit;
use std::os::raw::{c_int, c_long, c_ulong};
use std::ptr;
use std::slice;

#[derive(Debug, Clone)]
pub struct VideoEncoderConfig {
    pub codec: VideoCodec,
    pub width: u32,
    pub height: u32,
    pub timebase_num: u32,
    pub timebase_den: u32,
    pub bitrate: u32,
    pub min_quantizer: u32,
    pub max_quantizer: u32,
    pub threads: u8,
    pub source: MediaSourceMode,
    pub prefer_hardware: bool,
    pub hardware: Vec<HardwareAcceleration>,
}

impl Default for VideoEncoderConfig {
    fn default() -> Self {
        Self {
            codec: VideoCodec::Vp8,
            width: 640,
            height: 360,
            timebase_num: 1,
            timebase_den: 30,
            bitrate: 900,
            min_quantizer: 2,
            max_quantizer: 32,
            threads: 2,
            source: MediaSourceMode::Raw,
            prefer_hardware: false,
            hardware: vec![HardwareAcceleration::Cpu],
        }
    }
}

pub struct VideoEncoder {
    cfg: VideoEncoderConfig,
    backend: VideoEncoderBackend,
    pts: u64,
}

enum VideoEncoderBackend {
    Raw,
    Vpx(VpxEncoder),
    #[allow(dead_code)]
    #[cfg(feature = "codec-av1")]
    Av1,
    #[allow(dead_code)]
    #[cfg(feature = "codec-h264")]
    H264,
    Unsupported(VideoCodec),
}

#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub timestamp: u64,
    pub keyframe: bool,
    pub codec: VideoCodec,
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
}

#[derive(Clone, Copy)]
pub struct I420Borrowed<'a> {
    pub y: &'a [u8],
    pub u: &'a [u8],
    pub v: &'a [u8],
    pub stride_y: usize,
    pub stride_u: usize,
    pub stride_v: usize,
}

impl fmt::Debug for VideoEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoEncoder")
            .field("codec", &self.cfg.codec)
            .field("width", &self.cfg.width)
            .field("height", &self.cfg.height)
            .field("bitrate", &self.cfg.bitrate)
            .field("threads", &self.cfg.threads)
            .field("pts", &self.pts)
            .finish_non_exhaustive()
    }
}

impl VideoEncoder {
    pub fn new(config: VideoEncoderConfig) -> MediaResult<Self> {
        if config.width == 0 || config.height == 0 {
            return Err(MediaError::InvalidConfig(
                "video dimensions must be positive",
            ));
        }
        if config.timebase_den == 0 || config.timebase_num == 0 {
            return Err(MediaError::InvalidConfig("invalid timebase"));
        }
        if matches!(config.source, MediaSourceMode::Encoded) {
            return Err(MediaError::InvalidConfig(
                "video encoder expects raw frames for input",
            ));
        }
        if config.threads == 0 {
            return Err(MediaError::InvalidConfig("thread count must be positive"));
        }
        let backend = match config.codec {
            VideoCodec::RawI420 => VideoEncoderBackend::Raw,
            VideoCodec::Vp8 | VideoCodec::Vp9 => {
                VideoEncoderBackend::Vpx(VpxEncoder::new(config.codec, &config)?)
            }
            VideoCodec::Av1Main => {
                #[cfg(feature = "codec-av1")]
                {
                    // TODO: integrate rav1e encoder backend
                    VideoEncoderBackend::Unsupported(VideoCodec::Av1Main)
                }
                #[cfg(not(feature = "codec-av1"))]
                {
                    VideoEncoderBackend::Unsupported(VideoCodec::Av1Main)
                }
            }
            VideoCodec::H264Baseline | VideoCodec::H264Main | VideoCodec::H265Main => {
                #[cfg(feature = "codec-h264")]
                {
                    // TODO: integrate hardware/software H264 encoder
                    VideoEncoderBackend::Unsupported(config.codec)
                }
                #[cfg(not(feature = "codec-h264"))]
                {
                    VideoEncoderBackend::Unsupported(config.codec)
                }
            }
        };
        Ok(Self {
            cfg: config,
            backend,
            pts: 0,
        })
    }

    pub fn encode(
        &mut self,
        frame: I420Borrowed<'_>,
        timestamp: u64,
        force_keyframe: bool,
    ) -> MediaResult<Vec<VideoFrame>> {
        match &mut self.backend {
            VideoEncoderBackend::Raw => self.encode_raw(frame, timestamp),
            VideoEncoderBackend::Vpx(encoder) => {
                let frames = encoder.encode(frame, timestamp, force_keyframe, &self.cfg)?;
                self.pts = self.pts.wrapping_add(1);
                Ok(frames)
            }
            #[cfg(feature = "codec-av1")]
            VideoEncoderBackend::Av1 => Err(MediaError::Unsupported),
            #[cfg(feature = "codec-h264")]
            VideoEncoderBackend::H264 => Err(MediaError::Unsupported),
            VideoEncoderBackend::Unsupported(codec) => Err(MediaError::Codec(format!(
                "encoder for {codec:?} is not available"
            ))),
        }
    }

    fn encode_raw(
        &mut self,
        frame: I420Borrowed<'_>,
        timestamp: u64,
    ) -> MediaResult<Vec<VideoFrame>> {
        let width = self.cfg.width as usize;
        let height = self.cfg.height as usize;
        let uv_width = (width + 1) / 2;
        let uv_height = (height + 1) / 2;
        let expected_y = frame.stride_y * height;
        let expected_u = frame.stride_u * uv_height;
        let expected_v = frame.stride_v * uv_height;
        if frame.y.len() < expected_y || frame.u.len() < expected_u || frame.v.len() < expected_v {
            return Err(MediaError::InvalidConfig("insufficient planar data"));
        }
        let mut data = Vec::with_capacity(width * height + uv_width * uv_height * 2);
        copy_plane_into_vec_owned(frame.y, frame.stride_y, width, height, &mut data);
        copy_plane_into_vec_owned(frame.u, frame.stride_u, uv_width, uv_height, &mut data);
        copy_plane_into_vec_owned(frame.v, frame.stride_v, uv_width, uv_height, &mut data);
        Ok(vec![VideoFrame {
            timestamp,
            keyframe: true,
            codec: VideoCodec::RawI420,
            width: self.cfg.width,
            height: self.cfg.height,
            data,
        }])
    }
}

impl Drop for VideoEncoder {
    fn drop(&mut self) {
        if let VideoEncoderBackend::Vpx(encoder) = &mut self.backend {
            encoder.destroy();
        }
    }
}

pub struct VideoDecoder {
    backend: VideoDecoderBackend,
}

enum VideoDecoderBackend {
    None,
    Raw,
    Vpx(VpxDecoder),
    #[allow(dead_code)]
    #[cfg(feature = "codec-av1")]
    Av1,
    #[allow(dead_code)]
    #[cfg(feature = "codec-h264")]
    H264,
}

impl fmt::Debug for VideoDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VideoDecoder").finish()
    }
}

#[derive(Debug, Clone)]
pub struct DecodedFrame {
    pub timestamp: u64,
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
    pub codec: VideoCodec,
}

impl VideoDecoder {
    pub fn new() -> MediaResult<Self> {
        Ok(Self {
            backend: VideoDecoderBackend::None,
        })
    }

    pub fn decode(&mut self, frame: &VideoFrame) -> MediaResult<Vec<DecodedFrame>> {
        self.ensure_backend(frame.codec)?;
        match &mut self.backend {
            VideoDecoderBackend::Raw => Ok(vec![DecodedFrame {
                timestamp: frame.timestamp,
                width: frame.width,
                height: frame.height,
                data: frame.data.clone(),
                codec: VideoCodec::RawI420,
            }]),
            VideoDecoderBackend::Vpx(decoder) => decoder.decode(frame),
            #[cfg(feature = "codec-av1")]
            VideoDecoderBackend::Av1 => Err(MediaError::Unsupported),
            #[cfg(feature = "codec-h264")]
            VideoDecoderBackend::H264 => Err(MediaError::Unsupported),
            VideoDecoderBackend::None => Err(MediaError::Unsupported),
        }
    }

    fn ensure_backend(&mut self, codec: VideoCodec) -> MediaResult<()> {
        let need_switch = match (&self.backend, codec) {
            (VideoDecoderBackend::Raw, VideoCodec::RawI420) => false,
            (VideoDecoderBackend::Vpx(decoder), VideoCodec::Vp8 | VideoCodec::Vp9) => {
                decoder.codec != codec
            }
            #[cfg(feature = "codec-av1")]
            (VideoDecoderBackend::Av1, VideoCodec::Av1Main) => false,
            #[cfg(feature = "codec-h264")]
            (VideoDecoderBackend::H264, VideoCodec::H264Baseline | VideoCodec::H264Main) => false,
            _ => true,
        };
        if !need_switch {
            return Ok(());
        }
        self.backend = match codec {
            VideoCodec::RawI420 => VideoDecoderBackend::Raw,
            VideoCodec::Vp8 | VideoCodec::Vp9 => VideoDecoderBackend::Vpx(VpxDecoder::new(codec)?),
            VideoCodec::Av1Main => {
                #[cfg(feature = "codec-av1")]
                {
                    VideoDecoderBackend::Av1
                }
                #[cfg(not(feature = "codec-av1"))]
                {
                    return Err(MediaError::Unsupported);
                }
            }
            VideoCodec::H264Baseline | VideoCodec::H264Main | VideoCodec::H265Main => {
                #[cfg(feature = "codec-h264")]
                {
                    VideoDecoderBackend::H264
                }
                #[cfg(not(feature = "codec-h264"))]
                {
                    return Err(MediaError::Unsupported);
                }
            }
        };
        Ok(())
    }
}

impl Drop for VideoDecoder {
    fn drop(&mut self) {
        if let VideoDecoderBackend::Vpx(decoder) = &mut self.backend {
            decoder.destroy();
        }
    }
}

struct VpxEncoder {
    ctx: vpx::vpx_codec_ctx_t,
    cfg: vpx::vpx_codec_enc_cfg_t,
    codec: VideoCodec,
}

unsafe impl Send for VpxEncoder {}
unsafe impl Send for VideoEncoder {}
unsafe impl Send for VideoDecoder {}

impl VpxEncoder {
    fn new(codec: VideoCodec, config: &VideoEncoderConfig) -> MediaResult<Self> {
        let iface = match codec {
            VideoCodec::Vp8 => unsafe { vpx::vpx_codec_vp8_cx() },
            VideoCodec::Vp9 => unsafe { vpx::vpx_codec_vp9_cx() },
            other => {
                return Err(MediaError::Codec(format!(
                    "libvpx backend does not support {other:?}"
                )));
            }
        };
        if iface.is_null() {
            return Err(MediaError::Unsupported);
        }
        unsafe {
            let mut cfg = MaybeUninit::<vpx::vpx_codec_enc_cfg_t>::uninit();
            let res = vpx::vpx_codec_enc_config_default(iface, cfg.as_mut_ptr(), 0);
            if res != vpx::vpx_codec_err_t::VPX_CODEC_OK {
                return Err(MediaError::Codec(format!(
                    "vpx config init failed: {res:?}"
                )));
            }
            let mut cfg = cfg.assume_init();
            cfg.g_w = config.width;
            cfg.g_h = config.height;
            cfg.g_timebase.num = config.timebase_num as c_int;
            cfg.g_timebase.den = config.timebase_den as c_int;
            cfg.rc_target_bitrate = config.bitrate;
            cfg.rc_min_quantizer = config.min_quantizer;
            cfg.rc_max_quantizer = config.max_quantizer;
            cfg.g_threads = u32::from(config.threads);
            cfg.g_lag_in_frames = 0;
            cfg.g_pass = vpx::vpx_enc_pass::VPX_RC_ONE_PASS;
            cfg.rc_end_usage = vpx::vpx_rc_mode::VPX_VBR;
            cfg.kf_mode = vpx::vpx_kf_mode::VPX_KF_AUTO;
            if codec == VideoCodec::Vp9 {
                cfg.g_profile = 0;
            }
            let mut ctx = MaybeUninit::<vpx::vpx_codec_ctx_t>::zeroed();
            let init_res = vpx::vpx_codec_enc_init_ver(
                ctx.as_mut_ptr(),
                iface,
                &cfg,
                0,
                vpx::VPX_ENCODER_ABI_VERSION as c_int,
            );
            if init_res != vpx::vpx_codec_err_t::VPX_CODEC_OK {
                return Err(MediaError::Codec(format!(
                    "vpx encoder init failed: {init_res:?}"
                )));
            }
            Ok(Self {
                ctx: ctx.assume_init(),
                cfg,
                codec,
            })
        }
    }

    fn encode(
        &mut self,
        frame: I420Borrowed<'_>,
        timestamp: u64,
        force_keyframe: bool,
        config: &VideoEncoderConfig,
    ) -> MediaResult<Vec<VideoFrame>> {
        unsafe {
            let height = self.cfg.g_h as usize;
            let width = self.cfg.g_w as usize;
            let uv_height = (height + 1) / 2;
            let uv_width = (width + 1) / 2;
            let expected_y = frame.stride_y * height;
            let expected_u = frame.stride_u * uv_height;
            let expected_v = frame.stride_v * uv_height;
            if frame.y.len() < expected_y
                || frame.u.len() < expected_u
                || frame.v.len() < expected_v
            {
                return Err(MediaError::InvalidConfig("insufficient planar data"));
            }

            let image = vpx::vpx_img_alloc(
                ptr::null_mut(),
                vpx::vpx_img_fmt::VPX_IMG_FMT_I420,
                self.cfg.g_w,
                self.cfg.g_h,
                1,
            );
            if image.is_null() {
                return Err(MediaError::Codec("vpx_img_alloc failed".to_string()));
            }
            let img = &mut *image;
            copy_plane(
                frame.y,
                frame.stride_y,
                img.planes[0],
                img.stride[0] as usize,
                width,
                height,
            );
            copy_plane(
                frame.u,
                frame.stride_u,
                img.planes[1],
                img.stride[1] as usize,
                uv_width,
                uv_height,
            );
            copy_plane(
                frame.v,
                frame.stride_v,
                img.planes[2],
                img.stride[2] as usize,
                uv_width,
                uv_height,
            );

            let pts = i64::try_from(timestamp)
                .map_err(|_| MediaError::InvalidConfig("timestamp exceeds encoder range"))?;
            let duration: c_ulong = 1;
            let flags: c_long = if force_keyframe {
                c_long::from(vpx::VPX_EFLAG_FORCE_KF)
            } else {
                0
            };
            let res = vpx::vpx_codec_encode(
                &mut self.ctx,
                img,
                pts,
                duration,
                flags,
                c_ulong::from(vpx::VPX_DL_REALTIME),
            );
            vpx::vpx_img_free(image);
            if res != vpx::vpx_codec_err_t::VPX_CODEC_OK {
                return Err(MediaError::Codec(format!("vpx encode failed: {res:?}")));
            }

            let mut iter: vpx::vpx_codec_iter_t = ptr::null_mut();
            let mut output = Vec::new();
            loop {
                let pkt = vpx::vpx_codec_get_cx_data(&mut self.ctx, &mut iter);
                if pkt.is_null() {
                    break;
                }
                let packet = &*pkt;
                if packet.kind == vpx::vpx_codec_cx_pkt_kind::VPX_CODEC_CX_FRAME_PKT {
                    let frame_pkt = packet.data.frame;
                    if frame_pkt.sz == 0 {
                        continue;
                    }
                    let data =
                        slice::from_raw_parts(frame_pkt.buf as *const u8, frame_pkt.sz).to_vec();
                    let keyframe = frame_pkt.flags & vpx::VPX_FRAME_IS_KEY != 0;
                    output.push(VideoFrame {
                        timestamp,
                        keyframe,
                        codec: self.codec,
                        width: config.width,
                        height: config.height,
                        data,
                    });
                }
            }
            Ok(output)
        }
    }

    fn destroy(&mut self) {
        unsafe {
            let _ = vpx::vpx_codec_destroy(&mut self.ctx);
        }
    }
}

struct VpxDecoder {
    ctx: vpx::vpx_codec_ctx_t,
    codec: VideoCodec,
}

impl VpxDecoder {
    fn new(codec: VideoCodec) -> MediaResult<Self> {
        let iface = match codec {
            VideoCodec::Vp8 => unsafe { vpx::vpx_codec_vp8_dx() },
            VideoCodec::Vp9 => unsafe { vpx::vpx_codec_vp9_dx() },
            other => {
                return Err(MediaError::Codec(format!(
                    "libvpx decoder does not support {other:?}"
                )));
            }
        };
        if iface.is_null() {
            return Err(MediaError::Unsupported);
        }
        unsafe {
            let mut ctx = MaybeUninit::<vpx::vpx_codec_ctx_t>::zeroed();
            let res = vpx::vpx_codec_dec_init_ver(
                ctx.as_mut_ptr(),
                iface,
                ptr::null(),
                0,
                vpx::VPX_DECODER_ABI_VERSION as c_int,
            );
            if res != vpx::vpx_codec_err_t::VPX_CODEC_OK {
                return Err(MediaError::Codec(format!(
                    "vpx decoder init failed: {res:?}"
                )));
            }
            Ok(Self {
                ctx: ctx.assume_init(),
                codec,
            })
        }
    }

    fn decode(&mut self, frame: &VideoFrame) -> MediaResult<Vec<DecodedFrame>> {
        unsafe {
            let res = vpx::vpx_codec_decode(
                &mut self.ctx,
                frame.data.as_ptr(),
                frame.data.len() as u32,
                ptr::null_mut(),
                0,
            );
            if res != vpx::vpx_codec_err_t::VPX_CODEC_OK {
                return Err(MediaError::Codec(format!("vpx decode failed: {res:?}")));
            }
            let mut frames = Vec::new();
            let mut iter: vpx::vpx_codec_iter_t = ptr::null_mut();
            loop {
                let img_ptr = vpx::vpx_codec_get_frame(&mut self.ctx, &mut iter);
                if img_ptr.is_null() {
                    break;
                }
                let img = &*img_ptr;
                if img.fmt != vpx::vpx_img_fmt::VPX_IMG_FMT_I420 {
                    return Err(MediaError::Codec("unexpected pixel format".to_string()));
                }
                let width = img.d_w;
                let height = img.d_h;
                let y_size = (width as usize) * (height as usize);
                let uv_width = (width as usize + 1) / 2;
                let uv_height = (height as usize + 1) / 2;
                let uv_size = uv_width * uv_height;
                let mut buffer = Vec::with_capacity(y_size + uv_size * 2);
                copy_plane_into_vec(
                    img.planes[0],
                    img.stride[0] as usize,
                    width as usize,
                    height as usize,
                    &mut buffer,
                );
                copy_plane_into_vec(
                    img.planes[1],
                    img.stride[1] as usize,
                    uv_width,
                    uv_height,
                    &mut buffer,
                );
                copy_plane_into_vec(
                    img.planes[2],
                    img.stride[2] as usize,
                    uv_width,
                    uv_height,
                    &mut buffer,
                );
                frames.push(DecodedFrame {
                    timestamp: frame.timestamp,
                    width,
                    height,
                    data: buffer,
                    codec: VideoCodec::RawI420,
                });
            }
            Ok(frames)
        }
    }

    fn destroy(&mut self) {
        unsafe {
            let _ = vpx::vpx_codec_destroy(&mut self.ctx);
        }
    }
}

unsafe fn copy_plane(
    src: &[u8],
    src_stride: usize,
    dst_ptr: *mut u8,
    dst_stride: usize,
    width: usize,
    height: usize,
) {
    for row in 0..height {
        let src_offset = row * src_stride;
        let dst_offset = row * dst_stride;
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr().add(src_offset), dst_ptr.add(dst_offset), width);
        }
    }
}

unsafe fn copy_plane_into_vec(
    src_ptr: *const u8,
    stride: usize,
    width: usize,
    height: usize,
    dst: &mut Vec<u8>,
) {
    for row in 0..height {
        let src_offset = row * stride;
        let slice = unsafe { slice::from_raw_parts(src_ptr.add(src_offset), width) };
        dst.extend_from_slice(slice);
    }
}

fn copy_plane_into_vec_owned(
    src: &[u8],
    stride: usize,
    width: usize,
    height: usize,
    dst: &mut Vec<u8>,
) {
    for row in 0..height {
        let offset = row * stride;
        dst.extend_from_slice(&src[offset..offset + width]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vp8_roundtrip() {
        let mut encoder = VideoEncoder::new(VideoEncoderConfig::default()).expect("encoder");
        let mut decoder = VideoDecoder::new().expect("decoder");
        let width = encoder.cfg.width as usize;
        let height = encoder.cfg.height as usize;
        let uv_width = (width + 1) / 2;
        let uv_height = (height + 1) / 2;
        let y = vec![0x80; width * height];
        let u = vec![0x80; uv_width * uv_height];
        let v = vec![0x80; uv_width * uv_height];
        let frames = encoder
            .encode(
                I420Borrowed {
                    y: &y,
                    u: &u,
                    v: &v,
                    stride_y: width,
                    stride_u: uv_width,
                    stride_v: uv_width,
                },
                0,
                true,
            )
            .expect("encode");
        assert!(!frames.is_empty());
        let mut decoded = Vec::new();
        for packet in &frames {
            let mut output = decoder.decode(packet).expect("decode");
            decoded.append(&mut output);
        }
        assert!(!decoded.is_empty());
        assert_eq!(decoded[0].width, encoder.cfg.width);
        assert_eq!(decoded[0].height, encoder.cfg.height);
        assert_eq!(decoded[0].codec, VideoCodec::RawI420);
    }

    #[test]
    fn raw_passthrough() {
        let mut encoder = VideoEncoder::new(VideoEncoderConfig {
            codec: VideoCodec::RawI420,
            ..VideoEncoderConfig::default()
        })
        .expect("raw encoder");
        let mut decoder = VideoDecoder::new().expect("decoder");
        let width = encoder.cfg.width as usize;
        let height = encoder.cfg.height as usize;
        let uv_width = (width + 1) / 2;
        let uv_height = (height + 1) / 2;
        let y: Vec<u8> = (0..width * height).map(|v| (v % 255) as u8).collect();
        let u = vec![0x90; uv_width * uv_height];
        let v = vec![0x70; uv_width * uv_height];
        let frames = encoder
            .encode(
                I420Borrowed {
                    y: &y,
                    u: &u,
                    v: &v,
                    stride_y: width,
                    stride_u: uv_width,
                    stride_v: uv_width,
                },
                777,
                false,
            )
            .expect("encode");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].codec, VideoCodec::RawI420);
        assert!(frames[0].keyframe);
        let decoded = decoder.decode(&frames[0]).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(
            decoded[0].data.len(),
            width * height + uv_width * uv_height * 2
        );
    }
}
