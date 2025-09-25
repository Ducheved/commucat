#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use crate::{MediaError, MediaResult};
use env_libvpx_sys as vpx;
use std::mem::MaybeUninit;
use std::os::raw::c_int;
use std::ptr;
use std::slice;

#[derive(Debug, Clone)]
pub struct VideoEncoderConfig {
    pub width: u32,
    pub height: u32,
    pub timebase_num: u32,
    pub timebase_den: u32,
    pub bitrate: u32,
    pub min_quantizer: u32,
    pub max_quantizer: u32,
    pub threads: u8,
}

impl Default for VideoEncoderConfig {
    fn default() -> Self {
        Self {
            width: 640,
            height: 360,
            timebase_num: 1,
            timebase_den: 30,
            bitrate: 900,
            min_quantizer: 2,
            max_quantizer: 32,
            threads: 2,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VideoEncoder {
    ctx: vpx::vpx_codec_ctx_t,
    cfg: vpx::vpx_codec_enc_cfg_t,
    pts: u64,
}

#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub timestamp: u64,
    pub keyframe: bool,
    pub data: Vec<u8>,
}

pub struct I420Borrowed<'a> {
    pub y: &'a [u8],
    pub u: &'a [u8],
    pub v: &'a [u8],
    pub stride_y: usize,
    pub stride_u: usize,
    pub stride_v: usize,
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
        unsafe {
            let iface = vpx::vpx_codec_vp8_cx();
            if iface.is_null() {
                return Err(MediaError::Unsupported);
            }
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
            cfg.rc_target_bitrate = config.bitrate as c_int;
            cfg.rc_min_quantizer = config.min_quantizer as c_int;
            cfg.rc_max_quantizer = config.max_quantizer as c_int;
            cfg.g_threads = config.threads as c_int;
            cfg.g_lag_in_frames = 0;
            cfg.g_pass = vpx::vpx_enc_pass::VPX_RC_ONE_PASS;
            cfg.rc_end_usage = vpx::vpx_rc_mode::VPX_VBR;
            cfg.kf_mode = vpx::vpx_kf_mode::VPX_KF_AUTO;

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
                pts: 0,
            })
        }
    }

    pub fn encode(
        &mut self,
        frame: I420Borrowed<'_>,
        timestamp: u64,
        force_keyframe: bool,
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

            let flags = if force_keyframe {
                vpx::VPX_EFLAG_FORCE_KF as u64
            } else {
                0
            };
            let res = vpx::vpx_codec_encode(
                &mut self.ctx,
                img,
                timestamp,
                1,
                flags,
                vpx::VPX_DL_REALTIME as u64,
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
                    let data = slice::from_raw_parts(frame_pkt.buf as *const u8, frame_pkt.sz);
                    let keyframe = frame_pkt.flags & vpx::VPX_FRAME_IS_KEY as u32 != 0;
                    output.push(VideoFrame {
                        timestamp,
                        keyframe,
                        data: data.to_vec(),
                    });
                }
            }
            self.pts = self.pts.wrapping_add(1);
            Ok(output)
        }
    }
}

impl Drop for VideoEncoder {
    fn drop(&mut self) {
        unsafe {
            let _ = vpx::vpx_codec_destroy(&mut self.ctx);
        }
    }
}

#[derive(Debug, Clone)]
pub struct VideoDecoder {
    ctx: vpx::vpx_codec_ctx_t,
}

#[derive(Debug, Clone)]
pub struct DecodedFrame {
    pub timestamp: u64,
    pub width: u32,
    pub height: u32,
    pub data: Vec<u8>,
}

impl VideoDecoder {
    pub fn new() -> MediaResult<Self> {
        unsafe {
            let iface = vpx::vpx_codec_vp8_dx();
            if iface.is_null() {
                return Err(MediaError::Unsupported);
            }
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
            })
        }
    }

    pub fn decode(&mut self, data: &[u8], timestamp: u64) -> MediaResult<Vec<DecodedFrame>> {
        unsafe {
            let res = vpx::vpx_codec_decode(
                &mut self.ctx,
                data.as_ptr(),
                data.len() as u32,
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
                    timestamp,
                    width,
                    height,
                    data: buffer,
                });
            }
            Ok(frames)
        }
    }
}

impl Drop for VideoDecoder {
    fn drop(&mut self) {
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
        ptr::copy_nonoverlapping(src.as_ptr().add(src_offset), dst_ptr.add(dst_offset), width);
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
        let slice = slice::from_raw_parts(src_ptr.add(src_offset), width);
        dst.extend_from_slice(slice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vp8_roundtrip() {
        let config = VideoEncoderConfig::default();
        let mut encoder = VideoEncoder::new(config.clone()).expect("encoder");
        let mut decoder = VideoDecoder::new().expect("decoder");
        let width = config.width as usize;
        let height = config.height as usize;
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
        for packet in frames {
            let mut output = decoder
                .decode(&packet.data, packet.timestamp)
                .expect("decode");
            decoded.append(&mut output);
        }
        assert!(!decoded.is_empty());
        assert_eq!(decoded[0].width, config.width);
        assert_eq!(decoded[0].height, config.height);
    }
}
