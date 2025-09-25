use crate::{MediaError, MediaResult};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{SampleFormat, SampleRate, Stream};
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

type CaptureHandler = Arc<Mutex<Box<dyn FnMut(Vec<i16>) + Send>>>;

#[derive(Debug, Clone)]
pub struct AudioCaptureConfig {
    pub device: Option<String>,
    pub sample_rate: u32,
    pub channels: u8,
    pub frame_duration_ms: u16,
}

impl Default for AudioCaptureConfig {
    fn default() -> Self {
        Self {
            device: None,
            sample_rate: 48_000,
            channels: 1,
            frame_duration_ms: 20,
        }
    }
}

pub struct AudioCapture {
    stream: Stream,
    _buffer: Arc<Mutex<Vec<i16>>>,
}

impl AudioCapture {
    /// Starts an input stream and delivers PCM chunks to the provided handler.
    ///
    /// # Errors
    /// Returns `MediaError::InvalidConfig` or `MediaError::Io` when the audio backend
    /// cannot provide the requested configuration.
    pub fn start<F>(config: &AudioCaptureConfig, handler: F) -> MediaResult<Self>
    where
        F: FnMut(Vec<i16>) + Send + 'static,
    {
        let host = cpal::default_host();
        let device = if let Some(name) = config.device.as_ref() {
            host.input_devices()
                .map_err(|err| MediaError::Io(format!("device enumeration failed: {err}")))?
                .find(|dev| {
                    dev.name()
                        .map(|dev_name| dev_name == name.as_str())
                        .unwrap_or(false)
                })
                .ok_or(MediaError::InvalidConfig("input device not found"))?
        } else {
            host.default_input_device()
                .ok_or(MediaError::InvalidConfig("no default input device"))?
        };

        let supported = device
            .supported_input_configs()
            .map_err(|err| MediaError::Io(format!("input configuration query failed: {err}")))?
            .find(|range| {
                range.channels() == u16::from(config.channels)
                    && range.min_sample_rate() <= SampleRate(config.sample_rate)
                    && range.max_sample_rate() >= SampleRate(config.sample_rate)
            })
            .ok_or(MediaError::InvalidConfig(
                "requested capture format unsupported",
            ))?;

        let stream_config = supported
            .with_sample_rate(SampleRate(config.sample_rate))
            .config();
        let frame_samples =
            crate::audio::frame_samples_per_channel(config.sample_rate, config.frame_duration_ms)?
                * usize::from(stream_config.channels);

        let buffer = Arc::new(Mutex::new(Vec::with_capacity(frame_samples * 2)));
        let handler: CaptureHandler = Arc::new(Mutex::new(Box::new(handler)));
        let sample_format = supported.sample_format();

        let stream_result = match sample_format {
            SampleFormat::F32 => {
                let buffer = Arc::clone(&buffer);
                let handler = Arc::clone(&handler);
                device.build_input_stream(
                    &stream_config,
                    move |data: &[f32], _| {
                        if let Err(err) = process_f32(data, frame_samples, &buffer, &handler) {
                            warn!("audio capture processing failed: {err}");
                        }
                    },
                    move |err| warn!("audio capture stream error: {err}"),
                    None,
                )
            }
            SampleFormat::I16 => {
                let buffer = Arc::clone(&buffer);
                let handler = Arc::clone(&handler);
                device.build_input_stream(
                    &stream_config,
                    move |data: &[i16], _| {
                        if let Err(err) = process_i16(data, frame_samples, &buffer, &handler) {
                            warn!("audio capture processing failed: {err}");
                        }
                    },
                    move |err| warn!("audio capture stream error: {err}"),
                    None,
                )
            }
            SampleFormat::U16 => {
                let buffer = Arc::clone(&buffer);
                let handler = Arc::clone(&handler);
                device.build_input_stream(
                    &stream_config,
                    move |data: &[u16], _| {
                        if let Err(err) = process_u16(data, frame_samples, &buffer, &handler) {
                            warn!("audio capture processing failed: {err}");
                        }
                    },
                    move |err| warn!("audio capture stream error: {err}"),
                    None,
                )
            }
            other => {
                return Err(MediaError::InvalidConfig(match other {
                    SampleFormat::U8 => "u8 capture format unsupported",
                    _ => "unsupported capture sample format",
                }))
            }
        };
        let stream = stream_result
            .map_err(|err| MediaError::Io(format!("build input stream failed: {err}")))?;
        stream
            .play()
            .map_err(|err| MediaError::Io(format!("failed to start capture stream: {err}")))?;

        debug!(
            device = %device.name().unwrap_or_else(|_| "unknown".to_string()),
            sample_rate = config.sample_rate,
            channels = config.channels,
            frame_ms = config.frame_duration_ms,
            "audio capture started"
        );

        Ok(Self {
            stream,
            _buffer: buffer,
        })
    }

    pub fn stream(&self) -> &Stream {
        &self.stream
    }
}

fn extend_and_dispatch(
    buffer: &Arc<Mutex<Vec<i16>>>,
    handler: &CaptureHandler,
    frame_samples: usize,
    extend: impl FnOnce(&mut Vec<i16>),
) -> MediaResult<()> {
    let mut guard = buffer
        .lock()
        .map_err(|_| MediaError::Io("audio buffer poisoned".to_string()))?;
    extend(&mut guard);
    loop {
        if guard.len() < frame_samples {
            break;
        }
        let chunk = guard.drain(..frame_samples).collect::<Vec<_>>();
        drop(guard);
        if let Ok(mut callback) = handler.lock() {
            callback(chunk);
        }
        guard = buffer
            .lock()
            .map_err(|_| MediaError::Io("audio buffer poisoned".to_string()))?;
    }
    Ok(())
}

fn process_f32(
    data: &[f32],
    frame_samples: usize,
    buffer: &Arc<Mutex<Vec<i16>>>,
    handler: &CaptureHandler,
) -> MediaResult<()> {
    extend_and_dispatch(buffer, handler, frame_samples, |guard| {
        guard.extend(data.iter().map(|sample| float_to_i16(*sample)));
    })
}

fn process_i16(
    data: &[i16],
    frame_samples: usize,
    buffer: &Arc<Mutex<Vec<i16>>>,
    handler: &CaptureHandler,
) -> MediaResult<()> {
    extend_and_dispatch(buffer, handler, frame_samples, |guard| {
        guard.extend_from_slice(data);
    })
}

fn process_u16(
    data: &[u16],
    frame_samples: usize,
    buffer: &Arc<Mutex<Vec<i16>>>,
    handler: &CaptureHandler,
) -> MediaResult<()> {
    extend_and_dispatch(buffer, handler, frame_samples, |guard| {
        guard.extend(data.iter().map(|sample| u16_to_i16(*sample)));
    })
}

#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn float_to_i16(sample: f32) -> i16 {
    let scaled = (sample.clamp(-1.0, 1.0) * f32::from(i16::MAX)).round();
    if scaled >= f32::from(i16::MAX) {
        i16::MAX
    } else if scaled <= f32::from(i16::MIN) {
        i16::MIN
    } else {
        scaled as i16
    }
}

fn u16_to_i16(sample: u16) -> i16 {
    let centered = i32::from(sample) - ((i32::from(u16::MAX) + 1) / 2);
    i16::try_from(centered).expect("centered sample within i16 range")
}
