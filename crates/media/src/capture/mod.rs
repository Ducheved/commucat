use crate::{MediaError, MediaResult};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::{Sample, SampleFormat, SampleRate, Stream, StreamConfig};
use std::sync::{Arc, Mutex};
use tracing::{debug, warn};

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
    pub fn start<F>(config: AudioCaptureConfig, handler: F) -> MediaResult<Self>
    where
        F: FnMut(Vec<i16>) + Send + 'static,
    {
        let host = cpal::default_host();
        let device = if let Some(name) = config.device.clone() {
            host
                .input_devices()
                .map_err(|err| MediaError::Io(format!("device enumeration failed: {err}")))?
                .find(|dev| dev.name().map(|dev_name| dev_name == name).unwrap_or(false))
                .ok_or_else(|| MediaError::InvalidConfig("input device not found"))?
        } else {
            host
                .default_input_device()
                .ok_or_else(|| MediaError::InvalidConfig("no default input device"))?
        };

        let supported = device
            .supported_input_configs()
            .map_err(|err| MediaError::Io(format!("input configuration query failed: {err}")))?
            .find(|range| {
                range.channels() == config.channels as u16
                    && range.min_sample_rate() <= SampleRate(config.sample_rate)
                    && range.max_sample_rate() >= SampleRate(config.sample_rate)
            })
            .ok_or_else(|| MediaError::InvalidConfig("requested capture format unsupported"))?;

        let stream_config: StreamConfig = supported
            .with_sample_rate(SampleRate(config.sample_rate))
            .config();
        let frame_samples = crate::audio::frame_samples_per_channel(config.sample_rate, config.frame_duration_ms)?
            * usize::from(stream_config.channels);

        let buffer = Arc::new(Mutex::new(Vec::with_capacity(frame_samples * 2)));
        let handler: Arc<Mutex<Box<dyn FnMut(Vec<i16>) + Send>>> = Arc::new(Mutex::new(Box::new(handler)));
        let sample_format = supported.sample_format();

        let stream = match sample_format {
            SampleFormat::F32 => build_stream::<f32>(&device, &stream_config, frame_samples, &buffer, &handler)?,
            SampleFormat::I16 => build_stream::<i16>(&device, &stream_config, frame_samples, &buffer, &handler)?,
            SampleFormat::U16 => build_stream::<u16>(&device, &stream_config, frame_samples, &buffer, &handler)?,
            other => {
                return Err(MediaError::InvalidConfig(match other {
                    SampleFormat::U8 => "u8 capture format unsupported",
                    _ => "unsupported capture sample format",
                }))
            }
        };

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

fn build_stream<T>(
    device: &cpal::Device,
    config: &StreamConfig,
    frame_samples: usize,
    buffer: &Arc<Mutex<Vec<i16>>>,
    handler: &Arc<Mutex<Box<dyn FnMut(Vec<i16>) + Send>>>,
) -> MediaResult<Stream>
where
    T: Sample,
{
    let buffer = Arc::clone(buffer);
    let handler = Arc::clone(handler);
    let stream = device
        .build_input_stream(
            config,
            move |data: &[T], _| {
                if let Err(err) = process_samples(data, frame_samples, &buffer, &handler) {
                    warn!("audio capture processing failed: {err}");
                }
            },
            move |err| warn!("audio capture stream error: {err}"),
            None,
        )
        .map_err(|err| MediaError::Io(format!("build input stream failed: {err}")))?;
    stream
        .play()
        .map_err(|err| MediaError::Io(format!("failed to start capture stream: {err}")))?;
    Ok(stream)
}

fn process_samples<T: Sample>(
    data: &[T],
    frame_samples: usize,
    buffer: &Arc<Mutex<Vec<i16>>>,
    handler: &Arc<Mutex<Box<dyn FnMut(Vec<i16>) + Send>>>,
) -> MediaResult<()> {
    let mut guard = buffer
        .lock()
        .map_err(|_| MediaError::Io("audio buffer poisoned".to_string()))?;
    guard.extend(data.iter().map(|sample| sample.to_i16()));
    while guard.len() >= frame_samples {
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
