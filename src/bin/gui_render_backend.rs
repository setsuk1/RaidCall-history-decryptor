//! Graphics selection isolated from the GUI and decryption implementation.
//!
//! Windows: Vulkan -> Direct3D 12 (WARP supported) -> wgpu OpenGL/GLES.
//! Linux: Vulkan when a plausible adapter is available, otherwise legacy Glow.
//! Low-version OpenGL 1.1 is never selected by wgpu as a usable GL adapter.

use eframe::egui;
use egui_wgpu::{wgpu, WgpuConfiguration, WgpuSetup, WgpuSetupCreateNew};
use std::sync::Arc;

// eframe 0.31's wgpu renderer requests an 8192px texture limit by default.
// Ignore adapters which cannot meet its basic device requirements.
// Surface compatibility is checked separately when the native window exists.
const REQUIRED_MAX_TEXTURE_DIMENSION: u32 = 8192;

fn supports_gui(adapter: &wgpu::Adapter, surface: Option<&wgpu::Surface<'_>>) -> bool {
    adapter.limits().max_texture_dimension_2d >= REQUIRED_MAX_TEXTURE_DIMENSION
        && surface.map_or(true, |surface| {
            !surface.get_capabilities(adapter).formats.is_empty()
        })
}

// API preference is absolute: a usable Vulkan adapter precedes DX12, and
// DX12 precedes GL. Choosing Vulkan is not a claim it benchmarks faster.
fn backend_enabled(backends: wgpu::Backends, backend: wgpu::Backend) -> bool {
    match backend {
        wgpu::Backend::Vulkan => backends.contains(wgpu::Backends::VULKAN),
        wgpu::Backend::Dx12 => backends.contains(wgpu::Backends::DX12),
        wgpu::Backend::Gl => backends.contains(wgpu::Backends::GL),
        _ => false,
    }
}

fn backend_priority(backend: wgpu::Backend) -> u8 {
    match backend {
        wgpu::Backend::Vulkan => 0,
        wgpu::Backend::Dx12 => 1,
        wgpu::Backend::Gl => 2,
        _ => 3,
    }
}

fn device_priority(backend: wgpu::Backend, device: wgpu::DeviceType) -> u8 {
    if backend == wgpu::Backend::Dx12 {
        // Preserve the previous DX12 behavior for headless Windows VMs:
        // prefer Microsoft WARP's CPU rasterizer over other DX12 adapters.
        match device {
            wgpu::DeviceType::Cpu => 0,
            wgpu::DeviceType::VirtualGpu => 1,
            wgpu::DeviceType::IntegratedGpu => 2,
            wgpu::DeviceType::DiscreteGpu => 3,
            wgpu::DeviceType::Other => 4,
        }
    } else {
        // Prefer hardware within the selected backend; software Vulkan
        // still precedes DX12 because Vulkan is the requested API priority.
        match device {
            wgpu::DeviceType::DiscreteGpu => 0,
            wgpu::DeviceType::IntegratedGpu => 1,
            wgpu::DeviceType::VirtualGpu => 2,
            wgpu::DeviceType::Other => 3,
            wgpu::DeviceType::Cpu => 4,
        }
    }
}

fn wgpu_native_options(backends: wgpu::Backends) -> eframe::NativeOptions {
    let mut setup = WgpuSetupCreateNew::default();
    setup.instance_descriptor.backends = backends;

    // Explicitly choose adapters. wgpu's generic 'high performance'
    // preference alone does not guarantee Vulkan -> DX12 -> GL ordering.
    setup.native_adapter_selector = Some(Arc::new(move |adapters, surface| {
        let best = adapters
            .iter()
            .filter(|a| backend_enabled(backends, a.get_info().backend))
            .filter(|a| supports_gui(a, surface))
            .min_by_key(|a| {
                let info = a.get_info();
                (
                    backend_priority(info.backend),
                    device_priority(info.backend, info.device_type),
                )
            })
            .cloned();
        if let Some(adapter) = &best {
            let info = adapter.get_info();
            eprintln!(
                "RaidCall GUI: selected {:?} renderer, adapter '{}' ({:?})",
                info.backend, info.name, info.device_type
            );
        }
        best.ok_or_else(|| {
            "No suitable Vulkan, D3D12/WARP, or supported OpenGL/GLES adapter \
             can present to this window. The VM's OpenGL 1.1 is insufficient. \
             You can use rc-dat-decrypt.exe without a graphical renderer."
                .to_owned()
        })
    }));

    eframe::NativeOptions {
        renderer: eframe::Renderer::Wgpu,
        wgpu_options: WgpuConfiguration {
            wgpu_setup: WgpuSetup::CreateNew(setup),
            ..Default::default()
        },
        viewport: viewport(),
        ..Default::default()
    }
}

fn viewport() -> egui::ViewportBuilder {
    egui::ViewportBuilder::default()
        .with_inner_size([720.0, 400.0])
        .with_min_inner_size([540.0, 340.0])
        .with_icon(
            eframe::icon_data::from_png_bytes(include_bytes!("../../assets/decryptor-icon.png"))
                .expect("bundled decryptor icon must be a valid PNG"),
        )
}

// On Windows there is no dependency on egui_glow/OpenGL >=2.
// Vulkan is preferred, D3D12 WARP retains the VM software fallback, and
// wgpu OpenGL is used last only if it exposes a suitable modern adapter.
#[cfg(target_os = "windows")]
pub(crate) fn create_native_options() -> eframe::NativeOptions {
    wgpu_native_options(
        wgpu::Backends::VULKAN | wgpu::Backends::DX12 | wgpu::Backends::GL,
    )
}

// Keep the previous Glow behavior on Linux systems without a plausible
// Vulkan adapter. This is only an adapter probe, not a full render test.
#[cfg(target_os = "linux")]
pub(crate) fn create_native_options() -> eframe::NativeOptions {
    let mut descriptor = WgpuSetupCreateNew::default().instance_descriptor;
    descriptor.backends = wgpu::Backends::VULKAN;
    let instance = wgpu::Instance::new(&descriptor);
    let found = instance
        .enumerate_adapters(wgpu::Backends::VULKAN)
        .iter()
        .any(|a| supports_gui(a, None));
    if found {
        eprintln!("RaidCall GUI: Vulkan adapter detected on Linux; using wgpu");
        wgpu_native_options(wgpu::Backends::VULKAN)
    } else {
        eprintln!("RaidCall GUI: no eligible Vulkan adapter; preserving Linux Glow");
        eframe::NativeOptions {
            renderer: eframe::Renderer::Glow,
            viewport: viewport(),
            ..Default::default()
        }
    }
}

