// Adapted from the user-owned AIM TRAINER reference for this project.
#include "render/D3D11Renderer.h"

#include "render/CrosshairRenderer.h"
#include "render/GridRenderer.h"
#include "render/HudRenderer.h"
#include "render/TargetRenderer.h"

#include <cstring>
#include <d3dcompiler.h>
#include <vector>

namespace {
const char* kVertexShaderSource = R"(
struct VSInput {
    float2 pos : POSITION;
    float4 color : COLOR;
};

struct VSOutput {
    float4 pos : SV_POSITION;
    float4 color : COLOR;
};

VSOutput main(VSInput input) {
    VSOutput output;
    output.pos = float4(input.pos, 0.0f, 1.0f);
    output.color = input.color;
    return output;
}
)";

const char* kPixelShaderSource = R"(
struct PSInput {
    float4 pos : SV_POSITION;
    float4 color : COLOR;
};

float4 main(PSInput input) : SV_TARGET {
    return input.color;
}
)";
}

bool D3D11Renderer::Initialize(HWND hwnd) {
    hwnd_ = hwnd;

    // Device recreation must not retain a dynamic vertex buffer owned by the
    // previous D3D device. WRL output operators replace the other interfaces,
    // but this buffer is grown lazily by DrawVertices.
    vertex_buffer_.Reset();
    vertex_buffer_capacity_ = 0;
    render_target_.Reset();
    blend_state_.Reset();

    RECT rect{};
    GetClientRect(hwnd_, &rect);
    width_ = static_cast<UINT>(rect.right - rect.left);
    height_ = static_cast<UINT>(rect.bottom - rect.top);

    DXGI_SWAP_CHAIN_DESC desc{};
    desc.BufferCount = 2;
    desc.BufferDesc.Width = width_;
    desc.BufferDesc.Height = height_;
    desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.OutputWindow = hwnd_;
    desc.SampleDesc.Count = 1;
    desc.Windowed = TRUE;
    desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT flags = 0;
#if defined(_DEBUG)
    flags |= D3D11_CREATE_DEVICE_DEBUG;
#endif

    D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL created_level{};
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr,
                                               D3D_DRIVER_TYPE_HARDWARE,
                                               nullptr,
                                               flags,
                                               levels,
                                               2,
                                               D3D11_SDK_VERSION,
                                               &desc,
                                               &swap_chain_,
                                               &device_,
                                               &created_level,
                                               &context_);
    if (FAILED(hr)) {
        hr = D3D11CreateDeviceAndSwapChain(nullptr,
                                           D3D_DRIVER_TYPE_WARP,
                                           nullptr,
                                           0,
                                           levels,
                                           2,
                                           D3D11_SDK_VERSION,
                                           &desc,
                                           &swap_chain_,
                                           &device_,
                                           &created_level,
                                           &context_);
    }
    if (FAILED(hr)) {
        return false;
    }

    return CreateRenderTarget() && CreatePipeline();
}

bool D3D11Renderer::Resize(UINT width, UINT height) {
    if (!swap_chain_ || width == 0 || height == 0) {
        return true;
    }

    width_ = width;
    height_ = height;
    context_->OMSetRenderTargets(0, nullptr, nullptr);
    render_target_.Reset();
    context_->Flush();

    const HRESULT hr = swap_chain_->ResizeBuffers(0, width_, height_, DXGI_FORMAT_UNKNOWN, 0);
    if (FAILED(hr)) {
        return false;
    }
    return CreateRenderTarget();
}

RenderFrameResult D3D11Renderer::Render(double target_rel_x_counts,
                                   double target_rel_y_counts,
                                   double target_radius_counts,
                                   std::int64_t camera_x_counts,
                                   std::int64_t camera_y_counts,
                                   double radians_per_count,
                                   double crosshair_scale,
                                   bool draw_crosshair,
                                   bool enemy_highlight_enabled,
                                   bool inside_target,
                                   bool target_visible,
                                   float target_visual_strength,
                                   bool draw_world_grid,
                                   const RenderUiLayer& ui_layer) {
    if (!context_ || !render_target_) {
        return {RenderStatus::Failed, false};
    }

    const FLOAT clear_color[4] = {0.025f, 0.029f, 0.035f, 1.0f};
    context_->ClearRenderTargetView(render_target_.Get(), clear_color);
    context_->OMSetRenderTargets(1, render_target_.GetAddressOf(), nullptr);

    D3D11_VIEWPORT viewport{};
    viewport.TopLeftX = 0.0f;
    viewport.TopLeftY = 0.0f;
    viewport.Width = static_cast<FLOAT>(width_);
    viewport.Height = static_cast<FLOAT>(height_);
    viewport.MinDepth = 0.0f;
    viewport.MaxDepth = 1.0f;
    context_->RSSetViewports(1, &viewport);

    std::vector<RenderVertex> vertices;
    vertices.reserve(4096);
    if (draw_world_grid && !GridRenderer::AppendWorldGrid(
            vertices, camera_x_counts, camera_y_counts, radians_per_count, width_, height_)) {
        return {RenderStatus::Failed, false};
    }
    bool target_drawn = false;
    if (target_visible) {
        const auto geometry = TargetRenderer::AppendTarget(
            vertices, target_rel_x_counts, target_rel_y_counts, target_radius_counts,
            radians_per_count, width_, height_, inside_target && enemy_highlight_enabled,
            target_visual_strength);
        if (geometry == TargetRenderer::GeometryStatus::Invalid) {
            return {RenderStatus::Failed, false};
        }
        target_drawn = geometry == TargetRenderer::GeometryStatus::Drawable;
    }
    if (draw_crosshair) {
        CrosshairRenderer::AppendCrosshair(vertices, width_, height_, crosshair_scale);
    }
    for (const RenderRect& rect : ui_layer.rects) {
        HudRenderer::AppendRect(vertices, rect);
    }
    for (const RenderCrosshairPreview& preview : ui_layer.crosshair_previews) {
        CrosshairRenderer::AppendCrosshairAt(vertices, width_, height_, preview.scale, preview.x, preview.y);
    }
    for (const RenderText& text : ui_layer.texts) {
        HudRenderer::AppendText(vertices, text);
    }
    const auto draw_status = DrawVertices(vertices);
    if (draw_status != RenderStatus::Ok) return {draw_status, target_drawn};

    const HRESULT hr = swap_chain_->Present(0, 0);
    if (hr == S_OK) return {RenderStatus::Ok, target_drawn};
    if (hr == DXGI_STATUS_OCCLUDED) return {RenderStatus::Occluded, target_drawn};
    return {IsDeviceLost(hr) ? RenderStatus::DeviceLost : RenderStatus::Failed, target_drawn};
}

bool D3D11Renderer::CreateRenderTarget() {
    Microsoft::WRL::ComPtr<ID3D11Texture2D> back_buffer;
    HRESULT hr = swap_chain_->GetBuffer(0, IID_PPV_ARGS(&back_buffer));
    if (FAILED(hr)) {
        return false;
    }
    hr = device_->CreateRenderTargetView(back_buffer.Get(), nullptr, &render_target_);
    return SUCCEEDED(hr);
}

bool D3D11Renderer::CreatePipeline() {
    Microsoft::WRL::ComPtr<ID3DBlob> vs_blob;
    Microsoft::WRL::ComPtr<ID3DBlob> ps_blob;
    Microsoft::WRL::ComPtr<ID3DBlob> errors;

    HRESULT hr = D3DCompile(kVertexShaderSource,
                            strlen(kVertexShaderSource),
                            nullptr,
                            nullptr,
                            nullptr,
                            "main",
                            "vs_4_0",
                            0,
                            0,
                            &vs_blob,
                            &errors);
    if (FAILED(hr)) {
        return false;
    }

    hr = D3DCompile(kPixelShaderSource,
                    strlen(kPixelShaderSource),
                    nullptr,
                    nullptr,
                    nullptr,
                    "main",
                    "ps_4_0",
                    0,
                    0,
                    &ps_blob,
                    &errors);
    if (FAILED(hr)) {
        return false;
    }

    hr = device_->CreateVertexShader(vs_blob->GetBufferPointer(), vs_blob->GetBufferSize(), nullptr, &vertex_shader_);
    if (FAILED(hr)) {
        return false;
    }

    hr = device_->CreatePixelShader(ps_blob->GetBufferPointer(), ps_blob->GetBufferSize(), nullptr, &pixel_shader_);
    if (FAILED(hr)) {
        return false;
    }

    D3D11_INPUT_ELEMENT_DESC layout[] = {
        {"POSITION", 0, DXGI_FORMAT_R32G32_FLOAT, 0, 0, D3D11_INPUT_PER_VERTEX_DATA, 0},
        {"COLOR", 0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, sizeof(float) * 2, D3D11_INPUT_PER_VERTEX_DATA, 0},
    };
    hr = device_->CreateInputLayout(layout,
                                    2,
                                    vs_blob->GetBufferPointer(),
                                    vs_blob->GetBufferSize(),
                                    &input_layout_);
    if (FAILED(hr)) {
        return false;
    }

    D3D11_RASTERIZER_DESC rasterizer_desc{};
    rasterizer_desc.FillMode = D3D11_FILL_SOLID;
    rasterizer_desc.CullMode = D3D11_CULL_NONE;
    rasterizer_desc.DepthClipEnable = TRUE;
    hr = device_->CreateRasterizerState(&rasterizer_desc, &rasterizer_state_);
    if (FAILED(hr)) {
        return false;
    }

    D3D11_BLEND_DESC blend_desc{};
    auto& target_blend = blend_desc.RenderTarget[0];
    target_blend.BlendEnable = TRUE;
    target_blend.SrcBlend = D3D11_BLEND_SRC_ALPHA;
    target_blend.DestBlend = D3D11_BLEND_INV_SRC_ALPHA;
    target_blend.BlendOp = D3D11_BLEND_OP_ADD;
    target_blend.SrcBlendAlpha = D3D11_BLEND_ONE;
    target_blend.DestBlendAlpha = D3D11_BLEND_INV_SRC_ALPHA;
    target_blend.BlendOpAlpha = D3D11_BLEND_OP_ADD;
    target_blend.RenderTargetWriteMask = D3D11_COLOR_WRITE_ENABLE_ALL;
    hr = device_->CreateBlendState(&blend_desc, &blend_state_);
    if (FAILED(hr)) {
        return false;
    }

    context_->IASetInputLayout(input_layout_.Get());
    context_->VSSetShader(vertex_shader_.Get(), nullptr, 0);
    context_->PSSetShader(pixel_shader_.Get(), nullptr, 0);
    context_->RSSetState(rasterizer_state_.Get());
    context_->OMSetBlendState(blend_state_.Get(), nullptr, 0xffffffffU);
    return true;
}

RenderStatus D3D11Renderer::DrawVertices(const std::vector<RenderVertex>& vertices) {
    if (vertices.empty()) {
        return RenderStatus::Ok;
    }

    const UINT needed = static_cast<UINT>(vertices.size());
    if (!vertex_buffer_ || needed > vertex_buffer_capacity_) {
        vertex_buffer_capacity_ = ((needed + 255) / 256) * 256;

        D3D11_BUFFER_DESC desc{};
        desc.ByteWidth = vertex_buffer_capacity_ * sizeof(RenderVertex);
        desc.Usage = D3D11_USAGE_DYNAMIC;
        desc.BindFlags = D3D11_BIND_VERTEX_BUFFER;
        desc.CPUAccessFlags = D3D11_CPU_ACCESS_WRITE;

        const HRESULT hr = device_->CreateBuffer(&desc, nullptr, &vertex_buffer_);
        if (FAILED(hr)) return IsDeviceLost(hr) ? RenderStatus::DeviceLost : RenderStatus::Failed;
    }

    D3D11_MAPPED_SUBRESOURCE mapped{};
    const HRESULT map = context_->Map(vertex_buffer_.Get(), 0, D3D11_MAP_WRITE_DISCARD, 0, &mapped);
    if (FAILED(map)) return IsDeviceLost(map) ? RenderStatus::DeviceLost : RenderStatus::Failed;
    std::memcpy(mapped.pData, vertices.data(), vertices.size() * sizeof(RenderVertex));
    context_->Unmap(vertex_buffer_.Get(), 0);

    const UINT stride = sizeof(RenderVertex);
    const UINT offset = 0;
    context_->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    context_->IASetVertexBuffers(0, 1, vertex_buffer_.GetAddressOf(), &stride, &offset);
    context_->IASetInputLayout(input_layout_.Get());
    context_->VSSetShader(vertex_shader_.Get(), nullptr, 0);
    context_->PSSetShader(pixel_shader_.Get(), nullptr, 0);
    context_->RSSetState(rasterizer_state_.Get());
    context_->OMSetBlendState(blend_state_.Get(), nullptr, 0xffffffffU);
    context_->Draw(static_cast<UINT>(vertices.size()), 0);
    return RenderStatus::Ok;
}

bool D3D11Renderer::IsDeviceLost(HRESULT hr) {
    return hr == DXGI_ERROR_DEVICE_REMOVED ||
           hr == DXGI_ERROR_DEVICE_RESET ||
           hr == DXGI_ERROR_DRIVER_INTERNAL_ERROR;
}
