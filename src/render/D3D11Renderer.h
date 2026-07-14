// Adapted from the user-owned AIM TRAINER reference for this project.
#pragma once

#include "render/RenderTypes.h"

#include <d3d11.h>
#include <cstdint>
#include <string>
#include <wrl/client.h>
#include <vector>
#include <windows.h>

enum class RenderStatus {
    Ok,
    Occluded,
    DeviceLost,
    Failed
};

struct RenderFrameResult {
    RenderStatus status = RenderStatus::Failed;
    bool target_drawn = false;
};

class D3D11Renderer {
public:
    bool Initialize(HWND hwnd);
    [[nodiscard]] bool Resize(UINT width, UINT height);
    [[nodiscard]] RenderFrameResult Render(double target_rel_x_counts,
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
                                      const RenderUiLayer& ui_layer);

private:
    bool CreateRenderTarget();
    bool CreatePipeline();
    [[nodiscard]] RenderStatus DrawVertices(const std::vector<RenderVertex>& vertices);
    [[nodiscard]] static bool IsDeviceLost(HRESULT hr);

    HWND hwnd_ = nullptr;
    UINT width_ = 1;
    UINT height_ = 1;
    Microsoft::WRL::ComPtr<ID3D11Device> device_;
    Microsoft::WRL::ComPtr<ID3D11DeviceContext> context_;
    Microsoft::WRL::ComPtr<IDXGISwapChain> swap_chain_;
    Microsoft::WRL::ComPtr<ID3D11RenderTargetView> render_target_;
    Microsoft::WRL::ComPtr<ID3D11VertexShader> vertex_shader_;
    Microsoft::WRL::ComPtr<ID3D11PixelShader> pixel_shader_;
    Microsoft::WRL::ComPtr<ID3D11InputLayout> input_layout_;
    Microsoft::WRL::ComPtr<ID3D11RasterizerState> rasterizer_state_;
    Microsoft::WRL::ComPtr<ID3D11BlendState> blend_state_;
    Microsoft::WRL::ComPtr<ID3D11Buffer> vertex_buffer_;
    UINT vertex_buffer_capacity_ = 0;
};
