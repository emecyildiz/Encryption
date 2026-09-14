#pragma once
namespace kasa::ui {
struct Rgb { float r,g,b; };
inline constexpr Rgb primary{0.16f,0.31f,0.51f};
inline constexpr Rgb primary_hover{0.19f,0.36f,0.58f};
inline constexpr Rgb primary_active{0.12f,0.25f,0.43f};
inline constexpr Rgb on_primary{1.0f,1.0f,1.0f};
inline constexpr Rgb secondary{0.90f,0.93f,0.96f};
inline constexpr Rgb secondary_hover{0.80f,0.86f,0.93f};
inline constexpr Rgb secondary_active{0.70f,0.78f,0.87f};
inline constexpr Rgb on_secondary{0.13f,0.17f,0.22f};
}
