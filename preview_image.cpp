#include "preview_image.h"
#include <windows.h>
#include <wincodec.h>
#include <openssl/crypto.h>
#include <algorithm>

namespace kasa::preview {
namespace {
template<class T> struct Com {
    T* p = nullptr;
    ~Com() { if (p) p->Release(); }
    T** out() { return &p; }
    T* operator->() const { return p; }
};
struct Apartment {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    ~Apartment() { if (SUCCEEDED(hr)) CoUninitialize(); }
    bool usable() const { return SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE; }
};
bool signature(std::span<const unsigned char> b, Kind kind) {
    constexpr unsigned char png[] = {137,80,78,71,13,10,26,10};
    if (kind == Kind::Png) return b.size() >= 8 && std::equal(std::begin(png),std::end(png),b.begin());
    return b.size() >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff;
}
}
ImagePreview::~ImagePreview() {
    if (!pixels_.empty()) OPENSSL_cleanse(pixels_.data(),pixels_.size());
}
std::unique_ptr<ImagePreview> ImagePreview::create(std::unique_ptr<AuthenticatedPreview> owner,
                                                  Kind expected, ImageStatus& status) noexcept {
    status = ImageStatus::InvalidInput;
    if (!owner) return nullptr;
    if (expected != Kind::Png && expected != Kind::Jpeg) { status=ImageStatus::Unsupported; return nullptr; }
    const auto bytes=owner->bytes();
    if (bytes.size()>max_encrypted_bytes) { status=ImageStatus::TooLarge; return nullptr; }
    status=ImageStatus::InvalidImage;
    if (!signature(bytes,expected)) return nullptr;
    try {
        Apartment apartment;
        status=ImageStatus::DecoderUnavailable;
        if (!apartment.usable()) return nullptr;
        Com<IWICImagingFactory> factory;
        if (FAILED(CoCreateInstance(CLSID_WICImagingFactory,nullptr,CLSCTX_INPROC_SERVER,
                                    IID_IWICImagingFactory,reinterpret_cast<void**>(factory.out())))) return nullptr;
        Com<IWICStream> stream;
        if (FAILED(factory->CreateStream(stream.out()))) return nullptr;
        // WIC requires a mutable pointer; this stream is used only by a decoder.
        // owner outlives stream/decoder and wipes the encoded plaintext afterwards.
        if (FAILED(stream->InitializeFromMemory(const_cast<BYTE*>(bytes.data()),static_cast<DWORD>(bytes.size())))) return nullptr;
        Com<IWICBitmapDecoder> decoder;
        const auto& clsid=expected==Kind::Png ? CLSID_WICPngDecoder : CLSID_WICJpegDecoder;
        if (FAILED(CoCreateInstance(clsid,nullptr,CLSCTX_INPROC_SERVER,IID_IWICBitmapDecoder,
                                    reinterpret_cast<void**>(decoder.out())))) return nullptr;
        status=ImageStatus::InvalidImage;
        if (FAILED(decoder->Initialize(stream.p,WICDecodeMetadataCacheOnDemand))) return nullptr;
        GUID format{};
        const auto& wanted=expected==Kind::Png ? GUID_ContainerFormatPng : GUID_ContainerFormatJpeg;
        if (FAILED(decoder->GetContainerFormat(&format)) || !IsEqualGUID(format,wanted)) return nullptr;
        UINT frames=0;
        if (FAILED(decoder->GetFrameCount(&frames)) || frames!=1) return nullptr;
        Com<IWICBitmapFrameDecode> frame;
        if (FAILED(decoder->GetFrame(0,frame.out()))) return nullptr;
        UINT width=0,height=0;
        if (FAILED(frame->GetSize(&width,&height))) return nullptr;
        if (!image_dimensions_allowed(width,height)) { status=ImageStatus::TooLarge; return nullptr; }
        Com<IWICFormatConverter> converter;
        if (FAILED(factory->CreateFormatConverter(converter.out())) ||
            FAILED(converter->Initialize(frame.p,GUID_WICPixelFormat32bppRGBA,WICBitmapDitherTypeNone,
                                          nullptr,0.0,WICBitmapPaletteTypeCustom))) return nullptr;
        auto image=std::unique_ptr<ImagePreview>(new ImagePreview);
        image->width_=width;image->height_=height;
        // Limits above bound multiplication to 80,000,000 bytes, within UINT.
        image->pixels_.resize(static_cast<std::size_t>(width)*height*4);
        if (FAILED(converter->CopyPixels(nullptr,width*4,static_cast<UINT>(image->pixels_.size()),image->pixels_.data()))) return nullptr;
        status=ImageStatus::Ready;
        return image;
    } catch (...) { status=ImageStatus::InvalidImage; return nullptr; }
}
}
