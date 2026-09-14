#include "preview_image.h"
#include <windows.h>
#include <wincodec.h>
#include <fstream>
#include <iostream>
#include <chrono>
#include <type_traits>
#include <stdexcept>
template<class T> struct Com { T* p=nullptr; ~Com(){if(p)p->Release();} T** out(){return &p;} T* operator->(){return p;} };
static void ok(HRESULT hr) { if(FAILED(hr))throw std::runtime_error("fixture encoder failed"); }
static std::vector<unsigned char> fixture(bool png) {
    Com<IWICImagingFactory> factory;
    ok(CoCreateInstance(CLSID_WICImagingFactory,nullptr,CLSCTX_INPROC_SERVER,IID_IWICImagingFactory,reinterpret_cast<void**>(factory.out())));
    Com<IStream> stream;ok(CreateStreamOnHGlobal(nullptr,TRUE,stream.out()));
    Com<IWICBitmapEncoder> encoder;
    ok(factory->CreateEncoder(png?GUID_ContainerFormatPng:GUID_ContainerFormatJpeg,nullptr,encoder.out()));
    ok(encoder->Initialize(stream.p,WICBitmapEncoderNoCache));
    Com<IWICBitmapFrameEncode> frame;Com<IPropertyBag2> properties;
    ok(encoder->CreateNewFrame(frame.out(),properties.out()));ok(frame->Initialize(properties.p));
    ok(frame->SetSize(2,1));GUID format=GUID_WICPixelFormat24bppBGR;
    ok(frame->SetPixelFormat(&format));
    if(!IsEqualGUID(format,GUID_WICPixelFormat24bppBGR))throw std::runtime_error("unexpected pixel format");
    BYTE pixels[]={0,0,255,0,255,0};ok(frame->WritePixels(1,6,6,pixels));
    ok(frame->Commit());ok(encoder->Commit());
    STATSTG stat{};ok(stream->Stat(&stat,STATFLAG_NONAME));
    std::vector<unsigned char> bytes(static_cast<size_t>(stat.cbSize.QuadPart));
    LARGE_INTEGER zero{};ok(stream->Seek(zero,STREAM_SEEK_SET,nullptr));
    ULONG read=0;ok(stream->Read(bytes.data(),static_cast<ULONG>(bytes.size()),&read));
    if(read!=bytes.size())throw std::runtime_error("short fixture read");return bytes;
}
int main() {
    using namespace kasa::preview;namespace fs=std::filesystem;
    static_assert(!std::is_copy_constructible_v<ImagePreview>);
    int checks=0,failures=0;
    auto check=[&](bool pass,const char* name){++checks;if(!pass){++failures;std::cerr<<"FAIL "<<name<<'\n';}};
    const auto hr=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);if(FAILED(hr))return 2;
    struct Uninit{~Uninit(){CoUninitialize();}}uninit;
    const auto root=fs::temp_directory_path()/("kasa-image-test-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directory(root);
    struct Cleanup{fs::path p;~Cleanup(){std::error_code ec;fs::remove_all(p,ec);}}cleanup{root};
    encryption_engine engine;int serial=0;
    auto owner=[&](const std::vector<unsigned char>& bytes){
        const auto src=root/(std::to_string(++serial)+".bin");const auto enc=fs::path(src.string()+".kasa");
        {std::ofstream f(src,std::ios::binary);f.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());}
        if(!engine.encrypt_aes256(src,"synthetic-image-test",false,enc))throw std::runtime_error("encrypt failed");
        auto result=engine.decrypt_preview_aes(enc,"synthetic-image-test");
        if(!result.content)throw std::runtime_error("decrypt failed");return std::move(result.content);
    };
    ImageStatus status;
    check(!ImagePreview::create(nullptr,Kind::Png,status)&&status==ImageStatus::InvalidInput,"null input");
    for(bool png:{true,false}) {
        auto bytes=fixture(png);const auto kind=png?Kind::Png:Kind::Jpeg;
        auto image=ImagePreview::create(owner(bytes),kind,status);
        check(image&&status==ImageStatus::Ready,"valid image under STA apartment");
        check(image&&image->width()==2&&image->height()==1&&image->pixels().size()==8,"RGBA dimensions");
        if(png)check(image&&image->pixels()[0]==255&&image->pixels()[1]==0&&image->pixels()[3]==255,"PNG pixel conversion");
        check(!ImagePreview::create(owner(bytes),png?Kind::Jpeg:Kind::Png,status)&&status==ImageStatus::InvalidImage,"extension mismatch");
        check(!ImagePreview::create(owner(bytes),Kind::Text,status)&&status==ImageStatus::Unsupported,"unsupported route");
        bytes.resize(8);
        check(!ImagePreview::create(owner(bytes),kind,status)&&status==ImageStatus::InvalidImage,"truncated image");
    }
    check(!ImagePreview::create(owner({}),Kind::Png,status)&&status==ImageStatus::InvalidImage,"empty content");
    check(!ImagePreview::create(owner({'n','o','t',' ','p','n','g'}),Kind::Png,status),"non-image");
    auto oversized=fixture(true);
    // Replace IHDR width with 16,385, then recompute its CRC. Pixel data is tiny:
    // the decoder must reject dimensions before allocating/copying a bitmap.
    oversized[16]=0;oversized[17]=0;oversized[18]=0x40;oversized[19]=1;
    std::uint32_t crc=0xffffffff;
    for(std::size_t i=12;i<29;++i){crc^=oversized[i];for(int bit=0;bit<8;++bit)crc=(crc>>1)^((crc&1)?0xedb88320:0);}
    crc^=0xffffffff;
    for(int i=0;i<4;++i)oversized[29+i]=static_cast<unsigned char>(crc>>(24-i*8));
    check(!ImagePreview::create(owner(oversized),Kind::Png,status)&&status==ImageStatus::TooLarge,"decoder dimension rejection");
    check(image_dimensions_allowed(4000,5000)&&!image_dimensions_allowed(4001,5000),"pixel boundary");
    check(!image_dimensions_allowed(16385,1)&&!image_dimensions_allowed(0,1),"dimension boundary");
    check(std::distance(fs::directory_iterator(root),fs::directory_iterator{})==serial*2,"no decoder disk output in fixture directory");
    std::cout<<checks<<" checks, "<<failures<<" failures\n";return failures?1:0;
}
