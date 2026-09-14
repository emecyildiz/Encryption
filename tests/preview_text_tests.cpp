#include "preview_text.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <type_traits>

static_assert(!std::is_copy_constructible_v<kasa::preview::TextPreview>);
int main() {
    using namespace kasa::preview;
    int checks=0, failures=0;
    auto check=[&](bool ok,const char* name){++checks;if(!ok){++failures;std::cerr<<"FAIL: "<<name<<'\n';}};
    auto test=[&](std::initializer_list<unsigned char> b,TextStatus expected){
        check(validate_text({b.begin(),b.size()}).status==expected,"UTF-8/control classification");};
    const auto ready=TextStatus::Ready, invalid=TextStatus::InvalidUtf8, control=TextStatus::UnsupportedControl;
    test({},ready);test({'a','\t','b','\r','\n'},ready);
    test({0xc3,0xa7,0xc4,0xb1,0xc5,0x9f},ready); // Turkish
    test({0xf0,0x9f,0x98,0x80},ready);
    test({0xef,0xbb,0xbf,'a'},ready);
    test({0xc0,0xaf},invalid);test({0xe0,0x80,0xaf},invalid);test({0xf0,0x80,0x80,0xaf},invalid);
    test({0x80},invalid);test({0xc2},invalid);test({0xe2,0x82},invalid);test({0xf0,0x9f,0x98},invalid);
    test({0xc2,'a'},invalid);test({0xed,0xa0,0x80},invalid);test({0xf4,0x90,0x80,0x80},invalid);
    test({0xf5,0x80,0x80,0x80},invalid);test({0xff},invalid);
    test({0},control);test({0x1b,'['},control);test({0x7f},control);test({0xc2,0x85},control);
    test({0xe2,0x80,0xae},control);test({0xe2,0x81,0xa6},control);
    test({'a',0xef,0xbb,0xbf},control);test({0xef,0xbf,0xbf},control);
    std::vector<unsigned char> text(max_text_bytes,'x');
    for(std::size_t i=4095;i<text.size();i+=4096)text[i]='\n';
    check(validate_text(text).status==ready,"exact text cap");
    text.push_back('x');check(validate_text(text).status==TextStatus::TooLarge,"text cap exceeded");
    const unsigned char bom[]={0xef,0xbb,0xbf};
    check(validate_text(bom).offset==3,"BOM view offset");
    std::vector<unsigned char> line(max_line_bytes,'x');
    check(validate_text(line).status==ready,"exact line boundary");
    line.push_back('x');check(validate_text(line).status==TextStatus::LayoutLimit,"line overflow");
    line.pop_back();line.push_back('\r');line.push_back('\n');
    check(validate_text(line).status==ready,"CRLF at line boundary");
    std::vector<unsigned char> rows(max_text_lines-1,'\n');
    check(validate_text(rows).status==ready,"exact line count");
    rows.push_back('\n');check(validate_text(rows).status==TextStatus::LayoutLimit,"line count overflow");
    std::vector<unsigned char> unicode;
    for(std::size_t i=0;i<max_line_bytes/2;++i){unicode.push_back(0xc3);unicode.push_back(0xa7);}
    check(validate_text(unicode).status==ready,"UTF-8 byte boundary");
    unicode.push_back(0xc3);unicode.push_back(0xa7);
    check(validate_text(unicode).status==TextStatus::LayoutLimit,"UTF-8 layout overflow");

    namespace fs=std::filesystem;
    const auto root=fs::temp_directory_path()/("kasa-text-test-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directory(root);
    struct Cleanup {fs::path p;~Cleanup(){std::error_code ec;fs::remove_all(p,ec);}} cleanup{root};
    encryption_engine engine;
    for(bool binary:{false,true}) {
        const auto src=root/(binary?"binary.txt":"text.txt");const auto enc=fs::path(src.string()+".kasa");
        {std::ofstream f(src,std::ios::binary);if(binary)f.put('\0');else f<<"plain text";}
        if(!engine.encrypt_aes256(src,"test-password",false,enc))return 2;
        auto result=engine.decrypt_preview_aes(enc,"test-password",max_text_bytes);
        check(result.status==PreviewDecryptStatus::Success,"authenticated input fixture");
        TextStatus status{};
        auto view=TextPreview::create(std::move(result.content),status);
        check(!result.content,"ownership transferred");
        check(binary ? !view && status==control : view && status==ready && view->bytes().size()==10,
              "authenticated text gate");
    }
    TextStatus status{};
    check(!TextPreview::create(nullptr,status),"missing authenticated owner rejected");
    std::cout<<checks<<" text preview checks; "<<failures<<" failures.\n";
    return failures?1:0;
}
