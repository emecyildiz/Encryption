#include "update_manifest.h"
#include "update_ui_policy.h"
#include <fstream>
#include <iostream>
int main(int argc,char** argv){
    if(argc!=5)return 2;
    const auto key=kasa::updates::parse_pinned_key(KASA_UPDATE_PUBLIC_KEY_HEX);if(!key)return 3;
    std::ifstream metadata(argv[1],std::ios::binary),sig(argv[2],std::ios::binary),payload(argv[3],std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(metadata)),{}),signature((std::istreambuf_iterator<char>(sig)),{});
    const auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    auto verified=kasa::updates::verify_manifest(bytes,std::span(reinterpret_cast<const unsigned char*>(signature.data()),signature.size()),*key,
        "1.1.0-test.1",argv[4],kasa::updates::Channel::Test,now);
    if(!verified || !kasa::updates::verify_payload(payload,*verified))return 1;
    std::cout<<"Pinned signature, manifest policy, size and SHA-256 verified.\n";return 0;
}
