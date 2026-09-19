#include "update_publisher.h"
#include "update_staging.h"
#include <fstream>
#include <sstream>
#include <chrono>
#include <iostream>
int main(int argc,char** argv){
    if(argc!=3)return 2;
    using namespace kasa::updates;
    std::ifstream file(argv[1],std::ios::binary);std::string bytes((std::istreambuf_iterator<char>(file)),{});
    std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(EVP_PKEY_Q_keygen(nullptr,nullptr,"ED25519"),EVP_PKEY_free);
    auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    std::istringstream payload(bytes);auto signature=sign_release(key.get(),payload,"1.1.0-test.3",now,600);
    auto m=verify_manifest(signature.descriptor,signature.signature,signature.public_key,"1.1.0-test.2","1.1.0-test.3",Channel::Test,now);
    if(!m)return 3;std::atomic<bool> cancel=false;
    auto staged=stage_update(*m,cancel,std::filesystem::temp_directory_path().lexically_normal(),[&](auto,auto,const auto&,const DownloadSink& sink){DownloadResult result;
        if(!sink(std::span(reinterpret_cast<const unsigned char*>(bytes.data()),bytes.size())))result.error=DownloadError::SinkFailed;return result;});
    if(!staged){std::cerr<<staged.error;return 4;}
    if(!staged.package->may_handoff(true,false,false,now))return 5;
    unsigned long error=0;
    std::cout<<staged.package->path().string()<<'\n';
    if(!staged.package->launch_helper(std::filesystem::absolute(argv[2]),now,error)){std::cerr<<error;return 6;}
    // Exiting releases our copies; helper must keep its copies until probe exits.
    return 0;
}
