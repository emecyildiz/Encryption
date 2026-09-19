#include "update_publisher.h"
#include "update_manifest.h"
#include <memory>
#include <sstream>
#include <iostream>
#include <limits>
int main(){
    using namespace kasa::updates;
    std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(EVP_PKEY_Q_keygen(nullptr,nullptr,"ED25519"),EVP_PKEY_free);
    int checks=0,failures=0;
    const auto check=[&](bool value){++checks;if(!value)++failures;};
    std::istringstream data("abc");const auto signed_data=sign_release(key.get(),data,"1.1.0-test.3",1000,86400);
    auto m=verify_manifest(signed_data.descriptor,signed_data.signature,signed_data.public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,1000);
    check(m.has_value());std::istringstream payload("abc");check(m && verify_payload(payload,*m));
    check(!verify_manifest(signed_data.descriptor+" ",signed_data.signature,signed_data.public_key,"1.1.0-test.2","v1.1.0-test.3",Channel::Test,1000));
    for(const auto* version:{"v1.2.3","1.2.3-rc.1","../file","1.02.3"}){
        bool rejected=false;try{std::istringstream p("abc");sign_release(key.get(),p,version,1000,1);}catch(...){rejected=true;}check(rejected);
    }
    for(auto lifetime:{0ULL,2592001ULL}){
        bool rejected=false;try{std::istringstream p("abc");sign_release(key.get(),p,"1.2.3",1000,lifetime);}catch(...){rejected=true;}check(rejected);
    }
    bool rejected=false;try{std::istringstream p("");sign_release(key.get(),p,"1.2.3",1000,1);}catch(...){rejected=true;}check(rejected);
    rejected=false;try{std::istringstream p("abc");sign_release(nullptr,p,"1.2.3",1000,1);}catch(...){rejected=true;}check(rejected);
    rejected=false;try{std::istringstream p("abc");sign_release(key.get(),p,"1.2.3",std::numeric_limits<std::uint64_t>::max(),1);}catch(...){rejected=true;}check(rejected);
    std::istringstream stable("abc");auto s=sign_release(key.get(),stable,"1.2.3",1000,2592000);
    check(verify_manifest(s.descriptor,s.signature,s.public_key,"1.2.2","v1.2.3",Channel::Stable,1000).has_value());
    std::cout<<checks<<" checks, "<<failures<<" failures\n";return failures!=0;
}
