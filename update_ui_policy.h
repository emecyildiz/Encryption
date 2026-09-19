#pragma once
#include "update_job.h"
#include <optional>
#include <string_view>
namespace kasa::updates {
inline std::optional<std::array<unsigned char,32>> parse_pinned_key(std::string_view hex){
    if(hex.size()!=64)return std::nullopt;
    std::array<unsigned char,32> key{};bool nonzero=false;
    const auto digit=[](char c){return c>='0'&&c<='9'?c-'0':(c>='a'&&c<='f'?c-'a'+10:-1);};
    for(std::size_t i=0;i<32;++i){const int a=digit(hex[i*2]),b=digit(hex[i*2+1]);
        if(a<0||b<0)return std::nullopt;key[i]=static_cast<unsigned char>(a*16+b);nonzero|=key[i]!=0;}
    return nonzero?std::optional{key}:std::nullopt;
}
inline bool locks_update_selection(PreparePhase phase){
    return phase==PreparePhase::Preparing || phase==PreparePhase::Ready || phase==PreparePhase::Transferred;
}
inline bool may_prepare_update(bool trusted,bool available,bool checking,bool processing,PreparePhase phase){
    return trusted && available && !checking && !processing && phase==PreparePhase::Idle;
}
}
