#pragma once
#include <filesystem>
#include <stdexcept>

namespace kasa {
inline std::filesystem::path unique_output_path(const std::filesystem::path& folder,
                                                const std::filesystem::path& desired_name) {
    // This is a name candidate only. The publisher must still refuse overwrite.
    auto free=[](const std::filesystem::path& candidate){
        auto temporary=candidate;temporary+=L".tmp";
        return !std::filesystem::exists(candidate)&&!std::filesystem::exists(temporary);
    };
    auto candidate=folder/desired_name;
    if(free(candidate))return candidate;
    for(int number=2;number<10000;++number){
        auto name=desired_name.stem().native()+L" ("+std::to_wstring(number)+L")"+desired_name.extension().native();
        candidate=folder/name;
        if(free(candidate))return candidate;
    }
    // Never return an unchecked fallback which may already exist.
    throw std::runtime_error("No available output filename was found");
}
}
