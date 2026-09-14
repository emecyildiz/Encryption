#pragma once
#include <string_view>
namespace kasa {
enum class StartupMode { Main, Preview, Invalid };
inline StartupMode startup_mode(int argc,wchar_t* const* argv) noexcept {
    if(argc==1)return StartupMode::Main;
    if(argc==3&&argv&&argv[1]&&argv[2]&&std::wstring_view(argv[1])==L"--preview"&&argv[2][0]!=L'\0')
        return StartupMode::Preview;
    return StartupMode::Invalid;
}
}
