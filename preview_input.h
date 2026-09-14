#pragma once
#include "preview_policy.h"
#include <filesystem>
#include <windows.h>

namespace kasa::preview {
inline Kind kind_from_path(const std::filesystem::path& file) {
    auto ext=file.extension().wstring();
    for(auto& c:ext)if(c>=L'A'&&c<=L'Z')c+=L'a'-L'A';
    return ext==L".kasa"?kind_from_extension(file.stem().extension().wstring()):Kind::Unsupported;
}
enum class InputStatus { Available, Unavailable, TooLarge };
// UI hint only. Close immediately: actual decryption reopens and validates the
// same stable handle throughout. This check never authorizes later file access.
inline InputStatus inspect_preview_input(const std::filesystem::path& file) noexcept {
    HANDLE h=CreateFileW(file.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
                         FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
    if(h==INVALID_HANDLE_VALUE)return InputStatus::Unavailable;
    BY_HANDLE_FILE_INFORMATION info{};LARGE_INTEGER size{};
    const bool valid=GetFileType(h)==FILE_TYPE_DISK&&GetFileInformationByHandle(h,&info)
        &&!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)&&GetFileSizeEx(h,&size)&&size.QuadPart>=0;
    CloseHandle(h);
    if(!valid)return InputStatus::Unavailable;
    return static_cast<std::uint64_t>(size.QuadPart)>max_encrypted_bytes?InputStatus::TooLarge:InputStatus::Available;
}
inline constexpr const char* unavailable_notice=
    "The file could not be read. It may be missing or in use. Nothing was opened.";
}
