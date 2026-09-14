#pragma once
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <vector>

namespace kasa {
inline bool mark_for_deletion(HANDLE handle, bool remove) {
    FILE_DISPOSITION_INFO info {static_cast<BOOLEAN>(remove)};
    return SetFileInformationByHandle(handle, FileDispositionInfo, &info, sizeof(info)) != 0;
}

// Mark before writing plaintext. Windows closes the handle even if the process
// exits without running C++ destructors. No writable sharing is granted.
inline std::unique_ptr<FILE, decltype(&fclose)> create_plaintext_file(const std::filesystem::path& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE | DELETE, 0, nullptr,
                          CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {nullptr, &fclose};
    if (!mark_for_deletion(h, true)) { CloseHandle(h); return {nullptr, &fclose}; }
    const int fd = _open_osfhandle(reinterpret_cast<std::intptr_t>(h), _O_BINARY | _O_WRONLY);
    if (fd == -1) { CloseHandle(h); return {nullptr, &fclose}; }
    FILE* file = _fdopen(fd, "wb");
    if (!file) { _close(fd); return {nullptr, &fclose}; }
    // Do not leave an additional plaintext copy in a CRT-owned stdio buffer.
    if (setvbuf(file, nullptr, _IONBF, 0) != 0) { fclose(file); return {nullptr, &fclose}; }
    return {file, &fclose};
}

// Caller must authenticate and flush the complete plaintext before publishing.
// Clearing disposition and renaming are separate operations: a crash between
// them may leave COMPLETE authenticated plaintext at the temporary name.
inline bool publish_plaintext(FILE* file, const std::filesystem::path& destination) {
    const HANDLE h = reinterpret_cast<HANDLE>(_get_osfhandle(_fileno(file)));
    std::error_code error;
    const auto absolute = std::filesystem::absolute(destination, error);
    if (error) return false;
    const auto path = absolute.native();
    if (path.size() > (std::numeric_limits<DWORD>::max() - sizeof(FILE_RENAME_INFO)) / sizeof(wchar_t)) return false;
    const auto bytes = path.size() * sizeof(wchar_t);
    std::vector<unsigned char> storage(sizeof(FILE_RENAME_INFO) + bytes, 0);
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
    rename->ReplaceIfExists = FALSE;
    rename->FileNameLength = static_cast<DWORD>(bytes);
    std::memcpy(rename->FileName, path.data(), bytes);
    if (!mark_for_deletion(h, false)) return false;
    if (!SetFileInformationByHandle(h, FileRenameInfo, rename, static_cast<DWORD>(storage.size()))) {
        mark_for_deletion(h, true);
        return false;
    }
    return true;
}
}
