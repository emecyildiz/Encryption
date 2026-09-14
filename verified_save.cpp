#include "verified_save.h"
#include <windows.h>
#include <openssl/rand.h>
#include <array>
#include <vector>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>

namespace {
    struct Handle {
        HANDLE value = INVALID_HANDLE_VALUE;
        bool remove_on_close = false;
        ~Handle() {
            if (value == INVALID_HANDLE_VALUE) return;
            if (remove_on_close) {
                FILE_DISPOSITION_INFO disposition {TRUE};
                SetFileInformationByHandle(value, FileDispositionInfo, &disposition, sizeof(disposition));
            }
            CloseHandle(value);
        }
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
        explicit Handle(HANDLE h) : value(h) {}
    };

    bool rewind_file(HANDLE h) {
        LARGE_INTEGER zero {};
        return SetFilePointerEx(h, zero, nullptr, FILE_BEGIN) != 0;
    }
}

bool save_verified(const std::filesystem::path& source,
                   const std::filesystem::path& destination
#ifdef KASA_SAVE_TESTING
                   , SaveFault fault
#endif
) {
    std::error_code error;
    const auto target = std::filesystem::absolute(destination, error);
    if (error || target.filename().empty()) return false;
    if (std::filesystem::exists(target, error) || error) return false;
    std::filesystem::create_directories(target.parent_path(), error);
    if (error) return false;

    Handle input(CreateFileW(source.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    if (input.value == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info {};
    if (GetFileType(input.value) != FILE_TYPE_DISK ||
        !GetFileInformationByHandle(input.value, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) return false;
    LARGE_INTEGER original_size {};
    if (!GetFileSizeEx(input.value, &original_size)) return false;

    std::array<unsigned char, 16> random {};
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) return false;
    std::wstring name = L".kasa-save-";
    constexpr wchar_t hex[] = L"0123456789abcdef";
    for (const auto byte : random) { name += hex[byte >> 4]; name += hex[byte & 15]; }
    name += L".tmp";
    const auto temporary = target.parent_path() / name;
    Handle output(CreateFileW(temporary.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE,
                              0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (output.value == INVALID_HANDLE_VALUE) return false;
    output.remove_on_close = true;

    std::array<unsigned char, 64 * 1024> buffer {};
    std::uint64_t copied = 0;
    while (true) {
        DWORD count = 0;
        if (!ReadFile(input.value, buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr)) return false;
        if (!count) break;
        DWORD written = 0;
        if (!WriteFile(output.value, buffer.data(), count, &written, nullptr) || written != count) return false;
        copied += count;
#ifdef KASA_SAVE_TESTING
        if (fault == SaveFault::PartialWrite) return false;
#endif
    }
    if (copied != static_cast<std::uint64_t>(original_size.QuadPart)) return false;
#ifdef KASA_SAVE_TESTING
    if (fault == SaveFault::Flush) return false;
    if (fault == SaveFault::CorruptCopy && copied > 0) {
        DWORD written = 0;
        unsigned char wrong = static_cast<unsigned char>(buffer[0] ^ 0xff);
        if (!rewind_file(output.value) || !WriteFile(output.value, &wrong, 1, &written, nullptr)) return false;
    }
#endif
    if (!FlushFileBuffers(output.value) || !rewind_file(input.value) || !rewind_file(output.value)) return false;

    // Read back the saved file and compare every byte before publication.
    std::array<unsigned char, 64 * 1024> saved {};
    while (true) {
        DWORD count = 0, saved_count = 0;
        if (!ReadFile(input.value, buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr) ||
            !ReadFile(output.value, saved.data(), static_cast<DWORD>(saved.size()), &saved_count, nullptr) ||
            count != saved_count || !std::equal(buffer.begin(), buffer.begin() + count, saved.begin())) return false;
        if (!count) break;
    }
#ifdef KASA_SAVE_TESTING
    if (fault == SaveFault::Publish) return false;
#endif
    // Rename the owned handle, not an independently reopened temporary path.
    const auto path = target.native();
    if (path.size() > (std::numeric_limits<DWORD>::max() - sizeof(FILE_RENAME_INFO)) / sizeof(wchar_t)) return false;
    const auto bytes = path.size() * sizeof(wchar_t);
    std::vector<unsigned char> storage(sizeof(FILE_RENAME_INFO) + bytes, 0);
    auto* rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
    rename->ReplaceIfExists = FALSE;
    rename->FileNameLength = static_cast<DWORD>(bytes);
    std::memcpy(rename->FileName, path.data(), bytes);
    if (!SetFileInformationByHandle(output.value, FileRenameInfo, rename, static_cast<DWORD>(storage.size()))) return false;
    // On a post-publication error keep both copies; caller must not delete original.
    output.remove_on_close = false;
#ifdef KASA_SAVE_TESTING
    if (fault == SaveFault::AfterPublish) return false;
#endif
    return FlushFileBuffers(output.value) != 0;
}
