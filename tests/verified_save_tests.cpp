#include "verified_save.h"
#include <windows.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <chrono>

namespace {
    struct Workspace {
        std::filesystem::path path = std::filesystem::temp_directory_path() /
            ("kasa-save-tests-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        Workspace() { std::filesystem::create_directories(path); }
        ~Workspace() { std::error_code error; std::filesystem::remove_all(path, error); }
    };
    bool write(const std::filesystem::path& path, const std::vector<char>& data) {
        std::ofstream stream(path, std::ios::binary);
        stream.write(data.data(), static_cast<std::streamsize>(data.size()));
        return stream.good();
    }
    std::vector<char> read(const std::filesystem::path& path) {
        std::ifstream stream(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
    }
    bool expect(bool value, const char* message) {
        if (!value) std::cerr << "FAIL: " << message << '\n';
        return value;
    }
    bool run(std::size_t size, SaveFault fault) {
        Workspace w;
        const auto source = w.path / "staged.kasa";
        const auto target = w.path / L"özel-klasör" / L"şifreli.kasa";
        std::vector<char> data(size);
        for (std::size_t i = 0; i < size; ++i) data[i] = static_cast<char>((i * 71 + 13) % 251);
        if (!write(source, data)) return false;
        const bool accepted = save_verified(source, target, fault);
        if (!expect(accepted == (fault == SaveFault::None), "Return value reflects save success") ||
            !expect(read(source) == data, "Staging source always retained intact")) return false;
        if (fault == SaveFault::None || fault == SaveFault::AfterPublish) {
            if (!expect(read(target) == data, "Published output bytes are intact")) return false;
        } else if (!expect(!std::filesystem::exists(target), "No partial destination published")) return false;
        for (const auto& entry : std::filesystem::directory_iterator(target.parent_path())) {
            if (!expect(entry.path() == target, "Owned temporary file cleaned on handled failure")) return false;
        }
        if (fault != SaveFault::None && fault != SaveFault::AfterPublish) {
            if (!expect(save_verified(source, target) && read(target) == data,
                        "Retry after failure succeeds")) return false;
        }
        return true;
    }
    bool collisions() {
        Workspace w;
        const auto source = w.path / "source.kasa";
        const auto target = w.path / "existing.kasa";
        const std::vector<char> original(64, 'a'), sentinel(64, 'z');
        if (!write(source, original) || !write(target, sentinel)) return false;
        if (!expect(!save_verified(source, target) && read(target) == sentinel && read(source) == original,
                    "Existing destination never replaced")) return false;
        if (!expect(!save_verified(source, source) && read(source) == original,
                    "Source cannot be its own destination")) return false;
        return expect(!save_verified(source, target / "child.kasa") && read(source) == original,
                      "Invalid destination parent preserves source");
    }
    bool busy_source() {
        Workspace w;
        const auto source = w.path / "source.kasa";
        const auto target = w.path / "target.kasa";
        if (!write(source, std::vector<char>(128, 'b'))) return false;
        const HANDLE writer = CreateFileW(source.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (writer == INVALID_HANDLE_VALUE) return false;
        const bool result = save_verified(source, target);
        CloseHandle(writer);
        return expect(!result && !std::filesystem::exists(target), "Active writer rejected before copy");
    }
}
int main() {
    bool passed = true;
    for (const auto size : {std::size_t(0), std::size_t(1), std::size_t(1024 * 1024 + 17)})
        passed &= run(size, SaveFault::None);
    for (const auto fault : {SaveFault::PartialWrite, SaveFault::Flush, SaveFault::CorruptCopy,
                             SaveFault::Publish, SaveFault::AfterPublish}) passed &= run(128 * 1024 + 3, fault);
    passed &= collisions();
    passed &= busy_source();
    if (passed) std::cout << "All 10 verified-save scenarios passed.\n";
    return passed ? 0 : 1;
}
