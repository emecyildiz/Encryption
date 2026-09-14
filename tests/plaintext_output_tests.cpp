#include "plaintext_output.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <string>

bool check(bool value, const char* label) {
    if (!value) std::cerr << "FAIL: " << label << '\n';
    return value;
}
std::string read(const std::filesystem::path& path) {
    std::ifstream f(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), {}};
}
int main(int argc, char** argv) {
    const auto temp = std::filesystem::temp_directory_path() /
        ("kasa-plaintext-" + std::to_string(GetCurrentProcessId()));
    if (argc == 2 && std::string(argv[1]) == "--abrupt-child") {
        auto output = kasa::create_plaintext_file(temp);
        if (!output || fwrite("sensitive", 1, 9, output.get()) != 9 ||
            fflush(output.get()) || _commit(_fileno(output.get()))) return 2;
        ExitProcess(77); // Deliberately bypass all C++ destructors.
    }
    const auto root = std::filesystem::temp_directory_path() /
        ("kasa-plaintext-tests-" + std::to_string(GetCurrentProcessId()) + "-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(root);
    struct Cleanup { std::filesystem::path path; ~Cleanup(){ std::error_code e; std::filesystem::remove_all(path,e); } } cleanup {root};
    const auto tmp = root / "output.tmp", final = root / L"çıktı.txt";
    bool ok = true;
    {
        auto file = kasa::create_plaintext_file(tmp);
        ok &= check(file && fwrite("partial",1,7,file.get()) == 7, "write partial");
    }
    ok &= check(!std::filesystem::exists(tmp), "ordinary failure cleans temporary");
    {
        auto file = kasa::create_plaintext_file(tmp);
        if (!file) return 1;
        ok &= check(fwrite("verified",1,8,file.get()) == 8 && !fflush(file.get()) &&
            !_commit(_fileno(file.get())) && kasa::publish_plaintext(file.get(),final), "publish");
    }
    ok &= check(!std::filesystem::exists(tmp) && read(final)=="verified", "published output survives close");
    {
        auto file = kasa::create_plaintext_file(tmp);
        if (!file) return 1;
        fwrite("partial",1,7,file.get());
        ok &= check(!kasa::publish_plaintext(file.get(),final), "existing target refused");
    }
    ok &= check(!std::filesystem::exists(tmp) && read(final)=="verified", "failed publication cleans only owned file");
    auto existing = kasa::create_plaintext_file(final);
    ok &= check(!existing && read(final)=="verified", "temporary name collision preserves existing file");

    wchar_t executable[32768];
    if (!GetModuleFileNameW(nullptr, executable, 32768)) return 1;
    std::wstring command = L"\"" + std::wstring(executable) + L"\" --abrupt-child";
    STARTUPINFOW startup {}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION child {};
    if (!CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child)) return 1;
    const auto child_temp = std::filesystem::temp_directory_path() /
        ("kasa-plaintext-" + std::to_string(child.dwProcessId));
    const DWORD wait = WaitForSingleObject(child.hProcess, 15000);
    if (wait != WAIT_OBJECT_0) { TerminateProcess(child.hProcess, 2); WaitForSingleObject(child.hProcess, 5000); }
    DWORD exit_code = 0; GetExitCodeProcess(child.hProcess, &exit_code);
    CloseHandle(child.hThread); CloseHandle(child.hProcess);
    ok &= check(wait == WAIT_OBJECT_0 && exit_code == 77 && !std::filesystem::exists(child_temp),
                "abrupt child exit removes plaintext without destructors");
    if (!ok) return 1;
    std::cout << "All 5 plaintext lifecycle scenarios passed.\n";
}
