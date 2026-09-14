#include "AppWindow.h"
#include "PreviewWindow.h"
#include "startup_arguments.h"

#include <windows.h>
#include <shellapi.h>
#include <string_view>

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    int argc=0;
    LPWSTR* argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    if(!argv)return 1;
    const auto mode=kasa::startup_mode(argc,argv);
    if(mode!=kasa::StartupMode::Main) {
        if(mode==kasa::StartupMode::Invalid) {
            LocalFree(argv);
            MessageBoxW(nullptr,L"Usage: KASA.exe --preview \"file.txt.kasa\"",L"KASA",MB_OK|MB_ICONINFORMATION);
            return 1;
        }
        const std::filesystem::path file(argv[2]);LocalFree(argv);
        return runTextPreviewWindow(file);
    }
    LocalFree(argv);
    AppWindow application;
    if (!application.init()) {
        MessageBoxW(nullptr, L"The KASA interface could not be initialized.", L"KASA",
                    MB_OK | MB_ICONERROR);
        return 1;
    }
    application.run();
    return 0;
}
