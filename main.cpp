#include "AppWindow.h"

#include <windows.h>

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    AppWindow application;
    if (!application.init()) {
        MessageBoxW(nullptr, L"KASA arayuzu baslatilamadi.", L"KASA",
                    MB_OK | MB_ICONERROR);
        return 1;
    }
    application.run();
    return 0;
}
