// No network, crypto, shell, elevation or arbitrary command string support.
// All package locks are inherited from the verified parent via an allowlist.
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cerrno>
#include <chrono>
#include "update_completion_policy.h"
static bool reopen_installed_kasa() {
    // Launch only the fixed sibling executable in the registered install path.
    // Never use a URL, PATH lookup, downloaded command, or shell association.
    wchar_t module[32768]{};
    const DWORD length=GetModuleFileNameW(nullptr,module,32768);
    if(!length || length>=32768)return false;
    std::wstring directory(module,length);
    const auto slash=directory.find_last_of(L"\\/");
    if(slash==std::wstring::npos)return false;
    directory.resize(slash);
    wchar_t registered[32768]{};DWORD bytes=sizeof(registered);
    HKEY install_key=nullptr;
    if(RegOpenKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{8AAE51C3-BD6C-495A-A0E6-15B0BF50C4A4}_is1",
        0,KEY_QUERY_VALUE|KEY_WOW64_64KEY,&install_key)!=ERROR_SUCCESS)return false;
    const auto read=RegGetValueW(install_key,nullptr,L"InstallLocation",RRF_RT_REG_SZ,nullptr,registered,&bytes);
    RegCloseKey(install_key);
    if(read!=ERROR_SUCCESS)return false;
    std::wstring expected(registered);
    while(!expected.empty() && (expected.back()==L'\\'||expected.back()==L'/'))expected.pop_back();
    if(_wcsicmp(directory.c_str(),expected.c_str())!=0)return false;
    const std::wstring application=directory+L"\\KASA.exe";
    const DWORD attributes=GetFileAttributesW(application.c_str());
    if(attributes==INVALID_FILE_ATTRIBUTES || (attributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)))return false;
    std::wstring command=L"\""+application+L"\"";
    STARTUPINFOW start{};start.cb=sizeof(start);PROCESS_INFORMATION child{};
    if(!CreateProcessW(application.c_str(),command.data(),nullptr,nullptr,FALSE,0,nullptr,directory.c_str(),&start,&child))return false;
    CloseHandle(child.hThread);CloseHandle(child.hProcess);return true;
}
static void outcome(DWORD code){
    HKEY key=nullptr;if(RegCreateKeyExW(HKEY_CURRENT_USER,L"Software\\Emecworks\\KASA\\Updates",0,nullptr,0,KEY_SET_VALUE,nullptr,&key,nullptr)==ERROR_SUCCESS){
        RegSetValueExW(key,L"LastInstallerExit",0,REG_DWORD,reinterpret_cast<const BYTE*>(&code),sizeof(code));RegCloseKey(key);
    }
}
static HANDLE handle(const wchar_t* text){
    if(!text || !*text)return nullptr;for(auto p=text;*p;++p)if(*p<L'0'||*p>L'9')return nullptr;
    errno=0;wchar_t* end=nullptr;const auto n=wcstoull(text,&end,10);
    if(errno || !end || *end || !n || n>UINTPTR_MAX)return nullptr;
    return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(n));
}
int WINAPI wWinMain(HINSTANCE,HINSTANCE,LPWSTR,int){
    int argc=0;auto args=CommandLineToArgvW(GetCommandLineW(),&argc);
    if(!args || argc<8){if(args)LocalFree(args);return 2;}
    const HANDLE file=handle(args[1]),parent=handle(args[2]),ready=handle(args[3]);
    const auto expiry=static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(handle(args[4])));
    std::vector<HANDLE> locks;for(int i=5;i<argc;++i){auto h=handle(args[i]);if(!h){LocalFree(args);return 2;}locks.push_back(h);}LocalFree(args);
    BY_HANDLE_FILE_INFORMATION info{};
    if(!file||!parent||!ready||!GetFileInformationByHandle(file,&info)||info.nNumberOfLinks!=1||
        (info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY)))return 3;
    std::vector<wchar_t> buffer(32768);const DWORD n=GetFinalPathNameByHandleW(file,buffer.data(),static_cast<DWORD>(buffer.size()),FILE_NAME_NORMALIZED);
    if(!n||n>=buffer.size())return 4;const std::wstring path(buffer.data(),n);
    const auto slash=path.find_last_of(L"\\/");
    if(slash==std::wstring::npos || path.substr(slash+1)!=L"installer.exe")return 5;
    const auto directory=path.substr(0,slash);const auto folder=directory.substr(directory.find_last_of(L"\\/")+1);
    if(folder.size()!=44 || !folder.starts_with(L"KASA-update-"))return 5;
    for(auto c:folder.substr(12))if(!((c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f')))return 5;
    if(!SetEvent(ready))return 6;
    if(WaitForSingleObject(parent,90000)!=WAIT_OBJECT_0)return 7;
    const auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    if(!expiry || now>=expiry){outcome(ERROR_TIMEOUT);return 9;}
    // Retain all inherited file/directory locks until the installer exits.
    // User approval has already been collected by KASA. Keep progress/errors
    // visible; never suppress errors, override tasks or force-close other apps.
    std::wstring command=L"\""+path+L"\" /KASAUPDATE=1 /SILENT /SP- /NORESTART /NOCLOSEAPPLICATIONS /RESTARTEXITCODE=3010";
    STARTUPINFOW start{};start.cb=sizeof(start);PROCESS_INFORMATION process{};
    if(!CreateProcessW(path.c_str(),command.data(),nullptr,nullptr,FALSE,0,nullptr,nullptr,&start,&process)){
        outcome(GetLastError());MessageBoxW(nullptr,L"The verified installer could not start. KASA has not been updated. Reopen KASA and retry, or use the official release installer.",L"KASA update",MB_OK|MB_ICONERROR);return 8;
    }
    CloseHandle(process.hThread);WaitForSingleObject(process.hProcess,INFINITE);DWORD code=ERROR_GEN_FAILURE;
    GetExitCodeProcess(process.hProcess,&code);CloseHandle(process.hProcess);outcome(code);
    for(auto h:locks)CloseHandle(h);
    // Only this inherited package file and its empty directory; never recursive.
    const bool removed=DeleteFileW(path.c_str())!=FALSE;
    const bool cleaned=removed && RemoveDirectoryW(directory.c_str())!=FALSE;
    if(!cleaned)MessageBoxW(nullptr,L"Installation finished, but its temporary download could not be fully removed. No documents were deleted.",L"KASA update cleanup",MB_OK|MB_ICONWARNING);
    switch(kasa::updates::completion_for(code)) {
    case kasa::updates::Completion::Relaunch:
        if(!reopen_installed_kasa())MessageBoxW(nullptr,L"Installation completed, but KASA could not be reopened automatically. Open it from your existing shortcut.",L"KASA update",MB_OK|MB_ICONWARNING);
        break;
    case kasa::updates::Completion::RestartRequired:
        MessageBoxW(nullptr,L"Installation completed, but Windows must be restarted to finish the update. Save your work and restart Windows when ready, then open KASA. No automatic restart will occur.",L"KASA update",MB_OK|MB_ICONINFORMATION);
        break;
    case kasa::updates::Completion::Cancelled:
        MessageBoxW(nullptr,L"The update was cancelled. KASA was not reopened automatically. Open KASA manually or retry the official installer. The exit code is saved in Updates.",L"KASA update",MB_OK|MB_ICONINFORMATION);
        break;
    case kasa::updates::Completion::Failed:
        MessageBoxW(nullptr,L"Installation did not complete. Your encrypted documents were not removed by the updater. Reopen KASA or rerun the official installer. The exit code is saved in Updates.",L"KASA update",MB_OK|MB_ICONWARNING);
        break;
    }
    return static_cast<int>(code);
}
