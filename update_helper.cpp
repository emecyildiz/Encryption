// No network, crypto, shell, elevation or arbitrary command string support.
// All package locks are inherited from the verified parent via an allowlist.
#include <windows.h>
#include <shellapi.h>
#include <string>
#include <vector>
#include <cstdint>
#include <cerrno>
#include <chrono>
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
    std::wstring command=L"\""+path+L"\" /NORESTART";
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
    if(code!=0)MessageBoxW(nullptr,L"Installation did not complete. Your encrypted documents were not removed by the updater. Reopen KASA or rerun the official installer. The exit code is saved in Updates.",L"KASA update",MB_OK|MB_ICONWARNING);
    return static_cast<int>(code);
}
