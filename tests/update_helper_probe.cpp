#include <windows.h>
#include <string>
int main(){
    wchar_t path[32768]{};if(!GetEnvironmentVariableW(L"KASA_TEST_HELPER_MARKER",path,32768))return 2;
    HANDLE h=CreateFileW(path,GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(h==INVALID_HANDLE_VALUE)return 3;
    const char data[]="benign installer probe executed";DWORD written=0;const bool ok=WriteFile(h,data,sizeof(data)-1,&written,nullptr)!=FALSE;CloseHandle(h);return ok?0:4;
}
