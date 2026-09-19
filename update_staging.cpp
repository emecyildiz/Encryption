#include "update_staging.h"
#include <windows.h>
#include <sddl.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <vector>
#include <chrono>

namespace kasa::updates {
namespace {
struct Handle {
    HANDLE value=INVALID_HANDLE_VALUE;
    Handle()=default;
    explicit Handle(HANDLE h):value(h){}
    ~Handle(){close();}
    Handle(const Handle&)=delete;
    Handle& operator=(const Handle&)=delete;
    Handle(Handle&& h) noexcept:value(h.value){h.value=INVALID_HANDLE_VALUE;}
    Handle& operator=(Handle&& h) noexcept {if(this!=&h){close();value=h.value;h.value=INVALID_HANDLE_VALUE;}return *this;}
    void close(){if(value!=INVALID_HANDLE_VALUE && value)CloseHandle(value);value=INVALID_HANDLE_VALUE;}
    explicit operator bool()const{return value!=INVALID_HANDLE_VALUE && value;}
};
bool ordinary(HANDLE h,bool directory){
    BY_HANDLE_FILE_INFORMATION i{};
    return GetFileInformationByHandle(h,&i) && !(i.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) &&
        !!(i.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==directory && (directory || i.nNumberOfLinks==1);
}
bool pin_directories(const std::filesystem::path& root,std::vector<Handle>& handles){
    if(!root.is_absolute() || root.native().starts_with(L"\\\\") || root!=root.lexically_normal())return false;
    std::filesystem::path current;
    for(const auto& component:root){
        current/=component;
        if(!current.has_root_directory())continue;
        Handle h(CreateFileW(current.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,
            nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        if(!h || !ordinary(h.value,true))return false;
        handles.push_back(std::move(h));
    }
    return !handles.empty();
}
struct Descriptor {PSECURITY_DESCRIPTOR value=nullptr;~Descriptor(){if(value)LocalFree(value);}};
bool private_acl(Descriptor& sd){
    HANDLE raw=nullptr;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw))return false;
    Handle token(raw);DWORD size=0;
    GetTokenInformation(token.value,TokenUser,nullptr,0,&size);
    if(!size || size>65536)return false;
    std::vector<unsigned char> buffer(size);
    if(!GetTokenInformation(token.value,TokenUser,buffer.data(),size,&size))return false;
    LPWSTR sid=nullptr;
    if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid,&sid))return false;
    const std::wstring sddl=L"D:P(A;OICI;FA;;;"+std::wstring(sid)+L")(A;OICI;FA;;;SY)";
    LocalFree(sid);
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(),SDDL_REVISION_1,&sd.value,nullptr)!=FALSE;
}
std::wstring random_name(){
    std::array<unsigned char,16> bytes{};
    if(RAND_bytes(bytes.data(),static_cast<int>(bytes.size()))!=1)return {};
    constexpr wchar_t hex[]=L"0123456789abcdef";
    std::wstring result=L"KASA-update-";
    for(auto b:bytes){result+=hex[b>>4];result+=hex[b&15];}return result;
}
bool verify_locked(HANDLE file,const VerifiedManifest& m){
    LARGE_INTEGER zero{},size{};
    if(!ordinary(file,false) || !GetFileSizeEx(file,&size) || size.QuadPart<0 ||
        static_cast<std::uint64_t>(size.QuadPart)!=m.size() || !SetFilePointerEx(file,zero,nullptr,FILE_BEGIN))return false;
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> c(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    if(!c || EVP_DigestInit_ex(c.get(),EVP_sha256(),nullptr)!=1)return false;
    std::array<unsigned char,65536> buffer{};std::uint64_t total=0;
    for(;;){
        DWORD count=0;
        if(!ReadFile(file,buffer.data(),static_cast<DWORD>(buffer.size()),&count,nullptr))return false;
        if(!count)break;
        if(count>m.size()-total || EVP_DigestUpdate(c.get(),buffer.data(),count)!=1)return false;
        total+=count;
    }
    std::array<unsigned char,32> digest{};unsigned int count=0;
    return total==m.size() && EVP_DigestFinal_ex(c.get(),digest.data(),&count)==1 && count==32 &&
        CRYPTO_memcmp(digest.data(),m.sha256().data(),32)==0;
}
}
struct StagedUpdate::State {
    VerifiedManifest manifest;
    std::filesystem::path directory,file;
    std::vector<Handle> ancestors;
    Handle folder,writer,reader;
    bool own_directory=false,own_file=false;
    explicit State(const VerifiedManifest& m):manifest(m){}
    bool cleanup(){
        bool ok=true;
        reader.close();writer.close();
        if(own_file){
            if(DeleteFileW(file.c_str()) || GetLastError()==ERROR_FILE_NOT_FOUND)own_file=false;
            else ok=false;
        }
        folder.close();
        if(own_directory){
            if(RemoveDirectoryW(directory.c_str()) || GetLastError()==ERROR_PATH_NOT_FOUND || GetLastError()==ERROR_FILE_NOT_FOUND)own_directory=false;
            else ok=false;
        }
        return ok;
    }
    ~State(){cleanup();} // Never recursive; unknown files remain.
};
StagedUpdate::StagedUpdate(std::unique_ptr<State> s):state_(std::move(s)){}
StagedUpdate::~StagedUpdate()=default;
const std::filesystem::path& StagedUpdate::path()const{return state_->file;}
bool StagedUpdate::discard(){return state_->cleanup();}
bool StagedUpdate::may_handoff(bool approved,bool processing,bool pending,std::uint64_t now){
    return may_begin_install(approved,true,processing,pending) && state_->manifest.current_at(now) &&
        verify_locked(state_->reader.value,state_->manifest);
}
bool StagedUpdate::launch_helper(const std::filesystem::path& helper,std::uint64_t now,unsigned long& error){
    error=ERROR_INVALID_PARAMETER;
    if(!helper.is_absolute() || !state_->manifest.current_at(now) || !verify_locked(state_->reader.value,state_->manifest))return false;
    Handle binary(CreateFileW(helper.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if(!binary || !ordinary(binary.value,false)){error=GetLastError();return false;}
    std::vector<Handle> owned;std::vector<HANDLE> inherited;
    const auto duplicate=[&](HANDLE input)->HANDLE{
        HANDLE copy=nullptr;
        if(!DuplicateHandle(GetCurrentProcess(),input,GetCurrentProcess(),&copy,0,TRUE,DUPLICATE_SAME_ACCESS))return nullptr;
        owned.emplace_back(copy);inherited.push_back(copy);return copy;
    };
    const HANDLE file=duplicate(state_->reader.value);
    if(!file || !duplicate(state_->folder.value))return false;
    for(const auto& ancestor:state_->ancestors)if(!duplicate(ancestor.value))return false;
    Handle parent(OpenProcess(SYNCHRONIZE,FALSE,GetCurrentProcessId()));
    Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    if(!parent || !event)return false;
    const HANDLE parent_copy=duplicate(parent.value),event_copy=duplicate(event.value);
    if(!parent_copy || !event_copy)return false;
    SIZE_T bytes=0;InitializeProcThreadAttributeList(nullptr,1,0,&bytes);
    std::vector<unsigned char> storage(bytes);
    auto* attributes=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if(!InitializeProcThreadAttributeList(attributes,1,0,&bytes)){error=GetLastError();return false;}
    struct Cleanup{LPPROC_THREAD_ATTRIBUTE_LIST p;~Cleanup(){DeleteProcThreadAttributeList(p);}} cleanup{attributes};
    if(!UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited.data(),inherited.size()*sizeof(HANDLE),nullptr,nullptr)){error=GetLastError();return false;}
    const auto number=[](HANDLE h){return std::to_wstring(reinterpret_cast<std::uintptr_t>(h));};
    std::wstring args=L"\""+helper.wstring()+L"\" "+number(file)+L" "+number(parent_copy)+L" "+number(event_copy);
    args+=L" "+std::to_wstring(state_->manifest.expires_at());
    for(HANDLE handle:inherited)args+=L" "+number(handle);
    STARTUPINFOEXW start{};start.StartupInfo.cb=sizeof(start);start.lpAttributeList=attributes;
    PROCESS_INFORMATION process{};
    if(!CreateProcessW(helper.c_str(),args.data(),nullptr,nullptr,TRUE,EXTENDED_STARTUPINFO_PRESENT|CREATE_NO_WINDOW,nullptr,helper.parent_path().c_str(),&start.StartupInfo,&process)){error=GetLastError();return false;}
    Handle child(process.hProcess),thread(process.hThread);
    HANDLE waits[]={event.value,child.value};
    if(WaitForMultipleObjects(2,waits,FALSE,10000)!=WAIT_OBJECT_0){
        // This is our freshly spawned helper, still waiting for this process.
        TerminateProcess(child.value,ERROR_CANCELLED);WaitForSingleObject(child.value,5000);error=ERROR_TIMEOUT;return false;
    }
    error=0;return true;
}
StageResult stage_update(const VerifiedManifest& manifest,const std::atomic<bool>& cancel,
    const std::filesystem::path& root,const DownloadTransport& transport){
    StageResult result;
    std::unique_ptr<StagedUpdate::State> state;
    const auto fail=[&](const char* message)->StageResult{
        result.error=message;
        if(state && !state->cleanup())result.error+=" Some staging files could not be removed.";
        return std::move(result);
    };
    if(cancel){result.download.error=DownloadError::Cancelled;return fail("Cancelled before staging.");}
    try{
        state=std::make_unique<StagedUpdate::State>(manifest);
        if(!pin_directories(root,state->ancestors)){
            result.download.system_error=GetLastError();
            return fail("Staging root must be an existing local directory without reparse points.");
        }
        Descriptor acl;
        if(!private_acl(acl))return fail("Could not create private staging permissions.");
        SECURITY_ATTRIBUTES security{sizeof(security),acl.value,FALSE};
        const auto name=random_name();if(name.empty())return fail("Secure random staging name unavailable.");
        state->directory=root/name;
        if(!CreateDirectoryW(state->directory.c_str(),&security))return fail("Could not create a new staging directory.");
        state->own_directory=true;
        state->folder=Handle(CreateFileW(state->directory.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,
            nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        if(!state->folder || !ordinary(state->folder.value,true))return fail("Staging directory validation failed.");
        state->file=state->directory/L"installer.exe";
        state->writer=Handle(CreateFileW(state->file.c_str(),GENERIC_READ|GENERIC_WRITE,0,&security,CREATE_NEW,
            FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        if(!state->writer)return fail("Could not create a new staging file.");
        state->own_file=true;
        result.download=download_verified_payload(manifest,cancel,[&](auto block){
            DWORD written=0;
            return block.size()<=MAXDWORD && WriteFile(state->writer.value,block.data(),static_cast<DWORD>(block.size()),&written,nullptr) && written==block.size();
        },transport);
        if(!result.download)return fail("Download failed.");
        if(cancel){result.download.error=DownloadError::Cancelled;return fail("Download cancelled.");}
        if(!FlushFileBuffers(state->writer.value))return fail("Could not flush downloaded package.");
        state->writer.close();
        // Any replacement in the close/reopen gap must still pass a fresh hash under the read lock.
        state->reader=Handle(CreateFileW(state->file.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr));
        if(!state->reader || !verify_locked(state->reader.value,manifest))return fail("Staged package verification failed.");
        result.package=std::unique_ptr<StagedUpdate>(new StagedUpdate(std::move(state)));
        return result;
    }catch(...){return fail("Staging failed safely.");}
}
StageResult prepare_update(std::string_view installed,std::string_view release,Channel channel,
    std::span<const unsigned char> pinned_key,std::uint64_t now,const std::atomic<bool>& cancel,
    const std::filesystem::path& root,const DownloadTransport& transport){
    StageResult result;
    if(cancel){result.download.error=DownloadError::Cancelled;result.error="Cancelled before metadata request.";return result;}
    if(!transport || pinned_key.size()!=32 || !parse_version(installed) || !parse_version(release)){
        result.error="Missing trust root or invalid version.";return result;
    }
    if(release.starts_with('v'))release.remove_prefix(1);
    try{
        std::string descriptor;std::vector<unsigned char> signature;
        bool overflow=false;
        result.download=transport(release_asset_url(release,"KASA-update.json"),8192,cancel,[&](auto bytes){
            if(cancel || bytes.size()>8192-descriptor.size()){overflow=true;return false;}
            descriptor.append(reinterpret_cast<const char*>(bytes.data()),bytes.size());return true;
        });
        if(!result.download || overflow || cancel){result.error="Could not read bounded update descriptor.";return result;}
        result.download=transport(release_asset_url(release,"KASA-update.sig"),64,cancel,[&](auto bytes){
            if(cancel || bytes.size()>64-signature.size()){overflow=true;return false;}
            signature.insert(signature.end(),bytes.begin(),bytes.end());return true;
        });
        if(!result.download || overflow || cancel){result.error="Could not read update signature.";return result;}
        const auto manifest=verify_manifest(descriptor,signature,pinned_key,installed,release,channel,now);
        if(!manifest){result.error="Publisher signature or update policy validation failed.";return result;}
        return stage_update(*manifest,cancel,root,transport);
    }catch(...){result.error="Update preparation failed safely.";return result;}
}
}
