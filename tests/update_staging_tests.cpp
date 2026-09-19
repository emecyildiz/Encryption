#include "update_staging.h"
#include <windows.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <fstream>

int main(){
    using namespace kasa::updates;
    int checks=0,failures=0;
    const auto check=[&](bool ok,const char* label){++checks;if(!ok){++failures;std::cerr<<label<<'\n';}};
    const auto root=(std::filesystem::temp_directory_path()/
        (L"kasa-stage-tests-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64()))).lexically_normal();
    if(!std::filesystem::create_directory(root))return 2;
    struct Cleanup{std::filesystem::path p;~Cleanup(){std::error_code e;std::filesystem::remove(p,e);}} cleanup{root};
    using Key=std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)>;
    Key key(EVP_PKEY_Q_keygen(nullptr,nullptr,"ED25519"),EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    if(!key || !ctx)return 2;
    std::array<unsigned char,32> pub{};std::size_t key_size=32;
    if(EVP_PKEY_get_raw_public_key(key.get(),pub.data(),&key_size)!=1)return 2;
    nlohmann::json j={{"schema",1U},{"product","KASA"},{"platform","windows-x64"},{"version","1.1.0-test.3"},
        {"prerelease",true},{"asset","KASA-Setup-1.1.0-test.3.exe"},{"size",3U},
        {"sha256","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},{"issued_at",1000U},{"expires_at",2000U}};
    const auto json=j.dump();std::vector<unsigned char> sig(64);std::size_t sig_size=64;
    if(EVP_DigestSignInit(ctx.get(),nullptr,nullptr,nullptr,key.get())!=1 ||
        EVP_DigestSign(ctx.get(),sig.data(),&sig_size,reinterpret_cast<const unsigned char*>(json.data()),json.size())!=1)return 2;
    std::string payload="abc";std::atomic<bool> cancel{false};unsigned requests=0;
    DownloadTransport transport=[&](std::wstring_view url,std::uint64_t,const auto&,const DownloadSink& sink){
        ++requests;std::span<const unsigned char> bytes;
        if(url.ends_with(L".json"))bytes={reinterpret_cast<const unsigned char*>(json.data()),json.size()};
        else if(url.ends_with(L".sig"))bytes=sig;
        else bytes={reinterpret_cast<const unsigned char*>(payload.data()),payload.size()};
        if(!sink(bytes))return DownloadResult{DownloadError::SinkFailed};
        return DownloadResult{DownloadError::None,200,0,bytes.size()};
    };
    const auto prepare=[&](std::uint64_t now=1500){return prepare_update("1.1.0-test.2","v1.1.0-test.3",Channel::Test,pub,now,cancel,root,transport);};
    auto ready=prepare();
    check(static_cast<bool>(ready),ready.error.c_str());
    if(!ready){std::cerr<<"System error: "<<ready.download.system_error<<" root: "<<root.string()<<'\n';return 1;}
    check(requests==3,"descriptor signature payload sequence");
    const auto file=ready.package->path(), folder=file.parent_path();
    check(std::filesystem::file_size(file)==3,"staged size");
    check(ready.package->may_handoff(true,false,false,1500),"approved idle handoff");
    check(!ready.package->may_handoff(false,false,false,1500),"approval required");
    check(!ready.package->may_handoff(true,true,false,1500),"active operation blocked");
    check(!ready.package->may_handoff(true,false,true,1500),"pending output blocked");
    check(!ready.package->may_handoff(true,false,false,2000),"expiry rechecked");
    check(!ready.package->may_handoff(true,false,false,699),"future issue time rechecked");
    HANDLE write=CreateFileW(file.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        nullptr,OPEN_EXISTING,0,nullptr);
    check(write==INVALID_HANDLE_VALUE,"write locked");if(write!=INVALID_HANDLE_VALUE)CloseHandle(write);
    check(!DeleteFileW(file.c_str()),"delete locked");
    check(!MoveFileW(file.c_str(),(folder/L"changed.exe").c_str()),"rename locked");
    check(!MoveFileW(folder.c_str(),(root/L"moved").c_str()),"directory pinned");
    HANDLE read=CreateFileW(file.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr);
    check(read!=INVALID_HANDLE_VALUE,"installer can open read-only");if(read!=INVALID_HANDLE_VALUE)CloseHandle(read);
    check(ready.package->discard(),"explicit cleanup succeeds");
    check(!ready.package->may_handoff(true,false,false,1500),"discarded package cannot hand off");
    ready.package.reset();
    check(!std::filesystem::exists(folder),"RAII cleans owned package and folder");
    payload="ab";auto partial=prepare();
    check(!partial && partial.download.error==DownloadError::SizeMismatch,"partial download rejected");
    check(std::filesystem::is_empty(root),"partial download cleaned");
    payload="abd";auto tampered=prepare();
    check(!tampered && tampered.download.error==DownloadError::HashMismatch,"bad hash rejected");
    check(std::filesystem::is_empty(root),"bad hash cleaned");
    payload="abcd";check(!prepare(),"oversize rejected");check(std::filesystem::is_empty(root),"oversize cleaned");
    payload="abc";cancel=true;check(!prepare(),"cancelled preparation rejected");cancel=false;
    check(std::filesystem::is_empty(root),"cancel creates no lingering staging");
    sig[0]^=1;requests=0;check(!prepare(),"bad publisher signature rejected");
    check(requests==2,"no payload request after bad signature");sig[0]^=1;
    requests=0;check(!prepare(2000),"expired descriptor rejected");check(requests==2,"no expired payload request");
    check(!prepare_update("1.1.0-test.2","v1.1.0-test.3",Channel::Stable,pub,1500,cancel,root,transport),"stable channel rejects test");
    check(!prepare_update("1.1.0-test.2","v1.1.0-test.3",Channel::Test,{},1500,cancel,root,transport),"missing pinned key");
    check(!prepare_update("1.1.0-test.2","v1.1.0-test.3",Channel::Test,pub,1500,cancel,root/L"missing",transport),"missing root");
    check(!prepare_update("1.1.0-test.2","v1.1.0-test.3",Channel::Test,pub,1500,cancel,L"relative",transport),"relative root rejected");
    const DownloadTransport throwing=[](auto,auto,const auto&,const auto&)->DownloadResult{throw std::runtime_error("network");};
    check(!prepare_update("1.1.0-test.2","v1.1.0-test.3",Channel::Test,pub,1500,cancel,root,throwing),"transport exception");
    const DownloadTransport abusive=[](auto,auto,const auto&,const DownloadSink& sink){std::vector<unsigned char> b(8193,'x');sink(b);return DownloadResult{};};
    check(!prepare_update("1.1.0-test.2","v1.1.0-test.3",Channel::Test,pub,1500,cancel,root,abusive),"independent metadata cap");
    check(std::filesystem::is_empty(root),"final staging root empty");
    auto first=prepare(),second=prepare();
    check(first && second,"two isolated preparations");
    if(first && second){
        check(first.package->path()!=second.package->path(),"unique random folders");
        auto second_path=second.package->path();
        first.package.reset();
        check(std::filesystem::exists(second_path),"cleanup isolated from other update");
        check(second.package->may_handoff(true,false,false,1500),"remaining update valid");
        second.package.reset();
    }
    auto preserve=prepare();
    check(static_cast<bool>(preserve),"prepare preservation fixture");
    if(preserve){
        const auto dir=preserve.package->path().parent_path();
        const auto unrelated=dir/L"unrelated.txt";
        {std::ofstream f(unrelated);f<<"keep";}
        check(!preserve.package->discard(),"unknown file reported as incomplete cleanup");
        preserve.package.reset();
        check(std::filesystem::exists(unrelated),"never recursively delete unrelated file");
        check(!std::filesystem::exists(dir/L"installer.exe"),"owned file still removed");
        std::filesystem::remove(unrelated);std::filesystem::remove(dir);
    }
    bool cancelled_once=false;
    const DownloadTransport midway=[&](auto request,auto limit,const auto& flag,const DownloadSink& destination){
        return transport(request,limit,flag,[&](auto bytes){
            const bool ok=destination(bytes);
            if(request.ends_with(L".exe")){cancel=true;cancelled_once=true;}
            return ok;
        });
    };
    check(!prepare_update("1.1.0-test.2","v1.1.0-test.3",Channel::Test,pub,1500,cancel,root,midway),"cancel after file write");
    check(cancelled_once && std::filesystem::is_empty(root),"post-write cancellation cleans staging");cancel=false;
    check(std::filesystem::is_empty(root),"extended tests leave empty root");
    std::cout<<checks<<" checks, "<<failures<<" failures\n";
    return failures!=0;
}
