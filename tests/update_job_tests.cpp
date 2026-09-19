#include "update_job.h"
#include <windows.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <chrono>
#include <iostream>

int main(){
    using namespace kasa::updates;using namespace std::chrono_literals;
    int checks=0,failures=0;
    const auto check=[&](bool ok,const char* label){++checks;if(!ok){++failures;std::cerr<<label<<'\n';}};
    const auto root=(std::filesystem::temp_directory_path()/
        (L"kasa-job-tests-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64()))).lexically_normal();
    if(!std::filesystem::create_directory(root))return 2;
    struct Cleanup{std::filesystem::path p;~Cleanup(){std::error_code e;std::filesystem::remove(p,e);}} cleanup{root};
    std::unique_ptr<EVP_PKEY,decltype(&EVP_PKEY_free)> key(EVP_PKEY_Q_keygen(nullptr,nullptr,"ED25519"),EVP_PKEY_free);
    std::unique_ptr<EVP_MD_CTX,decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    if(!key || !ctx)return 2;
    PreparationRequest request{"1.1.0-test.2","v1.1.0-test.3",Channel::Test,{},1500,root};
    std::size_t public_size=32;
    if(EVP_PKEY_get_raw_public_key(key.get(),request.pinned_key.data(),&public_size)!=1)return 2;
    nlohmann::json json={{"schema",1U},{"product","KASA"},{"platform","windows-x64"},
        {"version","1.1.0-test.3"},{"prerelease",true},{"asset","KASA-Setup-1.1.0-test.3.exe"},
        {"size",3U},{"sha256","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"issued_at",1000U},{"expires_at",2000U}};
    const auto descriptor=json.dump();std::array<unsigned char,64> signature{};std::size_t size=64;
    if(EVP_DigestSignInit(ctx.get(),nullptr,nullptr,nullptr,key.get())!=1 || EVP_DigestSign(ctx.get(),signature.data(),&size,
        reinterpret_cast<const unsigned char*>(descriptor.data()),descriptor.size())!=1)return 2;
    std::atomic<bool> release{false},entered{false};std::string payload="abc";
    const DownloadTransport transport=[&](std::wstring_view url,auto,const std::atomic<bool>& cancelled,const DownloadSink& sink){
        entered=true;while(!release && !cancelled)std::this_thread::sleep_for(1ms);
        if(cancelled)return DownloadResult{DownloadError::Cancelled};
        std::span<const unsigned char> bytes;
        if(url.ends_with(L".json"))bytes={reinterpret_cast<const unsigned char*>(descriptor.data()),descriptor.size()};
        else if(url.ends_with(L".sig"))bytes=signature;
        else bytes={reinterpret_cast<const unsigned char*>(payload.data()),payload.size()};
        if(!sink(bytes))return DownloadResult{DownloadError::SinkFailed};
        return DownloadResult{DownloadError::None,200,0,bytes.size()};
    };
    const auto wait=[&](UpdatePreparation& job){
        const auto end=std::chrono::steady_clock::now()+5s;
        while(job.snapshot().phase==PreparePhase::Preparing && std::chrono::steady_clock::now()<end)std::this_thread::sleep_for(1ms);
        if(job.snapshot().phase==PreparePhase::Preparing){job.cancel();return false;}return true;
    };
    UpdatePreparation job;
    check(job.snapshot().phase==PreparePhase::Idle,"initial idle");
    auto untrusted=request;untrusted.pinned_key={};
    check(!job.start(untrusted,transport),"missing trust root rejected before worker");
    check(!job.start(request,{}),"missing transport rejected");
    check(job.start(request,transport),"start background job");
    check(job.snapshot().phase==PreparePhase::Preparing,"preparing status nonblocking");
    check(!job.start(request,transport),"duplicate start refused");
    check(!job.reset(),"reset refuses active worker");
    check(!job.take_ready(true,false,false,1500),"no premature handoff");
    job.cancel();check(wait(job),"cancel worker finishes");
    check(job.snapshot().phase==PreparePhase::Cancelled,"cancel state");
    check(std::filesystem::is_empty(root),"cancel leaves no staging");
    check(job.reset() && job.snapshot().phase==PreparePhase::Idle,"reset after cancellation");
    release=true;
    check(job.start(request,transport) && wait(job),"successful restart");
    check(job.snapshot().phase==PreparePhase::Ready,"ready status");
    check(job.snapshot().received==3 && job.snapshot().total==3,"payload progress excludes metadata");
    check(!job.start(request,transport),"ready package cannot be silently replaced");
    check(!job.take_ready(false,false,false,1500),"handoff requires approval");
    check(!job.take_ready(true,true,false,1500),"busy gate");
    check(!job.take_ready(true,false,true,1500),"unsaved output gate");
    check(!job.take_ready(true,false,false,2000),"expiry gate");
    auto transferred=job.take_ready(true,false,false,1500);
    check(transferred && job.snapshot().phase==PreparePhase::Transferred,"approved transfer");
    check(!job.take_ready(true,false,false,1500),"one-time ownership transfer");
    check(job.reset(),"reset transferred job");
    check(transferred && std::filesystem::exists(transferred->path()),"new owner retains locks and file");
    transferred.reset();check(std::filesystem::is_empty(root),"new owner cleanup");
    payload="abd";
    check(job.start(request,transport) && wait(job),"bad payload job finishes");
    check(job.snapshot().phase==PreparePhase::Failed,"bad payload failed state");
    check(!job.take_ready(true,false,false,1500),"failed package never transfers");
    check(std::filesystem::is_empty(root),"failed job cleanup");check(job.reset(),"reset failure");
    payload="abc";
    check(job.start(request,transport) && wait(job),"ready cancellation fixture");
    job.cancel();
    check(job.snapshot().phase==PreparePhase::Cancelled,"cancel already-ready package");
    check(!job.take_ready(true,false,false,1500) && std::filesystem::is_empty(root),"ready cancellation removes file and forbids transfer");
    check(job.reset(),"reset ready cancellation");
    payload="abc";release=false;entered=false;
    {
        UpdatePreparation closing;
        check(closing.start(request,transport),"closing job started");
        const auto deadline=std::chrono::steady_clock::now()+1s;
        while(!entered && std::chrono::steady_clock::now()<deadline)std::this_thread::sleep_for(1ms);
        check(entered,"worker entered transport before destruction");
    }
    check(std::filesystem::is_empty(root),"destructor cancels joins cleans");
    std::cout<<checks<<" checks, "<<failures<<" failures\n";return failures!=0;
}
