#include "preview_job.h"
#include "preview_input.h"
#include "startup_arguments.h"
#include "encryption_engine.h"
#include <shellapi.h>
#include <future>
#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>

using namespace kasa::preview;
struct Result {
    std::atomic<int>* destroyed;
    explicit Result(std::atomic<int>& count):destroyed(&count){}
    ~Result(){++*destroyed;}
};
template<class T> void completed(PreviewJob<T>& job){
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    while(job.busy()){if(std::chrono::steady_clock::now()>deadline)throw std::runtime_error("worker timeout");std::this_thread::yield();}
}
int main(){
    int checks=0,failures=0;
    auto check=[&](bool pass,const char* name){++checks;if(!pass){++failures;std::cerr<<"FAIL: "<<name<<'\n';}};
    using Job=PreviewJob<Result>;using Poll=Job::Poll;
    std::atomic<int> destroyed{0};
    {
        Job job;std::unique_ptr<Result> out;
        check(job.poll(out)==Poll::None&&!out,"idle poll");
        std::promise<void> entered,release;auto go=release.get_future().share();
        check(job.start([&]{entered.set_value();go.wait();return std::make_unique<Result>(destroyed);}),"start gated worker");
        entered.get_future().wait();
        check(job.busy()&&job.poll(out)==Poll::None&&!out,"no exposure while busy");
        check(!job.start([&]{return std::make_unique<Result>(destroyed);}),"duplicate job rejected");
        job.request_close();
        check(job.closing()&&!job.should_close(),"close waits for work");
        release.set_value();completed(job);
        check(job.should_close(),"close ready on completion");
        check(job.poll(out)==Poll::Discarded&&!out&&destroyed==1,"close discards result before presentation");
        check(!job.start([&]{return std::make_unique<Result>(destroyed);}),"closed job never restarts");
    }
    {
        Job job;std::unique_ptr<Result> out;
        job.start([&]{return std::make_unique<Result>(destroyed);});completed(job);
        job.request_close();
        check(job.poll(out)==Poll::Discarded&&!out,"close between completion and poll");
    }
    {
        Job job;std::unique_ptr<Result> out;
        job.start([]()->std::unique_ptr<Result>{throw std::runtime_error("synthetic");});completed(job);
        check(job.poll(out)==Poll::Failed&&!out,"exception contained");
        check(job.start([&]{return std::make_unique<Result>(destroyed);}),"retry after failure");completed(job);
        check(job.poll(out)==Poll::Ready&&out,"successful result ownership");
        check(job.poll(out)==Poll::None,"result delivered once");out.reset();
        job.start([]()->std::unique_ptr<Result>{return nullptr;});completed(job);
        check(job.poll(out)==Poll::Failed,"empty result treated as failure");
    }
    const int before=destroyed;
    {Job job;job.start([&]{return std::make_unique<Result>(destroyed);});}
    check(destroyed==before+1,"destructor joins and destroys unpublished result");
    {
        std::atomic<int> secret_destroyed{0};
        Job job;auto secret=std::make_unique<Result>(secret_destroyed);
        job.start([secret=std::move(secret)]()->std::unique_ptr<Result>{throw std::runtime_error("synthetic secret failure");});
        completed(job);check(secret_destroyed==1,"work captures released before completion publication");
    }

    namespace fs=std::filesystem;
    const auto root=fs::temp_directory_path()/("kasa-lifecycle-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directory(root);
    struct Cleanup{fs::path p;~Cleanup(){std::error_code ec;fs::remove_all(p,ec);}}cleanup{root};
    const auto unicode=root/L"\u00e7al\u0131\u015fma \u65e5\u672c \U0001f512";
    fs::create_directory(unicode);
    const auto src=unicode/L"\u015fifreli not.txt";const auto enc=unicode/L"\u015fifreli not.TXT.KaSa";
    {std::ofstream f(src,std::ios::binary);f<<"Synthetic Unicode path test";}
    encryption_engine engine;
    check(engine.encrypt_aes256(src,"unicode-test",false,enc),"encrypt Unicode path");
    check(kind_from_path(enc)==Kind::Text,"Unicode mixed-case routing");
    check(kind_from_path(unicode/L"image.JpEg.KaSa")==Kind::Jpeg,"JPEG mixed-case routing");
    check(kind_from_path(unicode/L"image.png")==Kind::Unsupported,"unencrypted extension rejected");
    check(kind_from_path(unicode/L"file.pdf.kasa")==Kind::Unsupported,"unsupported extension rejected");
    check(inspect_preview_input(enc)==InputStatus::Available,"Unicode preflight available");
    auto decrypted=engine.decrypt_preview_aes(enc,"unicode-test");
    check(decrypted.status==PreviewDecryptStatus::Success&&decrypted.content,"decrypt Unicode path");
    check(inspect_preview_input(root/L"missing.png.kasa")==InputStatus::Unavailable,"missing preflight");
    check(inspect_preview_input(unicode)==InputStatus::Unavailable,"directory preflight");
    HANDLE lock=CreateFileW(enc.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,0,nullptr);
    check(lock!=INVALID_HANDLE_VALUE,"lock synthetic source");
    check(inspect_preview_input(enc)==InputStatus::Unavailable,"locked source preflight");
    if(lock!=INVALID_HANDLE_VALUE)CloseHandle(lock);
    check(inspect_preview_input(enc)==InputStatus::Available,"retry preflight after unlock");
    const auto huge=root/L"huge.png.kasa";{std::ofstream f(huge,std::ios::binary);}
    fs::resize_file(huge,max_encrypted_bytes+1);
    check(inspect_preview_input(huge)==InputStatus::TooLarge,"oversize preflight");
    fs::resize_file(huge,max_encrypted_bytes);
    check(inspect_preview_input(huge)==InputStatus::Available,"exact cap preflight not format validation");
    check(inspect_preview_input(enc)==InputStatus::Available,"preflight before removal");
    fs::remove(enc); // Owned synthetic fixture only.
    auto removed=engine.decrypt_preview_aes(enc,"unicode-test");
    check(removed.status==PreviewDecryptStatus::Unavailable&&!removed.content,"actual read rechecks after preflight");
    check(!fs::exists(enc),"missing source not recreated");

    auto arguments=[&](const std::wstring& command,kasa::StartupMode expected,const std::wstring& path=L""){
        int argc=0;auto argv=CommandLineToArgvW(command.c_str(),&argc);
        check(argv&&kasa::startup_mode(argc,argv)==expected,"real Windows argument classification");
        if(argv&&expected==kasa::StartupMode::Preview)check(argv[2]==path,"Unicode quoted path preserved");
        if(argv)LocalFree(argv);
    };
    arguments(L"KASA.exe",kasa::StartupMode::Main);
    arguments(L"\"C:\\Program Files\\KASA\\KASA.exe\" --preview \""+enc.wstring()+L"\"",kasa::StartupMode::Preview,enc.wstring());
    arguments(L"KASA.exe --preview",kasa::StartupMode::Invalid);
    arguments(L"KASA.exe --preview \"\"",kasa::StartupMode::Invalid);
    arguments(L"KASA.exe --preview one two",kasa::StartupMode::Invalid);
    arguments(L"KASA.exe --other file",kasa::StartupMode::Invalid);
    std::cout<<checks<<" lifecycle/input/arguments checks; "<<failures<<" failures\n";
    return failures?1:0;
}
