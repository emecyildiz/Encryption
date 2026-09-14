#include "batch_runner.h"
#include "batch_state.h"
#include "encryption_engine.h"
#include <atomic>
#include <chrono>
#include <fstream>
#include <future>
#include <iostream>
#include <vector>
namespace fs = std::filesystem;
using Status = kasa::BatchItemStatus;
struct Source { fs::path path; };
struct Output { fs::path source_path; Status status; };
int main() {
    int checks=0, failures=0;
    auto check=[&](bool ok,const char* text){++checks;if(!ok){++failures;std::cerr<<"FAIL "<<text<<'\n';}};
    const std::vector<int> items{0,1,2};
    std::atomic<bool> cancel{true};
    int calls=0;
    auto early=kasa::run_file_batch(items,[&]{return cancel.load();},[&](int){++calls;});
    check(early.stopped_before_next&&early.attempted==0&&calls==0,"cancel before first file");
    auto empty=kasa::run_file_batch(std::vector<int>{},[&]{return cancel.load();},[&](int){++calls;});
    check(!empty.stopped_before_next&&empty.attempted==0,"empty batch not labelled cancelled");
    cancel=false;
    auto late=kasa::run_file_batch(items,[&]{return cancel.load();},[&](int i){if(i==2)cancel=true;});
    check(late.attempted==3&&!late.stopped_before_next,"late cancellation cannot relabel completed batch");
    bool fatal=false;calls=0;
    try{kasa::run_file_batch(items,[]{return false;},[&](int){++calls;throw 42;});}catch(...){fatal=true;}
    check(fatal&&calls==1,"unhandled worker error propagates without continuing");

    const auto root=fs::temp_directory_path()/("kasa-runner-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(root);
    struct Cleanup{fs::path p;~Cleanup(){std::error_code ec;fs::remove_all(p,ec);}} cleanup{root};
    encryption_engine engine;
    for(int i:items){std::ofstream f(root/(std::to_string(i)+".txt"),std::ios::binary);f<<"synthetic runner file "<<i;}
    for(bool staged:{false,true}) {
        cancel=false;
        std::promise<void> entered,release;
        auto entered_future=entered.get_future();auto gate=release.get_future().share();
        std::vector<Output> outputs;
        const auto folder=root/(staged?"staged":"saved");fs::create_directory(folder);
        auto future=std::async(std::launch::async,[&]{
            return kasa::run_file_batch(items,[&]{return cancel.load();},[&](int i){
                // Pause an admitted file: cancellation must not suppress its result.
                if(i==0){entered.set_value();gate.wait();}
                auto source=root/(std::to_string(i)+".txt");
                auto target=folder/(std::to_string(i)+".txt.kasa");
                const bool ok=engine.encrypt_aes256(source,"runner-test",false,target);
                outputs.push_back({source,ok?(staged?Status::PENDING_SAVE:Status::SAVED):Status::FAILED});
            });
        });
        const bool entered_in_time=entered_future.wait_for(std::chrono::seconds(5))==std::future_status::ready;
        cancel=true;release.set_value();
        const auto result=future.get();
        check(entered_in_time,"worker reached deterministic active-file barrier");
        check(result.attempted==1&&result.stopped_before_next,"active file completes; next file not admitted");
        check(outputs.size()==1&&outputs[0].status==(staged?Status::PENDING_SAVE:Status::SAVED),"active result retained after cancellation");
        auto plain=engine.decrypt_preview_aes(folder/"0.txt.kasa","runner-test");
        check(plain.content&&std::string(plain.content->bytes().begin(),plain.content->bytes().end())=="synthetic runner file 0","completed cipher authenticates after cancellation");
        check(!fs::exists(folder/"1.txt.kasa")&&!fs::exists(folder/"2.txt.kasa"),"unattempted files have no output");
        std::vector<Source> sources;for(int i:items)sources.push_back({root/(std::to_string(i)+".txt")});
        kasa::remove_saved_sources(sources,outputs);
        check(sources.size()==(staged?3:2),"retry retains unfinished inputs only plus pending source");
        check(kasa::has_pending_outputs(outputs)==staged,"pending output blocks retry only in staged mode");
        if(staged){outputs[0].status=Status::SAVED;kasa::remove_saved_sources(sources,outputs);}
        check(sources.size()==2&&sources[0].path.filename()=="1.txt","saved source excluded from retry");
        cancel=false;
        auto retry=kasa::run_file_batch(sources,[&]{return cancel.load();},[&](const Source& source){
            check(engine.encrypt_aes256(source.path,"runner-test",false,folder/(source.path.filename().string()+".kasa")),"retry encrypts unfinished input");
        });
        check(retry.attempted==2&&!retry.stopped_before_next,"retry processes exactly remaining two");
    }
    std::vector<Output> mixed;
    const std::vector<Source> sources{{root/"0.txt"},{root/"missing.txt"},{root/"2.txt"}};
    fs::create_directory(root/"mixed");
    const auto mixed_run=kasa::run_file_batch(sources,[]{return false;},[&](const Source& source){
        bool ok=false;
        try{ok=engine.encrypt_aes256(source.path,"runner-test",false,root/"mixed"/(source.path.filename().string()+".kasa"));}catch(...){ok=false;}
        mixed.push_back({source.path,ok?Status::SAVED:Status::FAILED});
    });
    check(mixed_run.attempted==3&&!mixed_run.stopped_before_next,"per-file failure does not stop subsequent input");
    check(mixed.size()==3&&mixed[0].status==Status::SAVED&&mixed[1].status==Status::FAILED&&mixed[2].status==Status::SAVED,"mixed success-failure-success results retained");
    auto retry_sources=sources;kasa::remove_saved_sources(retry_sources,mixed);
    check(retry_sources.size()==1&&retry_sources[0].path.filename()=="missing.txt","partial failure retry excludes successful inputs");
    check(!fs::exists(root/"mixed/missing.txt.kasa")&&!fs::exists(root/"mixed/missing.txt.kasa.tmp"),"failed input produces no accepted or temporary output");
    // Actual decrypt batch with a tampered middle input, not a mocked engine.
    fs::copy_file(root/"saved/1.txt.kasa",root/"damaged.txt.kasa");
    {std::fstream f(root/"damaged.txt.kasa",std::ios::binary|std::ios::in|std::ios::out);
     char c=0;f.read(&c,1);c^=0x40;f.seekp(0);f.write(&c,1);}
    const std::vector<Source> encrypted{{root/"saved/0.txt.kasa"},{root/"damaged.txt.kasa"},{root/"saved/2.txt.kasa"}};
    fs::create_directory(root/"decrypted");std::vector<Output> decrypted;
    const auto decrypt_run=kasa::run_file_batch(encrypted,[]{return false;},[&](const Source& source){
        const bool ok=engine.process_file(source.path,"runner-test",ActionType::DECRYPT,CipherType::AES256,false,root/"decrypted"/source.path.stem());
        decrypted.push_back({source.path,ok?Status::SAVED:Status::FAILED});
    });
    check(decrypt_run.attempted==3,"decrypt continues after authentication failure");
    check(decrypted[0].status==Status::SAVED&&decrypted[1].status==Status::FAILED&&decrypted[2].status==Status::SAVED,"decrypt mixed result sequence");
    check(!fs::exists(root/"decrypted/damaged.txt")&&!fs::exists(root/"decrypted/damaged.txt.tmp"),"failed authenticated decrypt leaves no plaintext output");
    auto decrypt_retry=encrypted;kasa::remove_saved_sources(decrypt_retry,decrypted);
    check(decrypt_retry.size()==1&&decrypt_retry[0].path==root/"damaged.txt.kasa","decrypt retry includes only damaged source");
    for(const auto* name:{"0.txt","2.txt"}){std::ifstream f(root/"decrypted"/name,std::ios::binary);std::string text{std::istreambuf_iterator<char>(f),{}};
        check(text==std::string("synthetic runner file ")+name[0],"successful decrypted content exact");}
    for(int i:items)check(fs::exists(root/(std::to_string(i)+".txt")),"original test input retained");
    std::cout<<checks<<" checks, "<<failures<<" failures\n";
    return failures?1:0;
}
