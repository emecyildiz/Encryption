#include "batch_save.h"
#include "output_path.h"
#include "verified_save.h"
#include "encryption_engine.h"
#include <chrono>
#include <fstream>
#include <iostream>
#include <vector>

namespace fs=std::filesystem;
using Status=kasa::BatchItemStatus;
struct Item {
    fs::path source_path,output_path,relative_path;
    std::string message="Ready to save";
    Status status=Status::PENDING_SAVE;
    bool staged=true,delete_source_after_save=false;
};
struct Source {fs::path path;};
static std::vector<char> read(const fs::path& p){std::ifstream f(p,std::ios::binary);return {std::istreambuf_iterator<char>(f),{}};}
int main(){
    int checks=0,failed=0,publishes=0,deletes=0;
    auto check=[&](bool ok,const char* name){++checks;if(!ok){++failed;std::cerr<<"FAIL: "<<name<<'\n';}};
    const auto root=fs::temp_directory_path()/("kasa-batch-save-"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    fs::create_directories(root/"stage");fs::create_directory(root/"target");
    struct Cleanup{fs::path p;~Cleanup(){std::error_code ec;fs::remove_all(p,ec);}}cleanup{root};
    encryption_engine engine;
    std::vector<Item> items;
    for(const auto* name:{L"one.txt",L"two.txt",L"\u015fifre \u65e5\u672c.txt"}){
        auto source=root/name;{std::ofstream f(source,std::ios::binary);f<<"synthetic batch plaintext";}
        auto relative=fs::path(name);relative+=L".kasa";
        auto stage=root/"stage"/relative;
        check(engine.encrypt_aes256(source,"batch-test",false,stage),"stage real AES file");
        items.push_back({source,stage,relative});
    }
    items.push_back({root/"prior-error",{},L"bad.kasa","Processing failed",Status::FAILED,false});
    items.push_back({root/"prior-saved",root/"old.kasa",L"old.kasa","Earlier save",Status::SAVED,false});
    const auto baseline=items;
    auto publish=[&](const auto& source,const auto& target){++publishes;return save_verified(source,target);};
    auto remove=[&](const Item&){++deletes;return true;}; // Never delete test input via callback.
    auto choose=[](const auto& folder,const auto& relative){return kasa::unique_output_path(folder/relative.parent_path(),relative.filename());};
    auto cancelled=kasa::save_all_prepared(items,std::nullopt,choose,publish,remove);
    check(cancelled.cancelled&&cancelled.saved==0&&publishes==0&&deletes==0,"Save All dialog cancellation has no callbacks");
    check(items[0].output_path==baseline[0].output_path&&items[0].message==baseline[0].message&&items[0].staged,"cancel preserves pending state");
    check(kasa::save_prepared(items[0],std::nullopt,publish,remove)==kasa::SaveOutcome::Cancelled&&publishes==0,"single dialog cancellation");
    auto partial=kasa::save_all_prepared(items,std::optional<fs::path>(root/"target"),
        [&](const auto& folder,const auto& relative){
            if(relative==baseline[1].relative_path)throw fs::filesystem_error("synthetic destination failure",std::make_error_code(std::errc::permission_denied));
            return choose(folder,relative);
        },publish,remove);
    check(partial.saved==2&&partial.failed==1&&publishes==2,"path exception isolated and later output saved");
    check(items[0].status==Status::SAVED&&items[2].status==Status::SAVED,"successful entries saved");
    check(items[1].status==Status::PENDING_SAVE&&items[1].staged&&items[1].output_path==baseline[1].output_path,"failure retains stage and pending state");
    check(items[3].status==Status::FAILED&&items[3].message=="Processing failed"&&items[4].message=="Earlier save","prior results unchanged");
    check(deletes==0,"no deletion when not requested");
    std::vector<Source> sources={{items[0].source_path},{items[1].source_path},{items[2].source_path},{items[3].source_path},{root/"unattempted"}};
    kasa::remove_saved_sources(sources,items);
    check(sources.size()==3&&sources[0].path==items[1].source_path&&sources[2].path==root/"unattempted","cancelled processing retry keeps failed pending unattempted inputs");
    check(kasa::has_pending_outputs(items),"pending save prevents destructive restart");
    auto occupied=root/"target"/L"occupied.kasa";{std::ofstream f(occupied);f<<"sentinel";}
    const auto sentinel=read(occupied);
    auto collision=kasa::save_prepared(items[1],std::optional<fs::path>(occupied),publish,remove);
    check(collision==kasa::SaveOutcome::Failed&&read(occupied)==sentinel,"existing destination never overwritten");
    check(items[1].status==Status::PENDING_SAVE&&read(items[1].output_path)==read(baseline[1].output_path),"failed save retains verified source");
    items[1].delete_source_after_save=true;
    auto retried=kasa::save_prepared(items[1],std::optional<fs::path>(root/"target"/items[1].relative_path),publish,
        [&](const Item&)->bool{++deletes;throw std::runtime_error("synthetic deletion error");});
    check(retried==kasa::SaveOutcome::SavedWithWarning&&items[1].status==Status::SAVED&&!items[1].staged,"deletion exception does not undo published success");
    check(deletes==1&&fs::exists(items[1].source_path)&&items[1].message==kasa::source_delete_warning,"source retained with warning");
    kasa::remove_saved_sources(sources,items);
    check(!kasa::has_pending_outputs(items)&&sources.size()==2&&sources[1].path==root/"unattempted","retry list ready after save completion");
    const int calls=publishes;
    auto again=kasa::save_all_prepared(items,std::optional<fs::path>(root/"target"),choose,publish,remove);
    check(again.saved==0&&again.failed==0&&publishes==calls,"repeat Save All skips saved and processing failures");
    for(int i=0;i<3;++i){
        check(read(items[i].output_path)==read(baseline[i].output_path),"saved ciphertext byte identity");
        auto plain=engine.decrypt_preview_aes(items[i].output_path,"batch-test");
        const std::string expected="synthetic batch plaintext";
        check(plain.content&&std::string(plain.content->bytes().begin(),plain.content->bytes().end())==expected,"saved output authenticates and decrypts");
        check(fs::exists(baseline[i].output_path)&&fs::exists(items[i].source_path),"original and staging retained");
    }
    const auto unicode=fs::path(L"\u015fifre \u65e5\u672c.txt.kasa");
    auto next=kasa::unique_output_path(root/"target",unicode);
    check(next.filename()==fs::path(L"\u015fifre \u65e5\u672c.txt (2).kasa"),"Unicode collision suffix remains Unicode");
    auto tmp=next;tmp+=L".tmp";{std::ofstream f(tmp);f<<"reserved";}
    check(kasa::unique_output_path(root/"target",unicode).filename()==fs::path(L"\u015fifre \u65e5\u672c.txt (3).kasa"),"temporary-name collision skipped");
    auto copy=baseline[0];copy.delete_source_after_save=true;
    const int removed_before=deletes;
    check(kasa::save_prepared(copy,std::optional<fs::path>(root/"never.kasa"),
        [](const auto&,const auto&)->bool{throw std::runtime_error("synthetic publisher failure");},remove)==kasa::SaveOutcome::Failed,"publisher exception contained");
    check(copy.status==Status::PENDING_SAVE&&copy.staged&&deletes==removed_before,"publisher failure never invokes deletion");
    check(!fs::exists(root/"never.kasa"),"failed publisher produces no output");
    auto blocked=root/"target"/"not-a-directory";{std::ofstream f(blocked);f<<"blocker";}
    std::vector<Item> real_failure={baseline[0],baseline[1]};
    real_failure[0].relative_path=fs::path("not-a-directory")/"file.kasa";
    auto real_summary=kasa::save_all_prepared(real_failure,std::optional<fs::path>(root/"target"),choose,publish,remove);
    check(real_summary.failed==1&&real_summary.saved==1,"real invalid parent does not abort later save");
    check(real_failure[0].status==Status::PENDING_SAVE&&real_failure[1].status==Status::SAVED,"real partial result statuses");
    std::vector<Item> warnings={baseline[0]};warnings[0].delete_source_after_save=true;
    auto warning_summary=kasa::save_all_prepared(warnings,std::optional<fs::path>(root/"target"),choose,publish,[](const Item&){return false;});
    check(warning_summary.saved==1&&warning_summary.failed==0&&warning_summary.delete_warnings==1,"batch deletion warning counted separately");
    std::cout<<checks<<" batch-save checks; "<<failed<<" failures\n";return failed?1:0;
}
