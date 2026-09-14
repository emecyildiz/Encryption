#pragma once
#include "batch_state.h"
#include <filesystem>
#include <optional>
#include <string>

namespace kasa {
enum class SaveOutcome { Skipped, Cancelled, Failed, Saved, SavedWithWarning };
inline constexpr const char* save_failure_message="Save failed. Choose another destination and try again.";
inline constexpr const char* source_delete_warning="Saved, but the source file could not be deleted";

// Destination selection is separate: cancellation must not mutate any state.
// Prepare potentially allocating success state before publishing. Never delete
// source unless the verified publisher reports success; deletion failure does
// not turn a successfully saved file back into PENDING_SAVE.
template<class Item,class Publish,class Remove>
SaveOutcome save_prepared(Item& item,const std::optional<std::filesystem::path>& destination,
                          Publish publish,Remove remove) {
    if(item.status!=BatchItemStatus::PENDING_SAVE)return SaveOutcome::Skipped;
    if(!destination)return SaveOutcome::Cancelled;
    auto saved_path=*destination;
    const auto utf8=saved_path.u8string();
    std::string saved_message(utf8.begin(),utf8.end());
    std::string failed_message=save_failure_message,warning=source_delete_warning;
    bool saved=false;
    try {saved=publish(item.output_path,saved_path);}catch(...){saved=false;}
    if(!saved){item.message.swap(failed_message);return SaveOutcome::Failed;}
    bool removed=true;
    if(item.delete_source_after_save){try{removed=remove(item);}catch(...){removed=false;}}
    item.output_path.swap(saved_path);
    item.message.swap(removed?saved_message:warning);
    item.status=BatchItemStatus::SAVED;item.staged=false;
    return removed?SaveOutcome::Saved:SaveOutcome::SavedWithWarning;
}
struct SaveSummary {std::size_t saved=0,failed=0,delete_warnings=0;bool cancelled=false;};
template<class Outputs,class Choose,class Publish,class Remove>
SaveSummary save_all_prepared(Outputs& outputs,const std::optional<std::filesystem::path>& folder,
                             Choose choose,Publish publish,Remove remove) {
    SaveSummary summary;
    if(!folder){summary.cancelled=true;return summary;}
    for(auto& item:outputs){
        if(item.status!=BatchItemStatus::PENDING_SAVE)continue;
        SaveOutcome outcome=SaveOutcome::Failed;
        try {
            auto destination=choose(*folder,item.relative_path);
            outcome=save_prepared(item,std::optional<std::filesystem::path>(destination),publish,remove);
        }catch(...){item.message=save_failure_message;}
        if(outcome==SaveOutcome::Failed)++summary.failed;
        else if(outcome==SaveOutcome::Saved||outcome==SaveOutcome::SavedWithWarning){
            ++summary.saved;if(outcome==SaveOutcome::SavedWithWarning)++summary.delete_warnings;
        }
    }
    return summary;
}
}
