#include "update_job.h"
#include <algorithm>

namespace kasa::updates {
UpdatePreparation::~UpdatePreparation(){cancel_=true;if(worker_.joinable())worker_.join();}
PreparationStatus UpdatePreparation::snapshot()const{std::lock_guard lock(mutex_);return status_;}
void UpdatePreparation::cancel(){
    cancel_=true;
    std::lock_guard lock(mutex_);
    if(status_.phase==PreparePhase::Ready){
        const bool cleaned=!result_.package || result_.package->discard();
        result_.package.reset();status_.phase=PreparePhase::Cancelled;
        status_.message=cleaned ? "Prepared update discarded." : "Update cancelled; some staging files could not be removed.";
    }
}
bool UpdatePreparation::start(PreparationRequest request,DownloadTransport transport){
    {
        std::lock_guard lock(mutex_);
        if(status_.phase!=PreparePhase::Idle || !transport ||
            std::all_of(request.pinned_key.begin(),request.pinned_key.end(),[](auto b){return b==0;}))return false;
    }
    if(worker_.joinable())worker_.join();
    cancel_=false;
    {std::lock_guard lock(mutex_);status_={PreparePhase::Preparing,0,0,"Verifying release metadata..."};}
    try{
        worker_=std::thread([this,request=std::move(request),transport=std::move(transport)]{
            StageResult result;
            try{
                const DownloadTransport reporting=[&](auto url,auto maximum,const auto& cancelled,const DownloadSink& sink){
                    const bool payload=url.ends_with(L".exe");
                    if(payload){std::lock_guard lock(mutex_);status_.total=maximum;status_.message="Downloading and verifying update...";}
                    return transport(url,maximum,cancelled,[&](auto block){
                        if(cancel_)return false;
                        if(!sink(block))return false;
                        if(payload){std::lock_guard lock(mutex_);status_.received+=block.size();}
                        return true;
                    });
                };
                result=prepare_update(request.installed,request.release,request.channel,request.pinned_key,
                    request.now,cancel_,request.root,reporting);
            }catch(...){result.error="Update preparation failed safely.";}
            if(cancel_ && result.package){
                const bool removed=result.package->discard();result.package.reset();
                result.error=removed ? "Update cancelled." : "Update cancelled; some staging files could not be removed.";
            }
            std::lock_guard lock(mutex_);
            // Cancellation can arrive between preparation completion and publication.
            if(cancel_ && result.package){
                const bool removed=result.package->discard();result.package.reset();
                result.error=removed ? "Update cancelled." : "Update cancelled; some staging files could not be removed.";
            }
            status_.http_status=result.download.http_status;status_.system_error=result.download.system_error;
            if(cancel_){status_.phase=PreparePhase::Cancelled;status_.message=result.error.empty()?"Update cancelled.":result.error;}
            else if(result){status_.phase=PreparePhase::Ready;status_.message="Update verified and ready for your approval.";}
            else{status_.phase=PreparePhase::Failed;status_.message=result.error.empty()?"Update preparation failed.":result.error;}
            result_=std::move(result);
        });
    }catch(...){std::lock_guard lock(mutex_);status_.phase=PreparePhase::Failed;status_.message="Could not start update worker.";return false;}
    return true;
}
bool UpdatePreparation::reset(){
    {std::lock_guard lock(mutex_);if(status_.phase==PreparePhase::Preparing)return false;}
    if(worker_.joinable())worker_.join();
    std::lock_guard lock(mutex_);
    if(result_.package && !result_.package->discard()){
        status_.phase=PreparePhase::Failed;status_.message="Some staging files could not be removed. Cleanup is incomplete.";return false;
    }
    result_={};status_={};cancel_=false;return true;
}
std::unique_ptr<StagedUpdate> UpdatePreparation::take_ready(bool approved,bool processing,bool pending,std::uint64_t now){
    std::lock_guard lock(mutex_);
    if(cancel_ || status_.phase!=PreparePhase::Ready || !result_.package ||
        !result_.package->may_handoff(approved,processing,pending,now))return {};
    if(cancel_)return {};
    status_.phase=PreparePhase::Transferred;status_.message="Verified package transferred to the installer controller.";
    return std::move(result_.package);
}
}
