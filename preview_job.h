#pragma once
#include <atomic>
#include <memory>
#include <optional>
#include <thread>
#include <utility>

namespace kasa::preview {
// Control methods are GUI-thread only. The worker exclusively owns pending_
// until its release-store; poll joins before exposing or discarding the result.
template<class Result> class PreviewJob {
    std::thread thread_;
    std::atomic<bool> busy_{false};
    std::unique_ptr<Result> pending_;
    bool failed_=false;
    bool closing_=false;
public:
    enum class Poll { None, Ready, Failed, Discarded };
    PreviewJob()=default;
    PreviewJob(const PreviewJob&)=delete;
    PreviewJob& operator=(const PreviewJob&)=delete;
    ~PreviewJob(){if(thread_.joinable())thread_.join();pending_.reset();}
    bool busy() const noexcept {return busy_.load(std::memory_order_acquire);}
    bool pending() const noexcept {return thread_.joinable();}
    bool closing() const noexcept {return closing_;}
    bool should_close() const noexcept {return closing_&&!busy();}
    void request_close() noexcept {closing_=true;}
    template<class Work> bool start(Work work) noexcept {
        if(closing_||busy()||thread_.joinable())return false;
        failed_=false;pending_.reset();busy_.store(true,std::memory_order_relaxed);
        try {
            thread_=std::thread([this,work=std::optional<Work>(std::move(work))]() mutable {
                try {pending_=(*work)();failed_=!pending_;}
                catch(...){pending_.reset();failed_=true;}
                work.reset(); // Release passwords even when work throws.
                busy_.store(false,std::memory_order_release);
            });
        } catch(...){busy_.store(false,std::memory_order_release);return false;}
        return true;
    }
    Poll poll(std::unique_ptr<Result>& result) {
        if(busy()||!thread_.joinable())return Poll::None;
        thread_.join();
        if(closing_){pending_.reset();return Poll::Discarded;}
        if(failed_)return Poll::Failed;
        result=std::move(pending_);return Poll::Ready;
    }
};
}
