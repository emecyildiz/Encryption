#include "update_ui_policy.h"
#include <iostream>
int main(){using namespace kasa::updates;int n=0,f=0;const auto check=[&](bool ok){++n;if(!ok)++f;};
    check(!parse_pinned_key(""));check(!parse_pinned_key(std::string(64,'0')));
    check(!parse_pinned_key(std::string(63,'a')));check(!parse_pinned_key(std::string(65,'a')));
    check(!parse_pinned_key(std::string(64,'A')));check(!parse_pinned_key(std::string(64,'g')));
    const auto key=parse_pinned_key(std::string(64,'a'));check(key && (*key)[0]==0xaa && (*key)[31]==0xaa);
    check(may_prepare_update(true,true,false,false,PreparePhase::Idle));
    check(!may_prepare_update(false,true,false,false,PreparePhase::Idle));
    check(!may_prepare_update(true,false,false,false,PreparePhase::Idle));
    check(!may_prepare_update(true,true,true,false,PreparePhase::Idle));
    check(!may_prepare_update(true,true,false,true,PreparePhase::Idle));
    for(auto p:{PreparePhase::Preparing,PreparePhase::Ready,PreparePhase::Failed,PreparePhase::Cancelled,PreparePhase::Transferred})
        check(!may_prepare_update(true,true,false,false,p));
    check(locks_update_selection(PreparePhase::Preparing));check(locks_update_selection(PreparePhase::Ready));
    check(locks_update_selection(PreparePhase::Transferred));check(!locks_update_selection(PreparePhase::Idle));
    check(!locks_update_selection(PreparePhase::Failed));check(!locks_update_selection(PreparePhase::Cancelled));
    std::cout<<n<<" checks, "<<f<<" failures\n";return f!=0;}
