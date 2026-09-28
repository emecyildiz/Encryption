#include "update_completion_policy.h"
#include <iostream>
int main() {
    using namespace kasa::updates;
    static_assert(completion_for(0)==Completion::Relaunch);
    static_assert(completion_for(3010)==Completion::RestartRequired);
    static_assert(completion_for(2)==Completion::Cancelled);
    static_assert(completion_for(5)==Completion::Cancelled);
    for(unsigned code=1;code<65536;++code) {
        if(code==2||code==5||code==3010)continue;
        if(completion_for(code)!=Completion::Failed)return 1;
    }
    std::cout << "Completion policy passed; no process was launched\n";
}
