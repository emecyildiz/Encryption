#include "source_deletion_policy.h"
#include <iostream>

int main() {
    kasa::SourceDeletionPolicy policy;
    int failures = 0;
    const auto check = [&](bool ok, const char* name) {
        if (!ok) { ++failures; std::cerr << name << '\n'; }
    };
    check(!policy.for_mode(false), "Encryption preserves sources by default");
    check(policy.for_mode(true), "Decryption deletes sources by default");
    policy.for_mode(true) = false;
    check(!policy.for_mode(true), "Decryption opt-out is retained");
    check(!policy.for_mode(false), "Decryption opt-out does not change encryption");
    policy.for_mode(false) = true;
    check(policy.for_mode(false), "Encryption opt-in is retained");
    check(!policy.for_mode(true), "Encryption opt-in does not reset decryption opt-out");
    const auto snapshot = policy;
    policy.for_mode(true) = true;
    check(!snapshot.for_mode(true), "Operation snapshot is independent");
    check(kasa::SourceDeletionPolicy{}.for_mode(true), "New session restores decryption default");
    check(kasa::needs_source_retention_confirmation(false, false), "Keeping sources requires explicit confirmation");
    check(!kasa::needs_source_retention_confirmation(false, true), "Explicit keep confirmation permits start");
    check(!kasa::needs_source_retention_confirmation(true, false), "Deletion choice does not need keep warning");
    check(!kasa::needs_source_retention_confirmation(true, true), "Confirmed deletion choice has no keep warning");
    check(kasa::needs_source_retention_confirmation(false, false), "Confirmation is not remembered for the next operation");
    std::cout << "13 checks, " << failures << " failures\n";
    return failures ? 1 : 0;
}
