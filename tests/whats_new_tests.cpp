#include "whats_new.h"
#include <iostream>

using kasa::release_notes::should_show;
static_assert(should_show("1.2.0", "", true));
static_assert(should_show("1.2.0", "1.1.0", true));
static_assert(!should_show("1.2.0", "1.2.0", true));
static_assert(should_show("1.2.0", "1.2.0-test.1", true));
static_assert(should_show("1.2.0-test.2", "1.2.0-test.1", true));
static_assert(!should_show("1.2.0", "", false));
static_assert(!should_show("", "", true));
static_assert(kasa::release_notes::entries.size() == 4);
static_assert(kasa::release_notes::entries[0].important);
static_assert(kasa::release_notes::entries[1].important);
int main() { std::cout << "10 release-note policy/content checks passed\n"; }
