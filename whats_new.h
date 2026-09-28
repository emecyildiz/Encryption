#pragma once

#include <array>
#include <string_view>

namespace kasa::release_notes {
// Local, compiled content. No network access, HTML or executable links.
struct Entry { const char* title; const char* body; bool important; };
inline constexpr std::array<Entry, 4> entries{{
    {"Keeping source files requires confirmation",
     "If source deletion is turned off, both encryption and decryption ask for confirmation before processing. Originals and new outputs can take additional space and may appear in the same folder.", true},
    {"New installation location",
     "Fresh installations default to your local Emecworks/KASA folder. Updates keep the existing installation location and choices; they do not move your installation or documents.", true},
    {"A simpler update experience",
     "The updated installer reuses your installation choices and shows progress or errors. KASA reopens after success unless Windows requires a restart. The first update from an older updater may still show the full installation wizard.", false},
    {"Release notes available offline",
     "You can reopen this page from Updates. These notes are included in the application; opening them does not contact a server.", false}
}};

constexpr bool should_show(std::string_view current, std::string_view acknowledged,
                           bool preference_readable) {
    return preference_readable && !current.empty() && current != acknowledged;
}
}
