#pragma once
#include <filesystem>

#ifdef KASA_SAVE_TESTING
enum class SaveFault { None, PartialWrite, Flush, CorruptCopy, Publish, AfterPublish };
#endif

// Copies to a unique sibling temporary file, flushes, compares bytes, then
// publishes without replacing an existing destination. Always retains source.
bool save_verified(const std::filesystem::path& source,
                   const std::filesystem::path& destination
#ifdef KASA_SAVE_TESTING
                   , SaveFault fault = SaveFault::None
#endif
);
