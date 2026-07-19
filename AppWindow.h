#ifndef ENCRYPTION_APPWINDOW_H
#define ENCRYPTION_APPWINDOW_H

#include <GLFW/glfw3.h>
#include "encryption_engine.h"

#include <array>
#include <atomic>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

struct ImFont;

class AppWindow {
public:
    AppWindow();
    ~AppWindow();

    bool init();
    void run();
    void handleDroppedPaths(int count, const char** paths);

private:
    enum class UiMode { PROTECT, UNLOCK };
    enum class ItemStatus { READY, PROCESSING, PENDING_SAVE, SAVED, FAILED };

    struct SourceItem {
        std::filesystem::path path;
        std::uintmax_t size = 0;
        std::optional<KasaFileInfo> kasa_info;
    };

    struct OutputItem {
        std::filesystem::path source_path;
        std::filesystem::path output_path;
        std::string display_name;
        std::string message;
        ItemStatus status = ItemStatus::PROCESSING;
        bool staged = false;
        bool delete_source_after_save = false;
    };

    GLFWwindow* window = nullptr;
    bool imgui_initialized = false;
    bool com_initialized = false;
    ImFont* title_font = nullptr;
    ImFont* heading_font = nullptr;

    encryption_engine engine;
    UiMode mode = UiMode::PROTECT;
    CipherType cipher = CipherType::AES256;
    bool show_password = false;
    bool show_advanced = false;
    bool delete_original = false;
    std::array<char, 128> password {};
    std::array<char, 128> password_confirmation {};

    std::vector<SourceItem> sources;
    std::vector<OutputItem> outputs;
    std::filesystem::path unlock_destination;
    std::filesystem::path staging_directory;

    std::thread worker;
    std::atomic<bool> processing {false};
    std::atomic<bool> cancel_requested {false};
    std::atomic<std::size_t> processed_count {0};
    std::atomic<std::size_t> total_count {0};
    mutable std::mutex state_mutex;
    std::string current_file;
    std::string notice;

    void setupImGui();
    void renderUI();
    void renderTitleBar();
    void renderHeader();
    void renderSourcePanel();
    void renderOutputPanel();
    void renderSourceList();
    void renderOutputList();

    void setMode(UiMode new_mode);
    void addPath(const std::filesystem::path& path);
    void addFile(const std::filesystem::path& path);
    void clearSession();
    void startProcessing();
    void joinFinishedWorker();

    void chooseFiles();
    void chooseFolder();
    void chooseUnlockDestination();
    void saveOutput(std::size_t index);
    void saveAllOutputs();

    std::filesystem::path uniquePath(const std::filesystem::path& folder,
                                     const std::filesystem::path& desired_name) const;
    bool moveStagedOutput(const std::filesystem::path& source,
                          const std::filesystem::path& destination);
    static std::string formatSize(std::uintmax_t bytes);
    static std::string pathToUtf8(const std::filesystem::path& path);
};

#endif
