#include "AppWindow.h"
#include "verified_save.h"
#include "batch_save.h"
#include "batch_runner.h"
#include "ui_palette.h"
#include "output_path.h"
#include "operation_password.h"
#include "update_ui_policy.h"
#include <memory>
#include "resources/resource.h"

#define IMGUI_DEFINE_MATH_OPERATORS
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

#include <windows.h>
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3native.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string_view>

namespace {
    bool installedUpdateLocation(){
        wchar_t location[32768]{},module[32768]{};DWORD size=sizeof(location);
        if(RegGetValueW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{8AAE51C3-BD6C-495A-A0E6-15B0BF50C4A4}_is1",L"InstallLocation",RRF_RT_REG_SZ,nullptr,location,&size)!=ERROR_SUCCESS)return false;
        const DWORD n=GetModuleFileNameW(nullptr,module,32768);if(!n||n>=32768)return false;
        std::error_code error;
        return std::filesystem::equivalent(std::filesystem::path(module).parent_path(),std::filesystem::path(location),error) && !error;
    }
    constexpr ImVec4 COLOR_ACCENT {0.16f, 0.34f, 0.57f, 1.0f};
    constexpr ImVec4 COLOR_VIOLET {0.53f, 0.66f, 0.79f, 1.0f};
    constexpr ImVec4 COLOR_PINK {0.70f, 0.70f, 0.70f, 1.0f};
    constexpr ImVec4 COLOR_SUCCESS {0.12f, 0.43f, 0.28f, 1.0f};
    constexpr ImVec4 COLOR_WARNING {0.57f, 0.34f, 0.08f, 1.0f};
    constexpr ImVec4 COLOR_ERROR {0.72f, 0.18f, 0.22f, 1.0f};
    constexpr ImVec4 COLOR_MUTED {0.40f, 0.44f, 0.49f, 1.0f};

    struct PasswordStrength {
        float value = 0.0f;
        const char* label = "Weak";
        ImVec4 color = COLOR_ERROR;
    };

    PasswordStrength evaluatePasswordStrength(const char* password) {
        const std::size_t length = std::strlen(password);
        bool has_lower = false;
        bool has_upper = false;
        bool has_digit = false;
        bool has_symbol = false;
        for (const unsigned char character : std::string_view(password)) {
            has_lower |= std::islower(character) != 0;
            has_upper |= std::isupper(character) != 0;
            has_digit |= std::isdigit(character) != 0;
            has_symbol |= std::isalnum(character) == 0;
        }

        const int categories = static_cast<int>(has_lower) + static_cast<int>(has_upper) +
                               static_cast<int>(has_digit) + static_cast<int>(has_symbol);
        int score = 0;
        if (length >= 8) ++score;
        if (length >= 12) ++score;
        if (categories >= 3) ++score;
        if (length >= 16 && categories >= 3) ++score;
        if (categories <= 1) score = std::min(score, 1);
        else if (categories == 2) score = std::min(score, 2);

        switch (score) {
            case 4: return {1.0f, "Strong", COLOR_SUCCESS};
            case 3: return {0.75f, "Good", COLOR_ACCENT};
            case 2: return {0.50f, "Fair", COLOR_WARNING};
            default: return {0.25f, "Weak", COLOR_ERROR};
        }
    }

    std::string fitTextToWidth(const std::string& text, const float maximum_width) {
        if (maximum_width <= 0.0f || ImGui::CalcTextSize(text.c_str()).x <= maximum_width) {
            return text;
        }

        constexpr std::string_view ellipsis = "...";
        const float ellipsis_width = ImGui::CalcTextSize(ellipsis.data()).x;
        if (ellipsis_width >= maximum_width) return std::string(ellipsis);

        std::size_t byte_count = text.size();
        while (byte_count > 0) {
            --byte_count;
            while (byte_count > 0 &&
                   (static_cast<unsigned char>(text[byte_count]) & 0xC0U) == 0x80U) {
                --byte_count;
            }
            const std::string candidate = text.substr(0, byte_count) + std::string(ellipsis);
            if (ImGui::CalcTextSize(candidate.c_str()).x <= maximum_width) return candidate;
        }
        return std::string(ellipsis);
    }

    ImVec4 rgba(kasa::ui::Rgb c) { return ImVec4(c.r,c.g,c.b,1.0f); }
    void pushPrimaryButtonStyle() {
        ImGui::PushStyleColor(ImGuiCol_Button, rgba(kasa::ui::primary));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, rgba(kasa::ui::primary_hover));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, rgba(kasa::ui::primary_active));
        ImGui::PushStyleColor(ImGuiCol_Text, rgba(kasa::ui::on_primary));
    }
    void pushModalStyle() {
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 20.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(26.0f, 24.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 11.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(16.0f, 11.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(12.0f, 12.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(1,1,1,1));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.380f, 0.380f, 0.380f, 0.72f));
        ImGui::PushStyleColor(ImGuiCol_Button, rgba(kasa::ui::secondary));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, rgba(kasa::ui::secondary_hover));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, rgba(kasa::ui::secondary_active));
        ImGui::PushStyleColor(ImGuiCol_Text, rgba(kasa::ui::on_secondary));
        ImGui::PushStyleColor(ImGuiCol_ModalWindowDimBg, ImVec4(0.033f, 0.033f, 0.033f, 0.78f));
    }

    void popModalStyle() {
        ImGui::PopStyleColor(7);
        ImGui::PopStyleVar(6);
    }

    void drawModalAccent(const ImVec4& color) {
        ImDrawList* draw = ImGui::GetWindowDrawList();
        const ImVec2 position = ImGui::GetWindowPos();
        const ImVec2 size = ImGui::GetWindowSize();
        draw->AddRectFilled(position + ImVec2(24.0f, 0.0f),
                            position + ImVec2(size.x - 24.0f, 3.0f),
                            ImGui::GetColorU32(color), 3.0f);
    }

    void beginModalMessageCard(const char* id) {
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 14.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16.0f, 15.0f));
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.96f,0.97f,0.98f,1));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.333f, 0.333f, 0.333f, 0.62f));
        ImGui::BeginChild(id, ImVec2(0.0f, 0.0f),
                          ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY |
                              ImGuiChildFlags_AlwaysUseWindowPadding,
                          ImGuiWindowFlags_NoScrollbar);
        ImGui::PopStyleColor(2);
        ImGui::PopStyleVar(2);
    }

    std::filesystem::path pathFromUtf8(std::string_view value) {
        const std::u8string utf8(reinterpret_cast<const char8_t*>(value.data()), value.size());
        return std::filesystem::path(utf8);
    }

    void beginCard(const char* id, ImVec2 size) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(1,1,1,1));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(22.0f, 20.0f));
        ImGui::BeginChild(id, size, ImGuiChildFlags_Borders | ImGuiChildFlags_AlwaysUseWindowPadding);
        ImGui::PopStyleVar();
        ImGui::PopStyleColor();
    }

    void endCard() {
        ImGui::EndChild();
    }

    void drawDashedRect(ImDrawList* draw, const ImVec2& minimum, const ImVec2& maximum,
                        ImU32 color, float dash = 9.0f, float gap = 7.0f) {
        for (float x = minimum.x; x < maximum.x; x += dash + gap) {
            draw->AddLine(ImVec2(x, minimum.y), ImVec2(std::min(x + dash, maximum.x), minimum.y), color, 1.5f);
            draw->AddLine(ImVec2(x, maximum.y), ImVec2(std::min(x + dash, maximum.x), maximum.y), color, 1.5f);
        }
        for (float y = minimum.y; y < maximum.y; y += dash + gap) {
            draw->AddLine(ImVec2(minimum.x, y), ImVec2(minimum.x, std::min(y + dash, maximum.y)), color, 1.5f);
            draw->AddLine(ImVec2(maximum.x, y), ImVec2(maximum.x, std::min(y + dash, maximum.y)), color, 1.5f);
        }
    }

    void dropCallback(GLFWwindow* window, int count, const char** paths) {
        auto* app = static_cast<AppWindow*>(glfwGetWindowUserPointer(window));
        if (app) {
            app->handleDroppedPaths(count, paths);
        }
    }

    std::vector<std::filesystem::path> openFileDialog() {
        std::vector<std::filesystem::path> paths;
        IFileOpenDialog* dialog = nullptr;
        if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                    IID_PPV_ARGS(&dialog)))) {
            return paths;
        }

        FILEOPENDIALOGOPTIONS options = 0;
        dialog->GetOptions(&options);
        dialog->SetOptions(options | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST | FOS_ALLOWMULTISELECT);
        if (SUCCEEDED(dialog->Show(nullptr))) {
            IShellItemArray* items = nullptr;
            if (SUCCEEDED(dialog->GetResults(&items))) {
                DWORD count = 0;
                items->GetCount(&count);
                for (DWORD index = 0; index < count; ++index) {
                    IShellItem* item = nullptr;
                    if (SUCCEEDED(items->GetItemAt(index, &item))) {
                        PWSTR value = nullptr;
                        if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &value))) {
                            paths.emplace_back(value);
                            CoTaskMemFree(value);
                        }
                        item->Release();
                    }
                }
                items->Release();
            }
        }
        dialog->Release();
        return paths;
    }

    std::optional<std::filesystem::path> openFolderDialog(const wchar_t* title) {
        IFileOpenDialog* dialog = nullptr;
        if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                    IID_PPV_ARGS(&dialog)))) {
            return std::nullopt;
        }
        FILEOPENDIALOGOPTIONS options = 0;
        dialog->GetOptions(&options);
        dialog->SetOptions(options | FOS_FORCEFILESYSTEM | FOS_PICKFOLDERS | FOS_PATHMUSTEXIST);
        dialog->SetTitle(title);

        std::optional<std::filesystem::path> result;
        if (SUCCEEDED(dialog->Show(nullptr))) {
            IShellItem* item = nullptr;
            if (SUCCEEDED(dialog->GetResult(&item))) {
                PWSTR value = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &value))) {
                    result = std::filesystem::path(value);
                    CoTaskMemFree(value);
                }
                item->Release();
            }
        }
        dialog->Release();
        return result;
    }

    std::optional<std::filesystem::path> saveFileDialog(const std::filesystem::path& suggested_name) {
        IFileSaveDialog* dialog = nullptr;
        if (FAILED(CoCreateInstance(CLSID_FileSaveDialog, nullptr, CLSCTX_INPROC_SERVER,
                                    IID_PPV_ARGS(&dialog)))) {
            return std::nullopt;
        }
        FILEOPENDIALOGOPTIONS options = 0;
        dialog->GetOptions(&options);
        dialog->SetOptions(options | FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT);
        dialog->SetFileName(suggested_name.wstring().c_str());

        std::optional<std::filesystem::path> result;
        if (SUCCEEDED(dialog->Show(nullptr))) {
            IShellItem* item = nullptr;
            if (SUCCEEDED(dialog->GetResult(&item))) {
                PWSTR value = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &value))) {
                    result = std::filesystem::path(value);
                    CoTaskMemFree(value);
                }
                item->Release();
            }
        }
        dialog->Release();
        return result;
    }
}

AppWindow::AppWindow() = default;

AppWindow::~AppWindow() {
    if(installer_worker.joinable())installer_worker.join();
    update_preparation.cancel();
    cancel_requested = true;
    if (worker.joinable()) {
        worker.join();
    }
    OPENSSL_cleanse(password.data(), password.size());
    OPENSSL_cleanse(password_confirmation.data(), password_confirmation.size());

    std::error_code cleanup_error;
    if (!staging_directory.empty()) {
        std::filesystem::remove_all(staging_directory, cleanup_error);
    }

    if (imgui_initialized) {
        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplGlfw_Shutdown();
        ImGui::DestroyContext();
    }
    if (window) {
        glfwDestroyWindow(window);
    }
    glfwTerminate();
    if (com_initialized) {
        CoUninitialize();
    }
}

bool AppWindow::init() {
    const HRESULT com_result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    com_initialized = SUCCEEDED(com_result);

    if (!glfwInit()) {
        return false;
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_DECORATED, GLFW_TRUE);
    window = glfwCreateWindow(1200, 820, "KASA - Local File Protection", nullptr, nullptr);
    if (!window) {
        return false;
    }

    glfwSetWindowSizeLimits(window, 1024, 720, GLFW_DONT_CARE, GLFW_DONT_CARE);
    const HWND native_window = glfwGetWin32Window(window);
    const HINSTANCE instance = GetModuleHandleW(nullptr);
    const auto large_icon = reinterpret_cast<HICON>(LoadImageW(
        instance, MAKEINTRESOURCEW(IDI_KASA_ICON), IMAGE_ICON,
        GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_SHARED));
    const auto small_icon = reinterpret_cast<HICON>(LoadImageW(
        instance, MAKEINTRESOURCEW(IDI_KASA_ICON), IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED));
    if (large_icon) SendMessageW(native_window, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(large_icon));
    if (small_icon) SendMessageW(native_window, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(small_icon));

    glfwMakeContextCurrent(window);
    glfwSetWindowUserPointer(window, this);
    glfwSetDropCallback(window, dropCallback);
    setupImGui();
    const auto installed_version = kasa::updates::parse_version(KASA_RELEASE_VERSION);
    update_channel = installed_version && installed_version->test ? 1 : 0;
    DWORD preference = 1, preference_size = sizeof(preference);
    if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Emecworks\\KASA\\Updates", L"Startup",
            RRF_RT_REG_DWORD, nullptr, &preference, &preference_size) == ERROR_SUCCESS)
        update_on_startup = preference != 0;
    preference = static_cast<DWORD>(update_channel); preference_size = sizeof(preference);
    if (RegGetValueW(HKEY_CURRENT_USER, L"Software\\Emecworks\\KASA\\Updates", L"Channel",
            RRF_RT_REG_DWORD, nullptr, &preference, &preference_size) == ERROR_SUCCESS)
        update_channel = preference == 1 ? 1 : 0;
    if (update_on_startup) {
        update_check.start(update_channel ? kasa::updates::Channel::Test : kasa::updates::Channel::Stable);
        next_update_check = glfwGetTime() + 30;
    }

    const auto session_id = std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64());
    staging_directory = std::filesystem::temp_directory_path() / "KASA" / session_id;
    std::error_code create_error;
    std::filesystem::create_directories(staging_directory, create_error);
    if (create_error) {
        notice = "The temporary workspace could not be created.";
        return false;
    }
    return true;
}

void AppWindow::setupImGui() {
    glfwSwapInterval(1);
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr;

    static const ImWchar glyph_ranges[] = {
        0x0020, 0x00FF,
        0x011E, 0x011F,
        0x0130, 0x0131,
        0x015E, 0x015F,
        0x2022, 0x2022,
        0x2713, 0x2713,
        0
    };
    if (std::filesystem::exists("C:/Windows/Fonts/segoeui.ttf")) {
        io.FontDefault = io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/segoeui.ttf", 17.0f,
                                                      nullptr, glyph_ranges);
    }
    if (std::filesystem::exists("C:/Windows/Fonts/seguisb.ttf")) {
        heading_font = io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/seguisb.ttf", 21.0f,
                                                    nullptr, glyph_ranges);
    }
    if (std::filesystem::exists("C:/Windows/Fonts/segoeuib.ttf")) {
        title_font = io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/segoeuib.ttf", 31.0f,
                                                  nullptr, glyph_ranges);
    }

    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    style.ChildRounding = 8.0f;
    style.FrameRounding = 5.0f;
    style.PopupRounding = 8.0f;
    style.ScrollbarRounding = 12.0f;
    style.FramePadding = ImVec2(12.0f, 8.0f);
    style.ItemSpacing = ImVec2(10.0f, 8.0f);
    style.ItemInnerSpacing = ImVec2(8.0f, 7.0f);
    style.WindowPadding = ImVec2(0.0f, 0.0f);
    style.CellPadding = ImVec2(9.0f, 0.0f);
    style.ScrollbarSize = 11.0f;
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.047f, 0.047f, 0.047f, 1.0f);
    style.Colors[ImGuiCol_ChildBg] = ImVec4(0.099f, 0.099f, 0.099f, 1.0f);
    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.136f, 0.136f, 0.136f, 1.0f);
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.180f, 0.180f, 0.180f, 1.0f);
    style.Colors[ImGuiCol_Button] = ImVec4(0.150f, 0.150f, 0.150f, 1.0f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.433f, 0.433f, 0.433f, 1.0f);
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.520f, 0.520f, 0.520f, 1.0f);
    style.Colors[ImGuiCol_CheckMark] = COLOR_ACCENT;
    style.Colors[ImGuiCol_SliderGrab] = COLOR_ACCENT;
    style.Colors[ImGuiCol_Header] = ImVec4(0.320f, 0.320f, 0.320f, 1.0f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.443f, 0.443f, 0.443f, 1.0f);
    style.Colors[ImGuiCol_Border] = ImVec4(0.343f, 0.343f, 0.343f, 0.42f);

    style.Colors[ImGuiCol_Text] = ImVec4(0.91f, 0.90f, 0.88f, 1.0f);
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.075f, 0.075f, 0.075f, 1.0f);
    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.15f, 0.15f, 0.15f, 1.0f);
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.19f, 0.19f, 0.19f, 1.0f);
    style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.22f, 0.22f, 0.22f, 1.0f);
    style.Colors[ImGuiCol_Button] = ImVec4(0.19f, 0.19f, 0.19f, 1.0f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.27f, 0.27f, 0.27f, 1.0f);
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.23f, 0.23f, 0.23f, 1.0f);
    style.Colors[ImGuiCol_Border] = ImVec4(0.24f, 0.24f, 0.24f, 1.0f);
    style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0.32f, 0.48f, 0.66f, 0.45f);

    style.Colors[ImGuiCol_Text] = ImVec4(0.13f,0.17f,0.22f,1);
    style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.50f,0.54f,0.58f,1);
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.95f,0.96f,0.97f,1);
    style.Colors[ImGuiCol_ChildBg] = ImVec4(1,1,1,1);
    // Combo menus use PopupBg, not ChildBg. Keep it opaque for dark text.
    style.Colors[ImGuiCol_PopupBg] = rgba(kasa::ui::popup_surface);
    style.Colors[ImGuiCol_Border] = ImVec4(0.85f,0.87f,0.90f,1);
    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.94f,0.95f,0.96f,1);
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.88f,0.91f,0.94f,1);
    style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.85f,0.89f,0.94f,1);
    style.Colors[ImGuiCol_Button] = ImVec4(0.90f,0.93f,0.96f,1);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.79f,0.85f,0.92f,1);
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.70f,0.79f,0.89f,1);
    style.Colors[ImGuiCol_Header] = ImVec4(0.89f,0.92f,0.95f,1);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.81f,0.87f,0.94f,1);
    style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.77f,0.83f,0.91f,1);
    style.Colors[ImGuiCol_Tab] = ImVec4(0.94f,0.95f,0.97f,1);
    style.Colors[ImGuiCol_TabHovered] = ImVec4(0.84f,0.89f,0.95f,1);
    style.Colors[ImGuiCol_TabSelected] = ImVec4(0.86f,0.91f,0.97f,1);
    style.Colors[ImGuiCol_TabSelectedOverline] = COLOR_ACCENT;
    style.Colors[ImGuiCol_Separator] = ImVec4(0.86f,0.89f,0.92f,1);
    style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.97f,0.98f,0.99f,1);
    style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.72f,0.76f,0.80f,1);
    style.FrameBorderSize = 1.0f;
    style.FramePadding = ImVec2(12,9);
    style.TabRounding = 6;
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");
    imgui_initialized = true;
}

void AppWindow::run() {
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        joinFinishedWorker();
        if(installer_ready){glfwSetWindowShouldClose(window,GLFW_TRUE);break;}

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        ImGui::BeginDisabled(installer_busy.load());
        renderUI();
        ImGui::EndDisabled();
        ImGui::Render();

        int display_width = 0;
        int display_height = 0;
        glfwGetFramebufferSize(window, &display_width, &display_height);
        glViewport(0, 0, display_width, display_height);
        glClearColor(0.035f, 0.047f, 0.070f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }
}

void AppWindow::renderUI() {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::Begin("KASA Workspace", nullptr, ImGuiWindowFlags_NoDecoration |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings);
    ImGui::SetCursorPos(ImVec2(28, 24));
    renderHeader();
    ImGui::SetCursorPos(ImVec2(20, 112));
    if (ImGui::BeginTable("WorkspaceColumns", 2, ImGuiTableFlags_SizingStretchProp,
            ImVec2(io.DisplaySize.x - 40, io.DisplaySize.y - 142))) {
        ImGui::TableSetupColumn("Workspace", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Settings", ImGuiTableColumnFlags_WidthFixed, 354.0f);
        ImGui::TableNextColumn();
        beginCard("WorkspaceCard", ImVec2(0, 0));
        if (ImGui::BeginTabBar("WorkspaceViews")) {
            if (ImGui::BeginTabItem("Files", nullptr, ImGuiTabItemFlags_None)) {
                renderSourcePanel();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Results", nullptr,
                    select_results ? ImGuiTabItemFlags_SetSelected : ImGuiTabItemFlags_None)) {
                select_results = false;
                renderOutputPanel();
                ImGui::EndTabItem();
            }
            const auto update_status = update_check.state();
            if (ImGui::BeginTabItem(update_status.available ? "Updates (!)###Updates" : "Updates###Updates")) {
                renderUpdates();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        endCard();
        ImGui::TableNextColumn();
        renderSettingsPanel();
        ImGui::EndTable();
    }
    ImGui::SetCursorPos(ImVec2(28, io.DisplaySize.y - 23));
    ImGui::TextColored(COLOR_MUTED, "Processed on this device  /  Folder sync and backup settings still apply");
    renderFailureModal();
    renderSuccessModal();
    renderMixedFolderModal();
    ImGui::End();
}



void AppWindow::renderUpdates() {
    ImGui::Spacing();
    ImGui::TextUnformatted("Application updates");
    ImGui::Text("Installed version: %s", KASA_RELEASE_VERSION);
    DWORD last_exit=0,exit_size=sizeof(last_exit);
    if(RegGetValueW(HKEY_CURRENT_USER,L"Software\\Emecworks\\KASA\\Updates",L"LastInstallerExit",RRF_RT_REG_DWORD,nullptr,&last_exit,&exit_size)==ERROR_SUCCESS)
        ImGui::Text("Last installer exit code: %lu (0 = completed)",last_exit);
    if(installer_busy)ImGui::TextWrapped("Rechecking the locked installer and preparing to close KASA...");
    if(installer_error)ImGui::Text("Installer handoff failed safely. Windows code: %lu",installer_error.load());
    ImGui::Separator();
    ImGui::TextWrapped("Checks the public Emecworks/Encryption releases on GitHub. Your files and passwords are never sent. GitHub receives normal connection information, including your IP address.");
    auto status = update_check.state();
    const auto preparation = update_preparation.snapshot();
    const bool selection_locked = kasa::updates::locks_update_selection(preparation.phase);
    const auto publisher_key = kasa::updates::parse_pinned_key(KASA_UPDATE_PUBLIC_KEY_HEX);
    ImGui::BeginDisabled(status.busy || selection_locked);
    bool changed = ImGui::Checkbox("Check for updates when KASA starts", &update_on_startup);
    const bool channel_changed = ImGui::Combo("Release channel", &update_channel, "Stable releases\0Test and stable releases\0");
    changed |= channel_changed;
    if (channel_changed) { update_check.reset(); status = update_check.state(); }
    if (changed) {
        HKEY key = nullptr;
        bool saved = false;
        if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Emecworks\\KASA\\Updates", 0,
                nullptr, 0, KEY_SET_VALUE, nullptr, &key, nullptr) == ERROR_SUCCESS) {
            DWORD startup = update_on_startup ? 1 : 0, channel = update_channel;
            const auto first = RegSetValueExW(key, L"Startup", 0, REG_DWORD,
                reinterpret_cast<const BYTE*>(&startup), sizeof(startup));
            const auto second = RegSetValueExW(key, L"Channel", 0, REG_DWORD,
                reinterpret_cast<const BYTE*>(&channel), sizeof(channel));
            saved = first == ERROR_SUCCESS && second == ERROR_SUCCESS;
            RegCloseKey(key);
        }
        update_settings_notice = saved ? "Update preferences saved." : "Update preferences apply to this session only; settings could not be saved.";
    }
    ImGui::EndDisabled();
    if (!update_settings_notice.empty()) ImGui::TextWrapped("%s", update_settings_notice.c_str());
    if (update_channel) ImGui::TextWrapped("Test releases may contain unfinished features. Keep independent backups of important encrypted files.");
    ImGui::BeginDisabled(status.busy || selection_locked || glfwGetTime() < next_update_check);
    if (ImGui::Button("Check now", ImVec2(150, 36))) {
        update_check.start(update_channel ? kasa::updates::Channel::Test : kasa::updates::Channel::Stable);
        next_update_check = glfwGetTime() + 30;
    }
    ImGui::EndDisabled();
    if (!status.busy && glfwGetTime() < next_update_check)
        ImGui::TextDisabled("Please wait briefly before checking again.");
    ImGui::Spacing();
    ImGui::TextWrapped("%s", status.message.c_str());
    if (status.available) ImGui::Text("Available version: %s", status.version.c_str());
    ImGui::Separator();
    if (!publisher_key) {
        ImGui::TextColored(COLOR_WARNING, "Update preparation is unavailable in this build.");
        ImGui::TextWrapped("The publisher verification key has not been configured. Release checks still work; signature verification cannot be bypassed.");
    }
    if (status.available) {
        const bool allowed = kasa::updates::may_prepare_update(publisher_key.has_value(),status.available,
            status.busy,processing.load(),preparation.phase);
        ImGui::BeginDisabled(!allowed);
        if (ImGui::Button("Download and verify", ImVec2(200,36)) && allowed) {
            try {
                kasa::updates::PreparationRequest request;
                request.installed=KASA_RELEASE_VERSION;
                request.release=status.version;
                request.channel=update_channel ? kasa::updates::Channel::Test : kasa::updates::Channel::Stable;
                request.pinned_key=*publisher_key;
                request.now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count());
                request.root=std::filesystem::temp_directory_path().lexically_normal();
                if(update_preparation.start(std::move(request))) {
                    preparing_version=status.version;
                    update_preparation_notice.clear();
                } else update_preparation_notice="Could not start update preparation.";
            } catch(...) { update_preparation_notice="The local update workspace could not be prepared."; }
        }
        ImGui::EndDisabled();
        if(processing)ImGui::TextWrapped("Wait for the current file operation before preparing an update.");
    }
    if(!update_preparation_notice.empty())ImGui::TextWrapped("%s",update_preparation_notice.c_str());
    using Phase=kasa::updates::PreparePhase;
    if(preparation.phase!=Phase::Idle) {
        ImGui::Spacing();
        ImGui::Text("Selected update: %s",preparing_version.c_str());
        ImGui::TextWrapped("%s",preparation.message.c_str());
        if(preparation.total) {
            const float progress=static_cast<float>(preparation.received)/static_cast<float>(preparation.total);
            ImGui::ProgressBar(std::clamp(progress,0.0f,1.0f),ImVec2(-1,20));
            ImGui::Text("%s / %s",formatSize(preparation.received).c_str(),formatSize(preparation.total).c_str());
        }
        if(preparation.phase==Phase::Preparing) {
            if(ImGui::Button("Cancel download"))update_preparation.cancel();
            ImGui::TextWrapped("Cancellation is checked between network operations and may take a few seconds.");
          } else if(preparation.phase==Phase::Ready) {
              bool pending=false;{std::lock_guard lock(state_mutex);pending=kasa::has_pending_outputs(outputs);}
              ImGui::TextWrapped("The installer will close KASA after a final verification. It runs interactively; review its destination and options. Your documents are not part of the installation.");
              ImGui::Checkbox("I approve closing KASA and starting this verified installer",&approve_install);
              const bool installed=installedUpdateLocation();
              const bool can_install=approve_install && !processing && !pending && !installer_busy && installed;
              if(!installed)ImGui::TextWrapped("Automatic installer handoff is available only from an installed KASA copy. Portable/development copies can check updates; use the official setup to install.");
              ImGui::BeginDisabled(!can_install);
              if(ImGui::Button("Install update") && can_install){
                  if(installer_worker.joinable())installer_worker.join();
                  installer_busy=true;installer_error=0;
                  try{installer_worker=std::thread([this]{
                      try{
                          const auto now=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
                          auto package=update_preparation.take_ready(true,false,false,now);
                          if(!package){installer_error=ERROR_INVALID_DATA;installer_busy=false;return;}
                          std::vector<wchar_t> module(32768);const auto n=GetModuleFileNameW(nullptr,module.data(),static_cast<DWORD>(module.size()));
                          unsigned long error=ERROR_BAD_PATHNAME;
                          if(n && n<module.size()){
                              const auto helper=std::filesystem::path(std::wstring(module.data(),n)).parent_path()/std::filesystem::path("KASA-Updater-" KASA_RELEASE_VERSION ".exe");
                              if(package->launch_helper(helper,now,error)){installer_ready=true;return;}
                          }
                          installer_error=error?error:ERROR_GEN_FAILURE;
                          update_preparation.reset();
                      }catch(...){installer_error=ERROR_GEN_FAILURE;update_preparation.reset();}
                      installer_busy=false;
                  });}catch(...){installer_busy=false;installer_error=ERROR_NOT_ENOUGH_MEMORY;}
              }
              ImGui::EndDisabled();
              if(processing || pending)ImGui::TextWrapped("Finish the current operation and save pending Results before installing.");
              if(ImGui::Button("Discard prepared update"))update_preparation.cancel();
        } else if(preparation.phase==Phase::Failed || preparation.phase==Phase::Cancelled) {
            if(preparation.http_status || preparation.system_error)
                ImGui::Text("HTTP: %lu | Windows error: %lu",preparation.http_status,preparation.system_error);
            if(ImGui::Button("Reset update preparation")) {
                if(update_preparation.reset()){preparing_version.clear();update_preparation_notice.clear();}
            }
        }
    }
    ImGui::Spacing();
    ImGui::TextWrapped("Downloading alone does not install an update. Installation requires your separate approval. If installation is cancelled, reopen the existing KASA application.");
}

void AppWindow::renderHeader() {
    const float top = ImGui::GetCursorPosY();
    ImGui::BeginGroup();
    if (title_font) ImGui::PushFont(title_font);
    ImGui::TextUnformatted("KASA");
    if (title_font) ImGui::PopFont();
    ImGui::TextColored(COLOR_MUTED, "Local file encryption");
    ImGui::EndGroup();
    ImGui::SetCursorPos(ImVec2(ImGui::GetWindowWidth() - 332, top + 8));
    ImGui::BeginChild("ModeSwitcher", ImVec2(304, 74), false, ImGuiWindowFlags_NoBackground);
    const bool locked = processing || !sources.empty();
    ImGui::BeginDisabled(locked);
    ImGui::PushStyleColor(ImGuiCol_Button, mode == UiMode::PROTECT ? COLOR_ACCENT : ImVec4(0.9f,0.92f,0.94f,1));
    ImGui::PushStyleColor(ImGuiCol_Text, mode == UiMode::PROTECT ? ImVec4(1,1,1,1) : ImVec4(0.18f,0.22f,0.28f,1));
    if (ImGui::Button("Encrypt", ImVec2(140, 40))) setMode(UiMode::PROTECT);
    ImGui::PopStyleColor(2);
    ImGui::SameLine(0,8);
    ImGui::PushStyleColor(ImGuiCol_Button, mode == UiMode::UNLOCK ? COLOR_ACCENT : ImVec4(0.9f,0.92f,0.94f,1));
    ImGui::PushStyleColor(ImGuiCol_Text, mode == UiMode::UNLOCK ? ImVec4(1,1,1,1) : ImVec4(0.18f,0.22f,0.28f,1));
    if (ImGui::Button("Decrypt", ImVec2(140,40))) setMode(UiMode::UNLOCK);
    ImGui::PopStyleColor(2);
    ImGui::EndDisabled();
    if (locked) ImGui::TextColored(COLOR_MUTED, "Clear the file list to switch modes.");
    ImGui::EndChild();
}

void AppWindow::renderSourcePanel() {

    if (heading_font) ImGui::PushFont(heading_font);
    ImGui::TextUnformatted(mode == UiMode::PROTECT ? "Sources" : "Encrypted files");
    if (heading_font) ImGui::PopFont();
    ImGui::TextColored(COLOR_MUTED, "Choose files or drag them onto this card.");

    ImGui::BeginDisabled(processing);
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.89f,0.92f,0.95f,1));
    if (ImGui::Button("+  Files")) chooseFiles();
    ImGui::SameLine();
    if (ImGui::Button("+  Folder")) chooseFolder();
    ImGui::PopStyleColor();
    ImGui::SameLine();
    if (ImGui::Button("Clear List")) clearSession();
    ImGui::EndDisabled();

    std::uintmax_t total_source_size = 0;
    for (const SourceItem& source : sources) total_source_size += source.size;
    if (sources.empty()) {
        ImGui::TextColored(COLOR_MUTED, "No files selected");
    } else {
        ImGui::TextColored(COLOR_MUTED, "%zu file%s selected  |  %s total",
                           sources.size(), sources.size() == 1 ? "" : "s",
                           formatSize(total_source_size).c_str());
    }

    renderSourceList();
}

void AppWindow::renderSettingsPanel() {
    bool& delete_original = source_deletion.for_mode(mode == UiMode::UNLOCK);
    beginCard("SettingsPanel", ImVec2(0, 0));
    if (heading_font) ImGui::PushFont(heading_font);
    ImGui::TextUnformatted("Operation");
    if (heading_font) ImGui::PopFont();
    ImGui::TextColored(COLOR_MUTED, mode == UiMode::PROTECT ? "Encrypt selected files" : "Restore encrypted files");
    ImGui::Separator();

    // Keep the action button visible. Only the settings area scrolls when the
    // window is short or the advanced section is expanded.
    const float settings_height = std::max(150.0f, ImGui::GetContentRegionAvail().y - 130.0f);
    ImGui::BeginChild("SecuritySettings", ImVec2(0, settings_height), ImGuiChildFlags_None);
    ImGui::BeginDisabled(processing);
    ImGui::TextColored(COLOR_MUTED, "01  /  PASSWORD");

    const ImGuiInputTextFlags password_flags = show_password ? 0 : ImGuiInputTextFlags_Password;
    ImGui::TextUnformatted("Password");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputText("##Password", password.data(), password.size(), password_flags);
    if (mode == UiMode::PROTECT) {
        if (password[0] != '\0') {
            const PasswordStrength strength = evaluatePasswordStrength(password.data());
            ImGui::PushStyleColor(ImGuiCol_PlotHistogram, strength.color);
            ImGui::ProgressBar(strength.value, ImVec2(-1, 6), "");
            ImGui::PopStyleColor();
            ImGui::TextColored(strength.color, "%s password", strength.label);
        }
        ImGui::TextUnformatted("Confirm password");
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##PasswordConfirmation", password_confirmation.data(),
                         password_confirmation.size(), password_flags);
    }
    ImGui::Checkbox("Show password", &show_password);
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::TextColored(COLOR_MUTED, "02  /  OUTPUT LOCATION");
    ImGui::Checkbox("Use source folder", &keep_source_location);
    if (keep_source_location) {
        ImGui::TextWrapped("A new file is saved next to each source.");
    } else if (mode == UiMode::PROTECT) {
        ImGui::TextWrapped("Choose where to save each output from the Results tab.");
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::PushStyleColor(ImGuiCol_Text, COLOR_ERROR);
    ImGui::TextUnformatted("03  /  SOURCE FILE DELETION");
    ImGui::Checkbox("Delete source after successful save", &delete_original);
    ImGui::TextWrapped("%s", delete_original
        ? (mode == UiMode::UNLOCK
            ? "ON: The .kasa source will be deleted after the decrypted file is verified and saved. The saved file is NOT encrypted."
            : "ON: The original unencrypted source will be deleted after the encrypted file is saved.")
        : "OFF: The source is kept. Both source and output will occupy disk space.");
    ImGui::PopStyleColor();
    if (delete_original) {
        ImGui::TextWrapped("Deletion does not use the Recycle Bin. Failed files keep their sources. Changed or busy sources may be kept with a warning.");
        ImGui::TextWrapped("Best-effort overwrite is not guaranteed secure erasure on SSDs.");
    }
    ImGui::Spacing();
    if (mode == UiMode::PROTECT) {
        if (ImGui::TreeNodeEx("Advanced settings", ImGuiTreeNodeFlags_SpanAvailWidth)) {
            show_advanced = true;
            if (ImGui::RadioButton("AES-256-GCM (recommended)", cipher == CipherType::AES256)) {
                cipher = CipherType::AES256;
            }
            if (ImGui::RadioButton("XOR (learning mode)", cipher == CipherType::XOR)) {
                cipher = CipherType::XOR;
            }
            if (cipher == CipherType::XOR) {
                ImGui::PushStyleColor(ImGuiCol_Text, COLOR_WARNING);
            ImGui::TextWrapped("XOR is not recommended for real file security.");
            ImGui::PopStyleColor();
            }
            ImGui::TreePop();
        }
    } else if (!keep_source_location) {
        ImGui::TextUnformatted("Decrypted file destination");
        const std::string destination = unlock_destination.empty()
            ? "No folder selected"
            : pathToUtf8(unlock_destination);
        ImGui::TextWrapped("%s", destination.c_str());
        ImGui::BeginDisabled(processing);
        if (ImGui::Button("Choose Destination")) chooseUnlockDestination();
        ImGui::EndDisabled();
    }

    ImGui::EndDisabled();
    if (!notice.empty()) {
        ImGui::TextWrapped("%s", notice.c_str());
    }
    ImGui::EndChild();

    // Keep deletion visible even when the settings card is scrolled.
    ImGui::PushStyleColor(ImGuiCol_Text, COLOR_ERROR);
    ImGui::TextWrapped("%s", delete_original
        ? (mode == UiMode::UNLOCK ? "After saving: DELETE .kasa source" : "After saving: DELETE original source")
        : "After saving: KEEP source and output");
    ImGui::PopStyleColor();
    const bool passwords_match = mode == UiMode::UNLOCK ||
                                 std::strcmp(password.data(), password_confirmation.data()) == 0;
    bool pending_outputs = false;
    {
        std::lock_guard lock(state_mutex);
        pending_outputs = kasa::has_pending_outputs(outputs);
    }
    const bool can_start = !processing && !pending_outputs && !sources.empty() && password[0] != '\0' && passwords_match &&
                           (mode == UiMode::PROTECT || keep_source_location ||
                            !unlock_destination.empty());
    if (!passwords_match) {
        ImGui::TextColored(COLOR_ERROR, "Passwords do not match.");
    }
    if (!processing && pending_outputs) {
        ImGui::TextWrapped("Save pending outputs in Results before starting another operation.");
    }
    if (processing) {
        const bool cancellation_pending = cancel_requested.load();
        ImGui::BeginDisabled(cancellation_pending);
        ImGui::PushStyleColor(ImGuiCol_Button, COLOR_WARNING);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.063f, 0.063f, 0.063f, 1.0f));
        if (ImGui::Button(cancellation_pending ? "CANCELLATION REQUESTED..."
                                               : "CANCEL AFTER CURRENT FILE",
                          ImVec2(-1, 46))) {
            cancel_requested = true;
        }
        ImGui::PopStyleColor(2);
        ImGui::EndDisabled();
    } else {
        ImGui::BeginDisabled(!can_start);
        ImGui::PushStyleColor(ImGuiCol_Button, COLOR_ACCENT);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1,1,1,1));
        if (ImGui::Button(mode == UiMode::PROTECT ? "Encrypt files" : "Decrypt files",
                          ImVec2(-1, 46))) {
            startProcessing();
        }
        ImGui::PopStyleColor(2);
        ImGui::EndDisabled();
    }
    endCard();
}

void AppWindow::renderSourceList() {
    const ImVec2 area_position = ImGui::GetCursorScreenPos();
    const float available_height = ImGui::GetContentRegionAvail().y;
    const float list_height = std::max(120.0f, available_height - 6.0f);
    const ImVec2 area_size(ImGui::GetContentRegionAvail().x, list_height);
    ImDrawList* parent_draw = ImGui::GetWindowDrawList();
    parent_draw->AddRectFilled(area_position, area_position + area_size,
                               IM_COL32(247, 247, 247, 210), 14.0f);
    parent_draw->AddRect(area_position, area_position + area_size,
                         IM_COL32(220, 220, 220, 120), 14.0f);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    ImGui::BeginChild("SourceList", area_size, false, ImGuiWindowFlags_NoBackground);
    ImGui::PopStyleColor();
    // Manual row drawings must use the child draw list so its clip rectangle
    // prevents scrolled rows from painting over the controls outside the list.
    ImDrawList* draw = ImGui::GetWindowDrawList();
    if (sources.empty()) {
        ImGui::SetCursorPosY(std::max(18.0f, area_size.y * 0.5f - 24.0f));
        const char* primary = mode == UiMode::PROTECT ? "Drop files to protect here"
                                                      : "Drop .kasa files here";
        const float primary_width = ImGui::CalcTextSize(primary).x;
        ImGui::SetCursorPosX((area_size.x - primary_width) * 0.5f);
        ImGui::TextUnformatted(primary);
        const char* secondary = "Files are not moved; only references are added.";
        const float secondary_width = ImGui::CalcTextSize(secondary).x;
        ImGui::SetCursorPosX((area_size.x - secondary_width) * 0.5f);
        ImGui::TextColored(COLOR_MUTED, "%s", secondary);
    }
    if (!sources.empty()) {
        const float item_step = mode == UiMode::UNLOCK ? 85.0f : 68.0f;
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(sources.size()), item_step);
        bool item_removed = false;
        while (clipper.Step() && !item_removed) {
            for (int visible_index = clipper.DisplayStart;
                 visible_index < clipper.DisplayEnd; ++visible_index) {
                const std::size_t index = static_cast<std::size_t>(visible_index);
                ImGui::PushID(visible_index);
                const ImVec2 row_start = ImGui::GetCursorScreenPos();
                draw->AddRectFilled(
                    row_start,
                    row_start + ImVec2(ImGui::GetContentRegionAvail().x, item_step - 6.0f),
                    IM_COL32(247, 247, 247, 235), 10.0f);
                ImGui::Dummy(ImVec2(8, 3));
                ImGui::SameLine();
                ImGui::BeginGroup();
                const std::string name = pathToUtf8(sources[index].path.filename());
                const auto fitted = fitTextToWidth(name, ImGui::GetContentRegionAvail().x - 155);
                ImGui::TextUnformatted(fitted.c_str());
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", name.c_str());
                ImGui::SameLine();
                ImGui::TextColored(COLOR_MUTED, "%s", formatSize(sources[index].size).c_str());
                if (sources[index].kasa_info) {
                    const KasaFileInfo& info = *sources[index].kasa_info;
                    const char* cipher_name = info.cipher == CipherType::AES256
                                                  ? "AES-256-GCM"
                                                  : "XOR + HMAC-SHA256";
                    ImGui::TextColored(COLOR_VIOLET,
                                       "%s  |  Format v%u  |  Authenticated on unlock",
                                       cipher_name, static_cast<unsigned int>(info.format_version));
                }
                const auto full_path = pathToUtf8(sources[index].path.parent_path());
                const auto short_path = fitTextToWidth(full_path, ImGui::GetContentRegionAvail().x - 48);
                ImGui::TextColored(COLOR_MUTED, "%s", short_path.c_str());
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", full_path.c_str());
                ImGui::EndGroup();
                if (!processing) {
                    ImGui::SameLine(ImGui::GetContentRegionMax().x - 30.0f);
                    if (ImGui::SmallButton("x")) {
                        sources.erase(sources.begin() + static_cast<std::ptrdiff_t>(index));
                        item_removed = true;
                    }
                }
                // Advance through a submitted item instead of changing the cursor directly.
                // ImGui 1.92 asserts when SetCursorPos extends a child window without a
                // following item, and the list clipper also relies on a stable row height.
                const float target_y = row_start.y + item_step;
                const float current_y = ImGui::GetCursorScreenPos().y;
                const float spacer_height = std::max(
                    0.0f, target_y - current_y - ImGui::GetStyle().ItemSpacing.y);
                ImGui::Dummy(ImVec2(0.0f, spacer_height));
                ImGui::PopID();
                if (item_removed) break;
            }
        }
        clipper.End();
    }
    ImGui::EndChild();
}

void AppWindow::renderOutputPanel() {

    if (heading_font) ImGui::PushFont(heading_font);
    ImGui::TextUnformatted("Results");
    if (heading_font) ImGui::PopFont();
    ImGui::PushStyleColor(ImGuiCol_Text, COLOR_MUTED);
    ImGui::TextWrapped(
                       keep_source_location
                           ? "Outputs keep the same folder locations as their sources."
                           : mode == UiMode::PROTECT
                                 ? "Save prepared encrypted files wherever you choose."
                                 : "Verified files are written to your selected folder.");
    ImGui::PopStyleColor();

    if (processing) {
        const std::size_t total = total_count.load();
        const std::size_t done = processed_count.load();
        const float fraction = total == 0 ? 0.0f : static_cast<float>(done) / static_cast<float>(total);
        ImGui::ProgressBar(fraction, ImVec2(-1, 24));
        std::lock_guard lock(state_mutex);
        ImGui::TextColored(COLOR_MUTED, "%zu / %zu  %s", done, total, current_file.c_str());
    } else if (mode == UiMode::PROTECT) {
        bool has_pending_output = false;
        {
            std::lock_guard lock(state_mutex);
            has_pending_output = std::any_of(outputs.begin(), outputs.end(), [](const OutputItem& item) {
                return item.status == ItemStatus::PENDING_SAVE;
            });
        }
        if (has_pending_output) {
            pushPrimaryButtonStyle();
            if (ImGui::Button("Save All...")) saveAllOutputs();
            ImGui::PopStyleColor(4);
        }
    }

    renderOutputList();
}

void AppWindow::renderOutputList() {
    std::vector<OutputItem> snapshot;
    {
        std::lock_guard lock(state_mutex);
        snapshot = outputs;
    }

    const ImVec2 list_position = ImGui::GetCursorScreenPos();
    const ImVec2 list_size(ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y);
    ImDrawList* parent_draw = ImGui::GetWindowDrawList();
    parent_draw->AddRectFilled(list_position, list_position + list_size,
                               IM_COL32(247, 247, 247, 205), 14.0f);
    parent_draw->AddRect(list_position, list_position + list_size,
                         IM_COL32(220, 220, 220, 110), 14.0f);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    ImGui::BeginChild("OutputList", list_size, false, ImGuiWindowFlags_NoBackground);
    ImGui::PopStyleColor();
    // Output rows belong to the child draw list so scrolling clips them at the
    // list boundary instead of painting over the panel heading and controls.
    ImDrawList* draw = ImGui::GetWindowDrawList();
    if (snapshot.empty()) {
        ImGui::SetCursorPosY(std::max(24.0f, list_size.y * 0.36f));
        const char* primary = mode == UiMode::PROTECT ? "No files processed yet"
                                                      : "Decryption results will appear here";
        ImGui::SetCursorPosX((list_size.x - ImGui::CalcTextSize(primary).x) * 0.5f);
        ImGui::TextUnformatted(primary);
        const char* secondary = "Status and saved locations appear after processing.";
        ImGui::SetCursorPosX((list_size.x - ImGui::CalcTextSize(secondary).x) * 0.5f);
        ImGui::TextColored(COLOR_MUTED, "%s", secondary);
    }
    constexpr float item_step = 94.0f;
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(snapshot.size()), item_step);
    while (clipper.Step()) {
        for (int visible_index = clipper.DisplayStart;
             visible_index < clipper.DisplayEnd; ++visible_index) {
            const std::size_t index = static_cast<std::size_t>(visible_index);
            const OutputItem& item = snapshot[index];
            ImGui::PushID(visible_index);
            const ImVec2 row_start = ImGui::GetCursorScreenPos();
            const float row_width = ImGui::GetContentRegionAvail().x;
            draw->AddRectFilled(row_start, row_start + ImVec2(row_width, item_step - 8.0f),
                                IM_COL32(247, 247, 247, 240), 12.0f);
            draw->AddRect(row_start, row_start + ImVec2(row_width, item_step - 8.0f),
                          IM_COL32(220, 220, 220, 65), 12.0f);

            const float action_width = item.status == ItemStatus::PENDING_SAVE ? 120.0f : 155.0f;
            const float text_width = std::max(90.0f, row_width - action_width - 52.0f);
            const std::string fitted_name = fitTextToWidth(item.display_name, text_width);
            const std::string fitted_message = fitTextToWidth(item.message, text_width);

            ImGui::Dummy(ImVec2(10, 7));
            ImGui::SameLine();
            ImGui::BeginGroup();
            const ImVec4 status_color = item.status == ItemStatus::FAILED ? COLOR_ERROR
                : item.status == ItemStatus::PENDING_SAVE ? COLOR_WARNING : COLOR_SUCCESS;
            ImGui::TextColored(status_color, "%s", item.status == ItemStatus::FAILED ? "!" :
                item.status == ItemStatus::PENDING_SAVE ? "..." : "✓");
            ImGui::SameLine();
            ImGui::TextUnformatted(fitted_name.c_str());
            if (ImGui::IsItemHovered() && fitted_name != item.display_name) {
                ImGui::SetTooltip("%s", item.display_name.c_str());
            }
            ImGui::TextColored(COLOR_MUTED, "%s", fitted_message.c_str());
            if (ImGui::IsItemHovered() && fitted_message != item.message) {
                ImGui::SetTooltip("%s", item.message.c_str());
            }
            ImGui::EndGroup();

            if (item.status == ItemStatus::PENDING_SAVE && !processing) {
                ImGui::SameLine(ImGui::GetContentRegionMax().x - 105.0f);
                if (ImGui::Button("Save...")) saveOutput(index);
            } else if (item.status == ItemStatus::SAVED) {
                ImGui::SameLine(ImGui::GetContentRegionMax().x - 135.0f);
                if (ImGui::SmallButton("Show in Folder")) {
                    const std::wstring argument = L"/select,\"" + item.output_path.wstring() + L"\"";
                    ShellExecuteW(nullptr, L"open", L"explorer.exe", argument.c_str(), nullptr,
                                  SW_SHOWNORMAL);
                }
            }

            const float target_y = row_start.y + item_step;
            const float current_y = ImGui::GetCursorScreenPos().y;
            const float spacer_height = std::max(
                0.0f, target_y - current_y - ImGui::GetStyle().ItemSpacing.y);
            ImGui::Dummy(ImVec2(0.0f, spacer_height));
            ImGui::PopID();
        }
    }
    clipper.End();
    ImGui::EndChild();
}

void AppWindow::renderFailureModal() {
    if (failure_modal_pending) {
        ImGui::OpenPopup("Operation failed");
        failure_modal_pending = false;
    }

    ImGui::SetNextWindowSizeConstraints(ImVec2(470.0f, 0.0f), ImVec2(540.0f, FLT_MAX));
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing,
                            ImVec2(0.5f, 0.5f));
    pushModalStyle();
    if (ImGui::BeginPopupModal("Operation failed", nullptr,
                               ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove |
                                   ImGuiWindowFlags_NoTitleBar)) {
        drawModalAccent(COLOR_ERROR);
        ImGui::TextColored(COLOR_ERROR, "ACTION NEEDED");
        if (heading_font) ImGui::PushFont(heading_font);
        ImGui::TextUnformatted(failure_modal_title.c_str());
        if (heading_font) ImGui::PopFont();
        ImGui::Dummy(ImVec2(0.0f, 4.0f));
        beginModalMessageCard("FailureMessage");
        ImGui::PushStyleColor(ImGuiCol_Text, COLOR_MUTED);
        ImGui::TextWrapped("%s", failure_modal_message.c_str());
        ImGui::PopStyleColor();
        ImGui::EndChild();
        ImGui::Dummy(ImVec2(0.0f, 4.0f));
        pushPrimaryButtonStyle();
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        const bool acknowledge_failure = ImGui::Button("Got it", ImVec2(-1.0f, 44.0f));
        ImGui::SetItemDefaultFocus();
        // Mouse-opened dialogs may not have active keyboard navigation yet.
        // Scope Enter to this focused modal; ignore its opening frame and repeats.
        if (acknowledge_failure || (!ImGui::IsWindowAppearing() &&
            ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
            (ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
             ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false)))) ImGui::CloseCurrentPopup();
        ImGui::PopStyleColor(4);
        ImGui::EndPopup();
    }
    popModalStyle();
}

void AppWindow::renderSuccessModal() {
    if (success_modal_pending) {
        ImGui::OpenPopup("Operation complete");
        success_modal_pending = false;
    }

    ImGui::SetNextWindowSizeConstraints(ImVec2(470.0f, 0.0f), ImVec2(540.0f, FLT_MAX));
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing,
                            ImVec2(0.5f, 0.5f));
    pushModalStyle();
    if (ImGui::BeginPopupModal("Operation complete", nullptr,
                               ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove |
                                   ImGuiWindowFlags_NoTitleBar)) {
        drawModalAccent(COLOR_SUCCESS);
        ImGui::TextColored(COLOR_SUCCESS, "COMPLETED");
        if (heading_font) ImGui::PushFont(heading_font);
        ImGui::TextUnformatted(success_modal_title.c_str());
        if (heading_font) ImGui::PopFont();
        ImGui::Dummy(ImVec2(0.0f, 4.0f));
        beginModalMessageCard("SuccessMessage");
        ImGui::PushStyleColor(ImGuiCol_Text, COLOR_MUTED);
        ImGui::TextWrapped("%s", success_modal_message.c_str());
        ImGui::PopStyleColor();
        ImGui::EndChild();
        ImGui::Dummy(ImVec2(0.0f, 4.0f));
        pushPrimaryButtonStyle();
        if (ImGui::IsWindowAppearing()) ImGui::SetKeyboardFocusHere();
        const bool acknowledge_success = ImGui::Button("Continue", ImVec2(-1.0f, 44.0f));
        ImGui::SetItemDefaultFocus();
        if (acknowledge_success || (!ImGui::IsWindowAppearing() &&
            ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
            (ImGui::IsKeyPressed(ImGuiKey_Enter, false) ||
             ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false)))) ImGui::CloseCurrentPopup();
        ImGui::PopStyleColor(4);
        ImGui::EndPopup();
    }
    popModalStyle();
}

void AppWindow::renderMixedFolderModal() {
    if (mixed_folder_modal_pending) {
        ImGui::OpenPopup("Mixed folder detected");
        mixed_folder_modal_pending = false;
    }

    ImGui::SetNextWindowSizeConstraints(ImVec2(500.0f, 0.0f), ImVec2(570.0f, FLT_MAX));
    ImGui::SetNextWindowPos(ImGui::GetMainViewport()->GetCenter(), ImGuiCond_Appearing,
                            ImVec2(0.5f, 0.5f));
    pushModalStyle();
    if (ImGui::BeginPopupModal("Mixed folder detected", nullptr,
                               ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove |
                                   ImGuiWindowFlags_NoTitleBar)) {
        drawModalAccent(COLOR_VIOLET);
        ImGui::TextColored(COLOR_VIOLET, "CHOOSE WORKFLOW");
        if (heading_font) ImGui::PushFont(heading_font);
        ImGui::TextUnformatted("Mixed folder detected");
        if (heading_font) ImGui::PopFont();
        ImGui::Dummy(ImVec2(0.0f, 4.0f));
        beginModalMessageCard("MixedFolderMessage");
        ImGui::PushStyleColor(ImGuiCol_Text, COLOR_MUTED);
        ImGui::TextWrapped("This folder contains both regular files and .kasa files. "
                           "Choose what KASA should do with this selection.");
        ImGui::PopStyleColor();
        ImGui::EndChild();
        ImGui::Dummy(ImVec2(0.0f, 4.0f));

        const std::string protect_label = "Protect regular files (" +
                                           std::to_string(pending_regular_files.size()) + ")";
        pushPrimaryButtonStyle();
        if (ImGui::Button(protect_label.c_str(), ImVec2(-1.0f, 46.0f))) {
            const std::vector<PendingPath> selected = pending_regular_files;
            pending_regular_files.clear();
            pending_kasa_files.clear();
            setMode(UiMode::PROTECT);
            for (const auto& selected_path : selected) {
                addFile(selected_path.path, selected_path.relative_path);
            }
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(4);
        ImGui::PushStyleColor(ImGuiCol_Text, COLOR_MUTED);
        ImGui::TextWrapped("Encrypt regular files and leave existing .kasa files unchanged.");
        ImGui::PopStyleColor();

        const std::string unlock_label = "Unlock .kasa files (" +
                                          std::to_string(pending_kasa_files.size()) + ")";
        pushPrimaryButtonStyle();
        if (ImGui::Button(unlock_label.c_str(), ImVec2(-1.0f, 46.0f))) {
            const std::vector<PendingPath> selected = pending_kasa_files;
            pending_regular_files.clear();
            pending_kasa_files.clear();
            setMode(UiMode::UNLOCK);
            for (const auto& selected_path : selected) {
                addFile(selected_path.path, selected_path.relative_path);
            }
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(4);
        ImGui::PushStyleColor(ImGuiCol_Text, COLOR_MUTED);
        ImGui::TextWrapped("Decrypt authenticated .kasa files and leave regular files unchanged.");
        ImGui::PopStyleColor();
        ImGui::Dummy(ImVec2(0.0f, 2.0f));
        if (ImGui::Button("Cancel", ImVec2(-1.0f, 40.0f))) {
            pending_regular_files.clear();
            pending_kasa_files.clear();
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    popModalStyle();
}

void AppWindow::setMode(UiMode new_mode) {
    if (mode == new_mode) return;
    clearSession();
    mode = new_mode;
    cipher = CipherType::AES256;
}

void AppWindow::handleDroppedPaths(int count, const char** paths) {
    if(installer_busy)return;
    if (processing) return;
    for (int index = 0; index < count; ++index) {
        addPath(pathFromUtf8(paths[index]));
        if (mixed_folder_modal_pending) break;
    }
}

void AppWindow::addPath(const std::filesystem::path& path) {
    try {
        if (std::filesystem::is_regular_file(path)) {
            addFile(path);
            return;
        }
        if (std::filesystem::is_directory(path)) {
            std::vector<PendingPath> regular_files;
            std::vector<PendingPath> kasa_files;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(
                     path, std::filesystem::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;

                std::error_code relative_error;
                std::filesystem::path relative_path = std::filesystem::relative(
                    entry.path(), path, relative_error);
                if (relative_error || relative_path.empty()) continue;
                if (!path.filename().empty()) relative_path = path.filename() / relative_path;

                std::string extension = entry.path().extension().string();
                std::transform(extension.begin(), extension.end(), extension.begin(),
                               [](const unsigned char character) {
                                   return static_cast<char>(std::tolower(character));
                               });
                PendingPath pending {entry.path(), std::move(relative_path)};
                if (extension == ".kasa") kasa_files.push_back(std::move(pending));
                else regular_files.push_back(std::move(pending));
            }

            // Directory iteration order is unspecified. A mixed folder therefore needs
            // an explicit choice instead of allowing whichever file appears first to
            // silently select the workflow.
            if (sources.empty() && !regular_files.empty() && !kasa_files.empty()) {
                pending_regular_files = std::move(regular_files);
                pending_kasa_files = std::move(kasa_files);
                mixed_folder_modal_pending = true;
                return;
            }

            const auto& selected_files = !sources.empty() && mode == UiMode::UNLOCK
                                             ? kasa_files
                                             : regular_files.empty() ? kasa_files : regular_files;
            for (const auto& selected_path : selected_files) {
                addFile(selected_path.path, selected_path.relative_path);
            }
        }
    } catch (const std::filesystem::filesystem_error& error) {
        notice = std::string("File scan failed: ") + error.what();
    }
}

void AppWindow::addFile(const std::filesystem::path& path,
                        std::filesystem::path relative_path) {
    std::string extension = path.extension().string();
    std::transform(extension.begin(), extension.end(), extension.begin(),
                   [](const unsigned char character) {
                       return static_cast<char>(std::tolower(character));
                   });
    const bool is_kasa = extension == ".kasa";

    std::optional<KasaFileInfo> kasa_info;
    if (is_kasa) {
        kasa_info = engine.inspect_file(path);
        if (!kasa_info) {
            notice = "This file has a .kasa extension but does not contain a supported KASA footer.";
            return;
        }
    }

    // The first source decides the workflow: .kasa files are unlocked, every
    // other file is protected. This keeps mode selection next to the actual input.
    if (sources.empty()) {
        const UiMode detected_mode = is_kasa ? UiMode::UNLOCK : UiMode::PROTECT;
        if (mode != detected_mode) setMode(detected_mode);
    }

    if ((mode == UiMode::PROTECT && is_kasa) || (mode == UiMode::UNLOCK && !is_kasa)) {
        notice = mode == UiMode::PROTECT
                     ? ".kasa files were not added to the protection list."
                     : "Unencrypted files were not added to the unlock list.";
        return;
    }
    const auto duplicate = std::find_if(sources.begin(), sources.end(),
        [&](const SourceItem& item) { return item.path == path; });
    if (duplicate != sources.end()) return;

    if (relative_path.empty() || relative_path.is_absolute() ||
        std::find(relative_path.begin(), relative_path.end(), std::filesystem::path("..")) !=
            relative_path.end()) {
        relative_path = path.filename();
    }

    std::error_code size_error;
    const std::uintmax_t size = std::filesystem::file_size(path, size_error);
    if (!size_error) sources.push_back({path, std::move(relative_path), size, kasa_info});
}

void AppWindow::clearSession() {
    if (processing) return;
    sources.clear();
    {
        std::lock_guard lock(state_mutex);
        outputs.clear();
        current_file.clear();
    }
    unlock_destination.clear();
    notice.clear();
    OPENSSL_cleanse(password.data(), password.size());
    OPENSSL_cleanse(password_confirmation.data(), password_confirmation.size());
    password.fill('\0');
    password_confirmation.fill('\0');

    std::error_code cleanup_error;
    std::filesystem::remove_all(staging_directory, cleanup_error);
    std::filesystem::create_directories(staging_directory, cleanup_error);
}

void AppWindow::retainResultsAfterSave() {
    // Keep the last operation visible. Only completed inputs leave the retry list;
    // failed and pending entries must survive a partial Save All operation.
    std::lock_guard lock(state_mutex);
    kasa::remove_saved_sources(sources, outputs);
    select_results = true;
}

void AppWindow::startProcessing() {
    if (processing) return;
    if (worker.joinable()) worker.join();
    {
        std::lock_guard lock(state_mutex);
        if (kasa::has_pending_outputs(outputs)) {
            notice = "Save pending outputs in Results before starting another operation.";
            select_results = true;
            return;
        }
    }
    if (sources.empty() || password[0] == '\0') return;
    try {
    std::vector<SourceItem> work_items = sources;
    auto password_owner = std::make_unique<OperationPassword>(password.data());
    const UiMode selected_mode = mode;
    const CipherType selected_cipher = cipher;
    const bool should_delete = source_deletion.for_mode(mode == UiMode::UNLOCK);
    const bool preserve_location = keep_source_location;
    const std::filesystem::path destination_folder = unlock_destination;

    {
        std::lock_guard lock(state_mutex);
        outputs.clear();
        current_file.clear();
    }
    processed_count = 0;
    total_count = work_items.size();
    failed_count = 0;
    deletion_warning_count = 0;
    cancel_requested = false;
    batch_stopped = false;
    worker_failed = false;
    select_results = true;
    processing = true;
    notice.clear();

    worker = std::thread([this, work_items = std::move(work_items),
                          password_owner = std::move(password_owner), selected_mode,
                          selected_cipher, should_delete, preserve_location,
                          destination_folder]() mutable {
        try {
        const auto run = kasa::run_file_batch(work_items,
            [this] { return cancel_requested.load(); },
            [&](const SourceItem& source) {
            {
                std::lock_guard lock(state_mutex);
                current_file = pathToUtf8(source.path.filename());
            }

            OutputItem result;
            result.source_path = source.path;
            result.delete_source_after_save = selected_mode == UiMode::PROTECT &&
                                              should_delete && !preserve_location;
            bool success = false;
            try {
                if (selected_mode == UiMode::PROTECT) {
                    result.relative_path = source.relative_path;
                    result.relative_path += ".kasa";
                    const std::filesystem::path output_parent = preserve_location
                        ? source.path.parent_path()
                        : staging_directory / result.relative_path.parent_path();
                    std::error_code directory_error;
                    std::filesystem::create_directories(output_parent, directory_error);
                    if (directory_error) throw std::filesystem::filesystem_error(
                        "The output folder could not be created", output_parent, directory_error);
                    result.output_path = uniquePath(output_parent,
                                                    result.relative_path.filename());
                    if (!preserve_location) {
                        result.relative_path = std::filesystem::relative(
                            result.output_path, staging_directory);
                    } else {
                        result.relative_path = result.output_path.filename();
                    }
                    result.display_name = pathToUtf8(result.relative_path);
                    success = engine.process_file(source.path, password_owner->value(), ActionType::ENCRYPT,
                                                  selected_cipher, false, result.output_path,
                                                  should_delete ? &result.source_snapshot : nullptr);
                    bool source_deleted = true;
                    if (success && preserve_location && should_delete) {
                        source_deleted = result.source_snapshot && engine.delete_file(source.path, *result.source_snapshot);
                        if (!source_deleted) ++deletion_warning_count;
                    }
                    result.staged = success && !preserve_location;
                    result.status = !success ? ItemStatus::FAILED
                                             : preserve_location ? ItemStatus::SAVED
                                                                 : ItemStatus::PENDING_SAVE;
                    result.message = !success
                                         ? "Encryption failed"
                                         : !preserve_location
                                               ? "Ready to save"
                                               : source_deleted
                                                     ? pathToUtf8(result.output_path)
                                                     : "Saved, but the source file could not be deleted";
                } else {
                    result.relative_path = source.relative_path;
                    result.relative_path.replace_extension("");
                    const std::filesystem::path destination_parent = preserve_location
                        ? source.path.parent_path()
                        : destination_folder / result.relative_path.parent_path();
                    std::error_code directory_error;
                    std::filesystem::create_directories(destination_parent, directory_error);
                    if (directory_error) throw std::filesystem::filesystem_error(
                        "The destination folder could not be created",
                        destination_parent, directory_error);
                    const std::filesystem::path desired_name = preserve_location
                        ? source.path.stem()
                        : result.relative_path.filename();
                    result.output_path = uniquePath(destination_parent, desired_name);
                    result.relative_path = preserve_location
                        ? result.output_path.filename()
                        : std::filesystem::relative(result.output_path, destination_folder);
                    result.display_name = pathToUtf8(result.relative_path);
                    success = engine.process_file(source.path, password_owner->value(), ActionType::DECRYPT,
                                                  CipherType::AES256, false, result.output_path,
                                                  should_delete ? &result.source_snapshot : nullptr);
                    bool source_deleted = true;
                    if (success && should_delete) {
                        source_deleted = result.source_snapshot && engine.delete_file(source.path, *result.source_snapshot);
                        if (!source_deleted) ++deletion_warning_count;
                    }
                    result.status = success ? ItemStatus::SAVED : ItemStatus::FAILED;
                    result.message = !success
                                         ? "Wrong password, corrupted file, or unavailable destination"
                                         : source_deleted
                                               ? pathToUtf8(result.output_path)
                                               : "Saved, but the .kasa source could not be deleted";
                }
            } catch (const std::exception& error) {
                success = false;
                result.status = ItemStatus::FAILED;
                result.message = error.what();
            } catch (...) {
                success = false;
                result.status = ItemStatus::FAILED;
                result.message = "An unexpected error occurred while processing this file.";
            }

            if (!success) ++failed_count;
            if (result.display_name.empty()) result.display_name = pathToUtf8(source.path.filename());
            {
                std::lock_guard lock(state_mutex);
                outputs.push_back(std::move(result));
            }
            ++processed_count;
        });
        batch_stopped = run.stopped_before_next;
        } catch (...) {
            // Never let an exception escape a std::thread and terminate the app.
            worker_failed = true;
        }
        {
            std::lock_guard lock(state_mutex);
            current_file.clear();
        }
        password_owner.reset();
        processing = false;
    });

    // The worker owns the only operation copy. Do not keep the password visible
    // or reusable in the UI for the rest of the save workflow.
    OPENSSL_cleanse(password.data(), password.size());
    OPENSSL_cleanse(password_confirmation.data(), password_confirmation.size());
    password.fill('\0');
    password_confirmation.fill('\0');
    } catch (...) {
        processing = false;
        select_results = false;
        total_count = 0;
        OPENSSL_cleanse(password.data(), password.size());
        OPENSSL_cleanse(password_confirmation.data(), password_confirmation.size());
        notice = "The operation could not start. Enter the password and try again.";
    }
}

void AppWindow::joinFinishedWorker() {
    if (!processing && worker.joinable()) {
        worker.join();
        const bool was_cancelled = batch_stopped.exchange(false);
        const bool aborted = worker_failed.exchange(false);
        // Also apply on cancellation: completed files must not run again on retry.
        retainResultsAfterSave();
        cancel_requested = false;
        const std::size_t failures = failed_count.exchange(0);
        const std::size_t deletion_warnings = deletion_warning_count.exchange(0);
        if (aborted) {
            failure_modal_title = "Operation interrupted";
            failure_modal_message = "An unexpected worker error stopped the batch. Recorded results remain in Results. "
                "Unfinished inputs remain in Files; inspect the destination before retrying. "
                "Save any pending outputs first.";
            failure_modal_pending = true;
        } else if (failures > 0) {
            std::ostringstream message;
            if (mode == UiMode::UNLOCK) {
                message << failures << " file" << (failures == 1 ? "" : "s")
                        << " could not be unlocked. The password may be incorrect, the file may "
                           "be corrupted, or the destination may be unavailable. No failed output "
                           "was accepted. File-specific errors appear in Results.";
                if (deletion_warnings > 0) {
                    message << "\n\n" << deletion_warnings << " successfully unlocked .kasa file"
                            << (deletion_warnings == 1 ? " was" : "s were")
                            << " not deleted; the restored output is safe.";
                }
                failure_modal_title = "Unable to unlock files";

                // Keep only failed inputs in the source list so a retry does not decrypt
                // successful files again and create duplicate outputs.
                std::vector<std::filesystem::path> successful_sources;
                {
                    std::lock_guard lock(state_mutex);
                    for (const OutputItem& output : outputs) {
                        if (output.status == ItemStatus::SAVED) successful_sources.push_back(output.source_path);
                    }
                }
                sources.erase(std::remove_if(sources.begin(), sources.end(),
                    [&](const SourceItem& source) {
                        return std::find(successful_sources.begin(), successful_sources.end(),
                                         source.path) != successful_sources.end();
                    }), sources.end());
            } else {
                message << failures << " file" << (failures == 1 ? "" : "s")
                        << " could not be protected. File-specific errors appear in Results.";
                if (keep_source_location && deletion_warnings > 0) {
                    message << "\n\n" << deletion_warnings << " protected source file"
                            << (deletion_warnings == 1 ? " was" : "s were")
                            << " not deleted; the encrypted output is safe.";
                }
                failure_modal_title = "Unable to protect files";

                if (keep_source_location) {
                    std::vector<std::filesystem::path> successful_sources;
                    {
                        std::lock_guard lock(state_mutex);
                        for (const OutputItem& output : outputs) {
                            if (output.status == ItemStatus::SAVED) successful_sources.push_back(output.source_path);
                        }
                    }
                    sources.erase(std::remove_if(sources.begin(), sources.end(),
                        [&](const SourceItem& source) {
                            return std::find(successful_sources.begin(), successful_sources.end(),
                                             source.path) != successful_sources.end();
                        }), sources.end());
                }
            }
            failure_modal_message = message.str();
            failure_modal_pending = true;
        } else if (!was_cancelled && mode == UiMode::UNLOCK && processed_count.load() > 0) {
            const std::size_t unlocked_count = processed_count.load();
            const std::string destination = keep_source_location
                ? "beside the source files"
                : pathToUtf8(unlock_destination);
            retainResultsAfterSave();
            success_modal_title = "Files unlocked successfully";
            success_modal_message = std::to_string(unlocked_count) + " file" +
                                    (unlocked_count == 1 ? " was" : "s were") +
                                    " verified and saved to:\n" + destination +
                                    "\n\nSaved locations remain available in Results.";
            if (deletion_warnings > 0) {
                success_modal_message += "\n\n" + std::to_string(deletion_warnings) +
                                         " .kasa source file" +
                                         (deletion_warnings == 1 ? " was" : "s were") +
                                         " not deleted.";
            }
            success_modal_pending = true;
        } else if (!was_cancelled && mode == UiMode::PROTECT && keep_source_location &&
                   processed_count.load() > 0) {
            const std::size_t protected_count = processed_count.load();
            retainResultsAfterSave();
            success_modal_title = "Files protected successfully";
            success_modal_message = std::to_string(protected_count) + " file" +
                                    (protected_count == 1 ? " was" : "s were") +
                                    " encrypted beside the source files.\n\nSaved locations "
                                    "remain available in Results.";
            if (deletion_warnings > 0) {
                success_modal_message += "\n\n" + std::to_string(deletion_warnings) +
                                         " source file" +
                                         (deletion_warnings == 1 ? " was" : "s were") +
                                         " not deleted.";
            }
            success_modal_pending = true;
        }
        if (was_cancelled) {
            notice = "Stopped before the next file. " + std::to_string(processed_count.load()) +
                " of " + std::to_string(total_count.load()) +
                " files attempted. Unfinished inputs remain in Files; save any pending outputs first.";
        }
    }
}

void AppWindow::chooseFiles() {
    for (const auto& path : openFileDialog()) addFile(path);
}

void AppWindow::chooseFolder() {
    if (const auto folder = openFolderDialog(L"Choose a folder for KASA")) addPath(*folder);
}

void AppWindow::chooseUnlockDestination() {
    if (const auto folder = openFolderDialog(L"Choose where decrypted files will be saved")) {
        unlock_destination = *folder;
    }
}

void AppWindow::saveOutput(std::size_t index) {
    if(processing)return;
    OutputItem item;
    {
        std::lock_guard lock(state_mutex);
        if (index >= outputs.size() || outputs[index].status != ItemStatus::PENDING_SAVE) return;
        item = outputs[index];
    }
    const auto destination = saveFileDialog(item.relative_path.filename());
    if (!destination) return;

    kasa::SaveOutcome outcome=kasa::SaveOutcome::Failed;
    try {
        outcome=kasa::save_prepared(item,destination,
            [this](const auto& source,const auto& target){return moveStagedOutput(source,target);},
            [this](const auto& output){return output.source_snapshot&&engine.delete_file(output.source_path,*output.source_snapshot);});
    }catch(...){item.message=kasa::save_failure_message;}
    const bool moved=outcome==kasa::SaveOutcome::Saved||outcome==kasa::SaveOutcome::SavedWithWarning;
    bool all_saved = false;
    std::size_t saved_count = 0;
    std::size_t delete_warning_count = 0;
    {
        std::lock_guard lock(state_mutex);
        // A failed move remains pending so the user can choose another destination.
        outputs[index]=std::move(item);
        all_saved = !outputs.empty() && std::all_of(outputs.begin(), outputs.end(),
            [](const OutputItem& output) { return output.status == ItemStatus::SAVED; });
        saved_count = outputs.size();
        delete_warning_count = static_cast<std::size_t>(std::count_if(
            outputs.begin(), outputs.end(), [](const OutputItem& output) {
                return output.message == "Saved, but the source file could not be deleted";
            }));
    }

    if (moved) retainResultsAfterSave();
    if (!moved) {
        failure_modal_title = "Unable to save the file";
        failure_modal_message = "The encrypted output could not be saved. Choose another "
                                "destination and try again. The staged output is still available.";
        failure_modal_pending = true;
    } else if (all_saved) {
        retainResultsAfterSave();
        success_modal_title = "Files saved successfully";
        success_modal_message = std::to_string(saved_count) + " encrypted file" +
                                (saved_count == 1 ? " was" : "s were") +
                                " saved. Saved locations remain available in Results.";
        if (delete_warning_count > 0) {
            success_modal_message += "\n\n" + std::to_string(delete_warning_count) +
                                     " source file" + (delete_warning_count == 1 ? " was" : "s were") +
                                     " not deleted.";
        }
        success_modal_pending = true;
    }
}

void AppWindow::saveAllOutputs() {
    if(processing)return;
    const auto folder = openFolderDialog(L"Choose where encrypted outputs will be saved");
    if (!folder) return;

    std::vector<OutputItem> work;
    {
        std::lock_guard lock(state_mutex);
        work=outputs;
    }
    const auto summary=kasa::save_all_prepared(work,folder,
        [this](const auto& parent,const auto& relative){return uniquePath(parent/relative.parent_path(),relative.filename());},
        [this](const auto& source,const auto& target){return moveStagedOutput(source,target);},
        [this](const auto& output){return output.source_snapshot&&engine.delete_file(output.source_path,*output.source_snapshot);});
    {std::lock_guard lock(state_mutex);outputs.swap(work);}

    retainResultsAfterSave();
    if (summary.failed > 0) {
        failure_modal_title = "Some files could not be saved";
        failure_modal_message = std::to_string(summary.failed) + " encrypted file" +
                                (summary.failed == 1 ? " remains" : "s remain") +
                                " ready to save. Choose another destination and try again.";
        failure_modal_pending = true;
        return;
    }

    const auto saved_count=summary.saved;
    const auto delete_warning_count=summary.delete_warnings;
    if(saved_count==0)return;
    success_modal_title = "Files saved successfully";
    success_modal_message = std::to_string(saved_count) + " encrypted file" +
                            (saved_count == 1 ? " was" : "s were") +
                            " saved to:\n" + pathToUtf8(*folder) +
                            "\n\nResults are retained, including any earlier processing errors.";
    if (delete_warning_count > 0) {
        success_modal_message += "\n\n" + std::to_string(delete_warning_count) +
                                 " source file" + (delete_warning_count == 1 ? " was" : "s were") +
                                 " not deleted.";
    }
    success_modal_pending = true;
}

std::filesystem::path AppWindow::uniquePath(const std::filesystem::path& folder,
                                            const std::filesystem::path& desired_name) const {
    return kasa::unique_output_path(folder,desired_name);
}

bool AppWindow::moveStagedOutput(const std::filesystem::path& source,
                                 const std::filesystem::path& destination) {
    // Keep the staging copy until normal session cleanup, including on failures.
    return save_verified(source, destination);
}

std::string AppWindow::formatSize(std::uintmax_t bytes) {
    static constexpr const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream output;
    output << std::fixed << std::setprecision(unit == 0 ? 0 : 1) << value << ' ' << units[unit];
    return output.str();
}

std::string AppWindow::pathToUtf8(const std::filesystem::path& path) {
    const auto value = path.u8string();
    return std::string(reinterpret_cast<const char*>(value.data()), value.size());
}
