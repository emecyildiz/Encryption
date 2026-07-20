#include "AppWindow.h"
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
    constexpr ImVec4 COLOR_ACCENT {0.18f, 0.78f, 0.86f, 1.0f};
    constexpr ImVec4 COLOR_VIOLET {0.55f, 0.38f, 0.96f, 1.0f};
    constexpr ImVec4 COLOR_PINK {0.94f, 0.35f, 0.68f, 1.0f};
    constexpr ImVec4 COLOR_SUCCESS {0.25f, 0.78f, 0.52f, 1.0f};
    constexpr ImVec4 COLOR_WARNING {0.95f, 0.66f, 0.25f, 1.0f};
    constexpr ImVec4 COLOR_ERROR {0.95f, 0.35f, 0.38f, 1.0f};
    constexpr ImVec4 COLOR_MUTED {0.56f, 0.62f, 0.70f, 1.0f};

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

    void pushModalStyle() {
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 20.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(26.0f, 24.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 11.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(16.0f, 11.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(12.0f, 12.0f));
        ImGui::PushStyleVar(ImGuiStyleVar_PopupBorderSize, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_PopupBg, ImVec4(0.055f, 0.075f, 0.135f, 0.99f));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.28f, 0.34f, 0.52f, 0.72f));
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.13f, 0.18f, 0.30f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.18f, 0.27f, 0.43f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.16f, 0.38f, 0.50f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ModalWindowDimBg, ImVec4(0.015f, 0.025f, 0.060f, 0.78f));
    }

    void popModalStyle() {
        ImGui::PopStyleColor(6);
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
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.035f, 0.052f, 0.105f, 0.92f));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.24f, 0.30f, 0.46f, 0.62f));
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
        const ImVec2 position = ImGui::GetCursorScreenPos();
        const ImVec2 resolved_size(
            size.x <= 0 ? ImGui::GetContentRegionAvail().x : size.x,
            size.y <= 0 ? ImGui::GetContentRegionAvail().y : size.y);
        ImDrawList* draw = ImGui::GetWindowDrawList();
        constexpr float card_rounding = 22.0f;
        draw->AddRectFilled(position + ImVec2(0, 7), position + resolved_size + ImVec2(0, 7),
                            IM_COL32(2, 5, 14, 82), card_rounding);
        draw->AddRectFilled(position, position + resolved_size, IM_COL32(17, 24, 43, 248), card_rounding);
        draw->AddRect(position, position + resolved_size, IM_COL32(69, 82, 119, 82),
                      card_rounding, 0, 1.0f);

        // The inset accent avoids the hard, full-width edge and keeps the card corners soft.
        const float accent_start = position.x + 24.0f;
        const float accent_end = position.x + resolved_size.x - 24.0f;
        const float accent_middle = accent_start + (accent_end - accent_start) * 0.52f;
        const float accent_y = position.y + 1.5f;
        draw->AddLine(ImVec2(accent_start, accent_y), ImVec2(accent_middle, accent_y),
                      IM_COL32(47, 211, 226, 190), 3.0f);
        draw->AddLine(ImVec2(accent_middle, accent_y), ImVec2(accent_end, accent_y),
                      IM_COL32(150, 91, 244, 185), 3.0f);
        draw->AddCircleFilled(ImVec2(accent_start, accent_y), 1.5f, IM_COL32(47, 211, 226, 190), 12);
        draw->AddCircleFilled(ImVec2(accent_end, accent_y), 1.5f, IM_COL32(150, 91, 244, 185), 12);
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(24.0f, 20.0f));
        ImGui::BeginChild(id, resolved_size, ImGuiChildFlags_AlwaysUseWindowPadding,
                          ImGuiWindowFlags_NoBackground);
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
    glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);
    window = glfwCreateWindow(1240, 800, "KASA - Local File Protection", nullptr, nullptr);
    if (!window) {
        return false;
    }

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
    style.ChildRounding = 16.0f;
    style.FrameRounding = 11.0f;
    style.PopupRounding = 12.0f;
    style.ScrollbarRounding = 12.0f;
    style.FramePadding = ImVec2(14.0f, 10.0f);
    style.ItemSpacing = ImVec2(11.0f, 11.0f);
    style.ItemInnerSpacing = ImVec2(8.0f, 7.0f);
    style.WindowPadding = ImVec2(0.0f, 0.0f);
    style.CellPadding = ImVec2(9.0f, 0.0f);
    style.ScrollbarSize = 7.0f;
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.028f, 0.039f, 0.075f, 1.0f);
    style.Colors[ImGuiCol_ChildBg] = ImVec4(0.065f, 0.086f, 0.145f, 1.0f);
    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.095f, 0.122f, 0.190f, 1.0f);
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.125f, 0.165f, 0.250f, 1.0f);
    style.Colors[ImGuiCol_Button] = ImVec4(0.105f, 0.135f, 0.210f, 1.0f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.20f, 0.48f, 0.62f, 1.0f);
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.16f, 0.66f, 0.74f, 1.0f);
    style.Colors[ImGuiCol_CheckMark] = COLOR_ACCENT;
    style.Colors[ImGuiCol_SliderGrab] = COLOR_ACCENT;
    style.Colors[ImGuiCol_Header] = ImVec4(0.18f, 0.30f, 0.48f, 1.0f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.43f, 0.64f, 1.0f);
    style.Colors[ImGuiCol_Border] = ImVec4(0.25f, 0.31f, 0.47f, 0.42f);

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");
    imgui_initialized = true;
}

void AppWindow::run() {
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        joinFinishedWorker();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        renderUI();
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
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                                   ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings;
    ImGui::Begin("KASA Workspace", nullptr, flags);
    ImDrawList* background = ImGui::GetWindowDrawList();
    const ImVec2 window_pos = ImGui::GetWindowPos();
    const ImVec2 window_size = ImGui::GetWindowSize();
    background->AddRectFilledMultiColor(window_pos, window_pos + window_size,
                                        IM_COL32(7, 12, 28, 255), IM_COL32(12, 17, 38, 255),
                                        IM_COL32(9, 15, 31, 255), IM_COL32(5, 10, 24, 255));
    background->AddCircleFilled(window_pos + ImVec2(window_size.x * 0.78f, 125.0f), 260.0f,
                                IM_COL32(98, 57, 210, 18), 64);
    background->AddCircleFilled(window_pos + ImVec2(100.0f, window_size.y - 80.0f), 220.0f,
                                IM_COL32(34, 202, 218, 13), 64);

    renderTitleBar();
    ImGui::SetCursorPos(ImVec2(28.0f, 68.0f));
    renderHeader();
    ImGui::SetCursorPosX(28.0f);

    if (ImGui::BeginTable("WorkspaceColumns", 2,
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchSame,
                          ImVec2(ImGui::GetWindowWidth() - 56.0f,
                                 ImGui::GetWindowHeight() - ImGui::GetCursorPosY() - 24.0f))) {
        ImGui::TableNextColumn();
        renderSourcePanel();
        ImGui::TableNextColumn();
        renderOutputPanel();
        ImGui::EndTable();
    }
    renderFailureModal();
    renderSuccessModal();
    renderMixedFolderModal();
    ImGui::End();
}

void AppWindow::renderTitleBar() {
    const ImVec2 position = ImGui::GetCursorScreenPos();
    const float width = ImGui::GetWindowWidth();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(position, position + ImVec2(width, 50.0f), IM_COL32(8, 13, 29, 245));
    draw->AddLine(position + ImVec2(0, 49), position + ImVec2(width, 49),
                  IM_COL32(65, 78, 116, 90));
    draw->AddCircleFilled(position + ImVec2(27, 25), 14.0f, IM_COL32(42, 202, 218, 255), 28);
    draw->AddCircleFilled(position + ImVec2(27, 25), 7.0f, IM_COL32(117, 75, 230, 255), 20);

    ImGui::SetCursorScreenPos(position);
    ImGui::InvisibleButton("##TitleDrag", ImVec2(width - 150.0f, 50.0f));
    if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
        if (glfwGetWindowAttrib(window, GLFW_MAXIMIZED)) glfwRestoreWindow(window);
        else glfwMaximizeWindow(window);
    } else if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        // Let Windows own the drag loop. Moving by ImGui's per-frame mouse delta creates
        // a feedback loop between the cursor and the window and is what caused the jitter.
        ReleaseCapture();
        SendMessageW(glfwGetWin32Window(window), WM_NCLBUTTONDOWN, HTCAPTION, 0);
    }

    ImGui::SetCursorScreenPos(position + ImVec2(50, 14));
    if (heading_font) ImGui::PushFont(heading_font);
    ImGui::TextUnformatted("KASA");
    if (heading_font) ImGui::PopFont();
    ImGui::SameLine();
    ImGui::TextColored(COLOR_MUTED, "LOCAL VAULT");

    ImGui::SetCursorScreenPos(position + ImVec2(width - 138.0f, 7.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
    if (ImGui::Button("_", ImVec2(40, 34))) glfwIconifyWindow(window);
    ImGui::SameLine(0, 4);
    if (ImGui::Button("[]", ImVec2(40, 34))) {
        if (glfwGetWindowAttrib(window, GLFW_MAXIMIZED)) glfwRestoreWindow(window);
        else glfwMaximizeWindow(window);
    }
    ImGui::SameLine(0, 4);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.82f, 0.18f, 0.28f, 1.0f));
    if (ImGui::Button("X", ImVec2(40, 34))) glfwSetWindowShouldClose(window, GLFW_TRUE);
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();
    ImGui::SetCursorScreenPos(position + ImVec2(0, 50));
}

void AppWindow::renderHeader() {
    const ImVec2 position = ImGui::GetCursorScreenPos();
    const float width = ImGui::GetWindowWidth() - 56.0f;
    const ImVec2 size(width, 112.0f);
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(position + ImVec2(0, 6), position + size + ImVec2(0, 6),
                        IM_COL32(2, 4, 13, 90), 18.0f);
    draw->AddRectFilled(position, position + size, IM_COL32(22, 32, 62, 252), 18.0f);
    draw->AddCircleFilled(position + ImVec2(width - 210, 12), 150.0f,
                          IM_COL32(117, 72, 225, 30), 48);
    draw->AddCircleFilled(position + ImVec2(width * 0.48f, 145), 165.0f,
                          IM_COL32(38, 201, 217, 15), 48);
    draw->AddRect(position, position + size, IM_COL32(99, 111, 166, 100), 18.0f);
    draw->AddCircleFilled(position + ImVec2(width - 165, -5), 125.0f,
                          IM_COL32(238, 76, 165, 22), 48);

    ImGui::BeginChild("HeroHeader", size, false, ImGuiWindowFlags_NoBackground);
    ImGui::SetCursorPos(ImVec2(24, 18));
    if (title_font) ImGui::PushFont(title_font);
    ImGui::TextUnformatted(mode == UiMode::PROTECT ? "Your files. Your control."
                                                    : "Bring your files back, safely.");
    if (title_font) ImGui::PopFont();
    ImGui::SetCursorPos(ImVec2(26, 67));
    ImGui::TextColored(ImVec4(0.72f, 0.78f, 0.89f, 1.0f),
                       mode == UiMode::PROTECT
                           ? "Local AES-256-GCM protection. Your files never leave this device."
                           : "KASA detects the algorithm and verifies integrity automatically.");

    ImGui::SetCursorPos(ImVec2(width - 250.0f, 28.0f));
    ImGui::TextColored(COLOR_SUCCESS, "●  LOCAL ONLY");
    ImGui::SetCursorPos(ImVec2(width - 250.0f, 61.0f));
    ImGui::TextColored(COLOR_MUTED, "The workflow is detected from the file type");
    ImGui::EndChild();
    ImGui::Dummy(ImVec2(0, 15));
}

void AppWindow::renderSourcePanel() {
    beginCard("SourcePanel", ImVec2(0, 0));
    if (heading_font) ImGui::PushFont(heading_font);
    ImGui::TextUnformatted(mode == UiMode::PROTECT ? "Sources" : "Encrypted files");
    if (heading_font) ImGui::PopFont();
    ImGui::TextColored(COLOR_MUTED, "Choose files or drag them onto this card.");

    ImGui::BeginDisabled(processing);
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.12f, 0.24f, 0.34f, 1.0f));
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
    ImGui::Dummy(ImVec2(0, 2));

    // Keep the action button visible. Only the settings area scrolls when the
    // window is short or the advanced section is expanded.
    const float settings_height = std::max(150.0f, ImGui::GetContentRegionAvail().y - 58.0f);
    ImGui::BeginChild("SecuritySettings", ImVec2(0, settings_height), ImGuiChildFlags_None);
    ImGui::TextColored(COLOR_MUTED, "SECURITY SETTINGS");

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
                ImGui::TextColored(COLOR_WARNING,
                                   "XOR is not recommended for real file security.");
            }
            ImGui::TreePop();
        }
        ImGui::Checkbox("Delete the source after the output is saved", &delete_original);
        if (delete_original) {
            ImGui::TextColored(COLOR_WARNING,
                               "The source is deleted only after the encrypted output is saved successfully.");
        }
    } else {
        ImGui::TextUnformatted("Decrypted file destination");
        const std::string destination = unlock_destination.empty()
            ? "No folder selected"
            : pathToUtf8(unlock_destination);
        ImGui::TextColored(unlock_destination.empty() ? COLOR_WARNING : COLOR_MUTED,
                           "%s", destination.c_str());
        ImGui::BeginDisabled(processing);
        if (ImGui::Button("Choose Destination")) chooseUnlockDestination();
        ImGui::EndDisabled();
        ImGui::Checkbox("Delete the .kasa file after successful decryption", &delete_original);
    }

    if (!notice.empty()) {
        ImGui::TextWrapped("%s", notice.c_str());
    }
    ImGui::EndChild();

    const bool passwords_match = mode == UiMode::UNLOCK ||
                                 std::strcmp(password.data(), password_confirmation.data()) == 0;
    const bool can_start = !processing && !sources.empty() && password[0] != '\0' && passwords_match &&
                           (mode == UiMode::PROTECT || !unlock_destination.empty());
    if (!passwords_match) {
        ImGui::TextColored(COLOR_ERROR, "Passwords do not match.");
    }
    if (processing) {
        const bool cancellation_pending = cancel_requested.load();
        ImGui::BeginDisabled(cancellation_pending);
        ImGui::PushStyleColor(ImGuiCol_Button, COLOR_WARNING);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.10f, 0.07f, 0.02f, 1.0f));
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
        if (ImGui::Button(mode == UiMode::PROTECT ? "PROTECT FILES" : "UNLOCK FILES",
                          ImVec2(-1, 46))) {
            startProcessing();
        }
        ImGui::PopStyleColor();
        ImGui::EndDisabled();
    }
    endCard();
}

void AppWindow::renderSourceList() {
    const ImVec2 area_position = ImGui::GetCursorScreenPos();
    const float available_height = ImGui::GetContentRegionAvail().y;
    const float list_height = std::clamp(available_height - 330.0f, 140.0f, 205.0f);
    const ImVec2 area_size(ImGui::GetContentRegionAvail().x, list_height);
    ImDrawList* parent_draw = ImGui::GetWindowDrawList();
    parent_draw->AddRectFilled(area_position, area_position + area_size,
                               IM_COL32(10, 17, 34, 210), 14.0f);
    parent_draw->AddRect(area_position, area_position + area_size,
                         IM_COL32(69, 86, 127, 120), 14.0f);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    ImGui::BeginChild("SourceList", area_size, false, ImGuiWindowFlags_NoBackground);
    ImGui::PopStyleColor();
    // Manual row drawings must use the child draw list so its clip rectangle
    // prevents scrolled rows from painting over the controls outside the list.
    ImDrawList* draw = ImGui::GetWindowDrawList();
    if (sources.empty()) {
        drawDashedRect(draw, area_position + ImVec2(10, 10), area_position + area_size - ImVec2(10, 10),
                       IM_COL32(58, 197, 215, 135));
        draw->AddCircleFilled(area_position + ImVec2(area_size.x * 0.5f, 68.0f), 25.0f,
                              IM_COL32(42, 202, 218, 36), 32);
        draw->AddCircle(area_position + ImVec2(area_size.x * 0.5f, 68.0f), 25.0f,
                        IM_COL32(62, 220, 232, 180), 32, 1.5f);
        draw->AddText(area_position + ImVec2(area_size.x * 0.5f - 5.0f, 56.0f),
                      IM_COL32(110, 231, 239, 255), "+");
        ImGui::SetCursorPosY(105.0f);
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
                    IM_COL32(23, 33, 57, 235), 10.0f);
                ImGui::Dummy(ImVec2(8, 3));
                ImGui::SameLine();
                ImGui::BeginGroup();
                const std::string name = pathToUtf8(sources[index].path.filename());
                ImGui::TextUnformatted(name.c_str());
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
                ImGui::TextColored(COLOR_MUTED, "%s",
                                   pathToUtf8(sources[index].path.parent_path()).c_str());
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
    beginCard("OutputPanel", ImVec2(0, 0));
    if (heading_font) ImGui::PushFont(heading_font);
    ImGui::TextUnformatted("Outputs");
    if (heading_font) ImGui::PopFont();
    ImGui::TextColored(COLOR_MUTED,
                       mode == UiMode::PROTECT ? "Save prepared encrypted files wherever you choose."
                                               : "Verified files are written to your selected folder.");

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
        ImGui::BeginDisabled(!has_pending_output);
        ImGui::PushStyleColor(ImGuiCol_Button, COLOR_VIOLET);
        if (ImGui::Button("Save All...")) saveAllOutputs();
        ImGui::PopStyleColor();
        ImGui::EndDisabled();
    }

    renderOutputList();
    endCard();
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
                               IM_COL32(9, 15, 31, 205), 14.0f);
    parent_draw->AddRect(list_position, list_position + list_size,
                         IM_COL32(69, 86, 127, 110), 14.0f);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
    ImGui::BeginChild("OutputList", list_size, false, ImGuiWindowFlags_NoBackground);
    ImGui::PopStyleColor();
    // Output rows belong to the child draw list so scrolling clips them at the
    // list boundary instead of painting over the panel heading and controls.
    ImDrawList* draw = ImGui::GetWindowDrawList();
    if (snapshot.empty()) {
        const ImVec2 center = list_position + ImVec2(list_size.x * 0.5f, list_size.y * 0.42f);
        draw->AddCircleFilled(center, 46.0f, IM_COL32(112, 73, 226, 25), 48);
        draw->AddCircle(center, 46.0f, IM_COL32(119, 89, 230, 120), 48, 1.2f);
        draw->AddCircle(center, 23.0f, IM_COL32(49, 209, 224, 120), 32, 1.5f);
        ImGui::SetCursorPosY(list_size.y * 0.42f + 67.0f);
        const char* primary = mode == UiMode::PROTECT ? "Your encrypted files will appear here"
                                                      : "Decryption results will appear here";
        ImGui::SetCursorPosX((list_size.x - ImGui::CalcTextSize(primary).x) * 0.5f);
        ImGui::TextUnformatted(primary);
        const char* secondary = "See status, location, and verification details at a glance.";
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
                                IM_COL32(24, 34, 59, 240), 12.0f);
            draw->AddRect(row_start, row_start + ImVec2(row_width, item_step - 8.0f),
                          IM_COL32(55, 204, 217, 65), 12.0f);

            const float action_width = item.status == ItemStatus::PENDING_SAVE ? 120.0f : 155.0f;
            const float text_width = std::max(90.0f, row_width - action_width - 52.0f);
            const std::string fitted_name = fitTextToWidth(item.display_name, text_width);
            const std::string fitted_message = fitTextToWidth(item.message, text_width);

            ImGui::Dummy(ImVec2(10, 7));
            ImGui::SameLine();
            ImGui::BeginGroup();
            const ImVec4 status_color = item.status == ItemStatus::PENDING_SAVE
                                            ? COLOR_WARNING
                                            : COLOR_SUCCESS;
            ImGui::TextColored(status_color, "✓");
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
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.56f, 0.20f, 0.28f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.72f, 0.25f, 0.34f, 1.0f));
        if (ImGui::Button("Got it", ImVec2(-1.0f, 44.0f))) ImGui::CloseCurrentPopup();
        ImGui::PopStyleColor(2);
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
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.16f, 0.54f, 0.40f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.20f, 0.66f, 0.48f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.95f, 1.0f, 0.98f, 1.0f));
        if (ImGui::Button("Continue", ImVec2(-1.0f, 44.0f))) ImGui::CloseCurrentPopup();
        ImGui::PopStyleColor(3);
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
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.12f, 0.51f, 0.62f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.15f, 0.64f, 0.74f, 1.0f));
        if (ImGui::Button(protect_label.c_str(), ImVec2(-1.0f, 46.0f))) {
            const std::vector<std::filesystem::path> selected = pending_regular_files;
            pending_regular_files.clear();
            pending_kasa_files.clear();
            setMode(UiMode::PROTECT);
            for (const auto& selected_path : selected) addFile(selected_path);
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(2);
        ImGui::TextColored(COLOR_MUTED, "Encrypt regular files and leave existing .kasa files unchanged.");

        const std::string unlock_label = "Unlock .kasa files (" +
                                          std::to_string(pending_kasa_files.size()) + ")";
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.39f, 0.27f, 0.70f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.50f, 0.35f, 0.84f, 1.0f));
        if (ImGui::Button(unlock_label.c_str(), ImVec2(-1.0f, 46.0f))) {
            const std::vector<std::filesystem::path> selected = pending_kasa_files;
            pending_regular_files.clear();
            pending_kasa_files.clear();
            setMode(UiMode::UNLOCK);
            for (const auto& selected_path : selected) addFile(selected_path);
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(2);
        ImGui::TextColored(COLOR_MUTED, "Decrypt authenticated .kasa files and leave regular files unchanged.");
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
    delete_original = false;
    cipher = CipherType::AES256;
}

void AppWindow::handleDroppedPaths(int count, const char** paths) {
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
            std::vector<std::filesystem::path> regular_files;
            std::vector<std::filesystem::path> kasa_files;
            for (const auto& entry : std::filesystem::recursive_directory_iterator(
                     path, std::filesystem::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;

                std::string extension = entry.path().extension().string();
                std::transform(extension.begin(), extension.end(), extension.begin(),
                               [](const unsigned char character) {
                                   return static_cast<char>(std::tolower(character));
                               });
                if (extension == ".kasa") kasa_files.push_back(entry.path());
                else regular_files.push_back(entry.path());
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
            for (const auto& selected_path : selected_files) addFile(selected_path);
        }
    } catch (const std::filesystem::filesystem_error& error) {
        notice = std::string("File scan failed: ") + error.what();
    }
}

void AppWindow::addFile(const std::filesystem::path& path) {
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

    std::error_code size_error;
    const std::uintmax_t size = std::filesystem::file_size(path, size_error);
    if (!size_error) sources.push_back({path, size, kasa_info});
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

void AppWindow::startProcessing() {
    if (processing) return;
    if (worker.joinable()) worker.join();

    const std::vector<SourceItem> work_items = sources;
    std::string password_value(password.data());
    const UiMode selected_mode = mode;
    const CipherType selected_cipher = cipher;
    const bool should_delete = delete_original;
    const std::filesystem::path destination_folder = unlock_destination;

    {
        std::lock_guard lock(state_mutex);
        outputs.clear();
        current_file.clear();
    }
    processed_count = 0;
    total_count = work_items.size();
    failed_count = 0;
    cancel_requested = false;
    processing = true;
    notice.clear();

    worker = std::thread([this, work_items, password_value, selected_mode,
                          selected_cipher, should_delete, destination_folder]() mutable {
        for (const SourceItem& source : work_items) {
            if (cancel_requested) break;
            {
                std::lock_guard lock(state_mutex);
                current_file = pathToUtf8(source.path.filename());
            }

            OutputItem result;
            result.source_path = source.path;
            result.delete_source_after_save = selected_mode == UiMode::PROTECT && should_delete;
            bool success = false;
            try {
                if (selected_mode == UiMode::PROTECT) {
                    result.display_name = pathToUtf8(source.path.filename()) + ".kasa";
                    result.output_path = uniquePath(staging_directory,
                                                    pathFromUtf8(result.display_name));
                    success = engine.process_file(source.path, password_value, ActionType::ENCRYPT,
                                                  selected_cipher, false, result.output_path);
                    result.staged = success;
                    result.status = success ? ItemStatus::PENDING_SAVE : ItemStatus::FAILED;
                    result.message = success ? "Ready to save" : "Encryption failed";
                } else {
                    const std::filesystem::path desired_name = source.path.stem();
                    result.output_path = uniquePath(destination_folder, desired_name);
                    result.display_name = pathToUtf8(result.output_path.filename());
                    success = engine.process_file(source.path, password_value, ActionType::DECRYPT,
                                                  CipherType::AES256, should_delete, result.output_path);
                    result.status = success ? ItemStatus::SAVED : ItemStatus::FAILED;
                    result.message = success ? pathToUtf8(result.output_path)
                                             : "Wrong password, corrupted file, or unavailable destination";
                }
            } catch (const std::exception& error) {
                result.status = ItemStatus::FAILED;
                result.message = error.what();
            }

            if (success) {
                std::lock_guard lock(state_mutex);
                outputs.push_back(std::move(result));
            } else {
                ++failed_count;
            }
            ++processed_count;
        }
        {
            std::lock_guard lock(state_mutex);
            current_file.clear();
        }
        OPENSSL_cleanse(password_value.data(), password_value.size());
        processing = false;
    });
}

void AppWindow::joinFinishedWorker() {
    if (!processing && worker.joinable()) {
        const bool was_cancelled = cancel_requested.load();
        worker.join();
        cancel_requested = false;
        const std::size_t failures = failed_count.exchange(0);
        if (failures > 0) {
            std::ostringstream message;
            if (mode == UiMode::UNLOCK) {
                message << failures << " file" << (failures == 1 ? "" : "s")
                        << " could not be unlocked. The password may be incorrect, the file may "
                           "be corrupted, or the destination may be unavailable. No failed output "
                           "was created or added to the Outputs list.";
                failure_modal_title = "Unable to unlock files";

                // Keep only failed inputs in the source list so a retry does not decrypt
                // successful files again and create duplicate outputs.
                std::vector<std::filesystem::path> successful_sources;
                {
                    std::lock_guard lock(state_mutex);
                    for (const OutputItem& output : outputs) {
                        successful_sources.push_back(output.source_path);
                    }
                }
                sources.erase(std::remove_if(sources.begin(), sources.end(),
                    [&](const SourceItem& source) {
                        return std::find(successful_sources.begin(), successful_sources.end(),
                                         source.path) != successful_sources.end();
                    }), sources.end());
            } else {
                message << failures << " file" << (failures == 1 ? "" : "s")
                        << " could not be protected. No failed output was added.";
                failure_modal_title = "Unable to protect files";
            }
            failure_modal_message = message.str();
            failure_modal_pending = true;
        } else if (!was_cancelled && mode == UiMode::UNLOCK && processed_count.load() > 0) {
            const std::size_t unlocked_count = processed_count.load();
            const std::string destination = pathToUtf8(unlock_destination);
            clearSession();
            success_modal_title = "Files unlocked successfully";
            success_modal_message = std::to_string(unlocked_count) + " file" +
                                    (unlocked_count == 1 ? " was" : "s were") +
                                    " verified and saved to:\n" + destination +
                                    "\n\nThe workspace has been cleared for the next operation.";
            success_modal_pending = true;
        }
        if (was_cancelled) notice = "The operation stopped after the current file.";
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
    OutputItem item;
    {
        std::lock_guard lock(state_mutex);
        if (index >= outputs.size() || outputs[index].status != ItemStatus::PENDING_SAVE) return;
        item = outputs[index];
    }
    const auto destination = saveFileDialog(pathFromUtf8(item.display_name));
    if (!destination) return;

    const bool moved = moveStagedOutput(item.output_path, *destination);
    bool source_deleted = true;
    if (moved && item.delete_source_after_save) {
        source_deleted = engine.delete_file(item.source_path);
    }
    bool all_saved = false;
    std::size_t saved_count = 0;
    std::size_t delete_warning_count = 0;
    {
        std::lock_guard lock(state_mutex);
        // A failed move remains pending so the user can choose another destination.
        outputs[index].status = moved ? ItemStatus::SAVED : ItemStatus::PENDING_SAVE;
        outputs[index].output_path = moved ? *destination : item.output_path;
        outputs[index].staged = !moved;
        outputs[index].message = !moved ? "Save failed. Choose another destination and try again."
                                : source_deleted ? pathToUtf8(*destination)
                                                 : "Saved, but the source file could not be deleted";
        all_saved = !outputs.empty() && std::all_of(outputs.begin(), outputs.end(),
            [](const OutputItem& output) { return output.status == ItemStatus::SAVED; });
        saved_count = outputs.size();
        delete_warning_count = static_cast<std::size_t>(std::count_if(
            outputs.begin(), outputs.end(), [](const OutputItem& output) {
                return output.message == "Saved, but the source file could not be deleted";
            }));
    }

    if (!moved) {
        failure_modal_title = "Unable to save the file";
        failure_modal_message = "The encrypted output could not be saved. Choose another "
                                "destination and try again. The staged output is still available.";
        failure_modal_pending = true;
    } else if (all_saved) {
        clearSession();
        success_modal_title = "Files saved successfully";
        success_modal_message = std::to_string(saved_count) + " encrypted file" +
                                (saved_count == 1 ? " was" : "s were") +
                                " saved. The workspace has been cleared for the next operation.";
        if (delete_warning_count > 0) {
            success_modal_message += "\n\n" + std::to_string(delete_warning_count) +
                                     " source file" + (delete_warning_count == 1 ? " was" : "s were") +
                                     " not deleted.";
        }
        success_modal_pending = true;
    }
}

void AppWindow::saveAllOutputs() {
    const auto folder = openFolderDialog(L"Choose where encrypted outputs will be saved");
    if (!folder) return;

    std::vector<std::size_t> indices;
    {
        std::lock_guard lock(state_mutex);
        for (std::size_t index = 0; index < outputs.size(); ++index) {
            if (outputs[index].status == ItemStatus::PENDING_SAVE) indices.push_back(index);
        }
    }
    std::size_t save_failures = 0;
    for (const std::size_t index : indices) {
        OutputItem item;
        {
            std::lock_guard lock(state_mutex);
            item = outputs[index];
        }
        const std::filesystem::path destination = uniquePath(*folder,
                                                             pathFromUtf8(item.display_name));
        const bool moved = moveStagedOutput(item.output_path, destination);
        bool source_deleted = true;
        if (moved && item.delete_source_after_save) source_deleted = engine.delete_file(item.source_path);

        {
            std::lock_guard lock(state_mutex);
            outputs[index].status = moved ? ItemStatus::SAVED : ItemStatus::PENDING_SAVE;
            outputs[index].output_path = moved ? destination : item.output_path;
            outputs[index].staged = !moved;
            outputs[index].message = !moved
                                         ? "Save failed. Choose another destination and try again."
                                         : source_deleted
                                               ? pathToUtf8(destination)
                                               : "Saved, but the source file could not be deleted";
        }
        if (!moved) ++save_failures;
    }

    if (save_failures > 0) {
        failure_modal_title = "Some files could not be saved";
        failure_modal_message = std::to_string(save_failures) + " encrypted file" +
                                (save_failures == 1 ? " remains" : "s remain") +
                                " ready to save. Choose another destination and try again.";
        failure_modal_pending = true;
        return;
    }

    std::size_t saved_count = 0;
    std::size_t delete_warning_count = 0;
    {
        std::lock_guard lock(state_mutex);
        saved_count = outputs.size();
        delete_warning_count = static_cast<std::size_t>(std::count_if(
            outputs.begin(), outputs.end(), [](const OutputItem& output) {
                return output.message == "Saved, but the source file could not be deleted";
            }));
    }
    clearSession();
    success_modal_title = "Files saved successfully";
    success_modal_message = std::to_string(saved_count) + " encrypted file" +
                            (saved_count == 1 ? " was" : "s were") +
                            " saved to:\n" + pathToUtf8(*folder) +
                            "\n\nThe workspace has been cleared for the next operation.";
    if (delete_warning_count > 0) {
        success_modal_message += "\n\n" + std::to_string(delete_warning_count) +
                                 " source file" + (delete_warning_count == 1 ? " was" : "s were") +
                                 " not deleted.";
    }
    success_modal_pending = true;
}

std::filesystem::path AppWindow::uniquePath(const std::filesystem::path& folder,
                                            const std::filesystem::path& desired_name) const {
    std::filesystem::path candidate = folder / desired_name;
    if (!std::filesystem::exists(candidate) && !std::filesystem::exists(candidate.string() + ".tmp")) {
        return candidate;
    }
    const std::filesystem::path stem = desired_name.stem();
    const std::filesystem::path extension = desired_name.extension();
    for (int number = 2; number < 10000; ++number) {
        candidate = folder / (stem.string() + " (" + std::to_string(number) + ")" + extension.string());
        if (!std::filesystem::exists(candidate) && !std::filesystem::exists(candidate.string() + ".tmp")) {
            return candidate;
        }
    }
    return folder / (desired_name.string() + "-new");
}

bool AppWindow::moveStagedOutput(const std::filesystem::path& source,
                                 const std::filesystem::path& destination) {
    if (std::filesystem::exists(destination)) return false;
    std::error_code error;
    std::filesystem::create_directories(destination.parent_path(), error);
    if (error) return false;

    std::filesystem::rename(source, destination, error);
    if (!error) return true;
    error.clear();
    if (!std::filesystem::copy_file(source, destination,
                                    std::filesystem::copy_options::none, error) || error) {
        return false;
    }
    std::error_code remove_error;
    std::filesystem::remove(source, remove_error);
    return !remove_error;
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
