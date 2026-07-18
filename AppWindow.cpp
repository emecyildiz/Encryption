#include "AppWindow.h"
#include <filesystem>
#include <iostream>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <GLFW/glfw3.h>
#include <windows.h>
#include <shlobj.h>
#include <vector>
#include <fstream>


using namespace std;

void drop_callback(GLFWwindow* window, int count, const char** paths) {
    if (count > 0) {
        // 1. Pencerenin cebindeki kargoyu alıp gerçek sahibine (AppWindow) geri çeviriyoruz
        AppWindow* app = (AppWindow*)glfwGetWindowUserPointer(window);

        // 2. Artık 'app' üzerinden o pencerenin gizli folder_path alanına erişebiliriz!
        if (app != nullptr) {
            strncpy(app->getFolderPathBuffer(), paths[0], 255);
            app->getFolderPathBuffer()[255] = '\0';
            std::cout << "[SÜRÜKLE BIRAK] Secilen yol: " << paths[0] << std::endl;
        }
    }
}

bool AppWindow::init() {
    if (!glfwInit()) {
        return false;
    }

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    window = glfwCreateWindow(800, 600, "crypto fab", NULL, NULL);
    if (!window) {
        glfwTerminate();
        return false;
    }
    glfwSetWindowUserPointer(window, this);
    glfwSetDropCallback(window, drop_callback);
    glfwMakeContextCurrent(window);

    setupImGui();

    return true;
}

void AppWindow::setupImGui() {
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 330");

}

void AppWindow::renderUI() {
    // 1. Dış pencerenin (800x600) gerçek boyutunu alıyoruz
    ImGuiIO& io = ImGui::GetIO();

    // 2. İç paneli tam sol üst köşeye (0,0) yapıştırıyoruz
    ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f));

    // 3. İç paneli dış pencereyle aynı boyuta (800x600) esnetiyoruz
    ImGui::SetNextWindowSize(io.DisplaySize);

    // 4. Paneli kilitliyoruz: Boyutu değişmesin, hareket etmesin, kapanmasın ve üstteki o çirkin başlık çubuğu gitsin!
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoCollapse |
                             ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove |
                             ImGuiWindowFlags_NoTitleBar;

    // Şimdi paneli bu kurallarla başlatıyoruz
    ImGui::Begin("Kripto Kontrol Paneli", NULL, flags);

    // 2. Ekrana düz bir metin (etiket) basıyoruz
    ImGui::Text("Sifrelenecek veya Cozulecek Klasor Yolunu Girin:");

    // 3. Kullanıcının yazı yazabileceği o kutuyu (InputText) oluşturuyoruz
    // Bu kutu, içine yazılan şeyi otomatik olarak "folder_path" değişkenine kaydedecek
    ImGui::InputText("Klasor Yolu", folder_path, 256);
    ImGui::SameLine();
    if (ImGui::Button("Goz At...", ImVec2(100, 35))) {
        // Windows'un standart klasör seçme penceresini hazırlıyoruz
        BROWSEINFO bi = { 0 };
        bi.lpszTitle = "Sifrelenecek Klasoru Secin";
        PIDLIST_ABSOLUTE pidl = SHBrowseForFolder(&bi);

        if (pidl != 0) {
            char selected_path[MAX_PATH];
            // Seçilen klasörün bilgisayardaki gerçek yolunu alıyoruz
            if (SHGetPathFromIDList(pidl, selected_path)) {
                // Hepsini tek bir adrese bağlamıştık ya; seçilen yolu doğrudan folder_path'e kopyalıyoruz!
                strncpy(folder_path, selected_path, 255);
                folder_path[255] = '\0';
                cout << "[DOSYA GEZGİNİ] Secilen klasor: " << selected_path << endl;
            }
            // Windows hafızasını temizle
            CoTaskMemFree(pidl);
        }
    }

    ImGui::Spacing(); // Araya biraz boşluk bırak (Görsel rahatlık)

    // 4. Şifre girilecek kutu (Karakterleri gizlemesi için Password flag'i koyduk)
    ImGui::Text("Kripto Kilitleme Anahtari (Key):");
    ImGui::InputText("Sifre", encryption_key, 64, ImGuiInputTextFlags_Password);

    ImGui::Spacing();   // Biraz boşluk bırak
    ImGui::Separator(); // Yatay çizgi çek
    ImGui::Spacing();

        if (ImGui::Button("Klasor şifrele ", ImVec2(180, 40))) {
            try {
                std::vector<std::filesystem::path> encrypt_list;

                if (std::filesystem::exists(folder_path)) {
                    for (const auto &entry : std::filesystem::recursive_directory_iterator(folder_path)) {
                        if (std::filesystem::is_directory(entry)) {
                            cout << "Dosya" << entry.path().string() << endl;

                        }else if (std::filesystem::is_regular_file(entry) ) {
                            if (entry.path().extension() != ".kasa") {
                                encrypt_list.push_back(entry.path());
                            }
                        }
                    }
                    for (const auto &entry : encrypt_list) {
                        engine.encrypt_xor (entry, encryption_key);
                    }
                }
            }catch (const std::filesystem::filesystem_error& e) {
                std::cerr << "Hata: " << e.what() << '\n';

            }
        }

        if (ImGui::Button("Şifre çöz ", ImVec2(180, 40))) {
            try {
                std::vector<std::filesystem::path> decrypt_list;
                if (std::filesystem::exists(folder_path)) {
                    for (const auto &entry : std::filesystem::recursive_directory_iterator(folder_path)) {
                        if (std::filesystem::is_regular_file(entry) ) {
                            if (entry.path().extension() == ".kasa") {
                                decrypt_list.push_back(entry.path());
                            }
                        }

                    }
                    for (const auto &entry : decrypt_list) {
                        engine.decrypt_xor (entry, encryption_key);
                    }
                }

            }catch(const std::filesystem::filesystem_error& e) {
                std::cerr << "Hata: " << e.what() << '\n';
            }
        }

        ImGui::End(); // Pencere çizimini bitir

}
void AppWindow::run() {
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        renderUI();
        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h); // Çizim alanını pencere boyutuna eşitle

        glClearColor(0.1f, 0.1f, 0.1f, 1.0f); // Arka planı koyu griye boya
        glClear(GL_COLOR_BUFFER_BIT);        // Ekranı temizle

        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);

    }
}

// 🌟 YAPICI FONKSİYON (Nesne doğarken çalışır)
AppWindow::AppWindow() {
    // folder_path ve encryption_key dizilerinin içini tertemiz yapıyoruz
    memset(folder_path, 0, sizeof(folder_path));
    memset(encryption_key, 0, sizeof(encryption_key));
    window = nullptr; // Başlangıçta pencere adresi boş olsun
}


AppWindow::~AppWindow() {
    // Program kapanırken arkada açık sistem bırakmıyoruz, RAM'i temizliyoruz
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    if (window) {
        glfwDestroyWindow(window);
    }
    glfwTerminate();
}