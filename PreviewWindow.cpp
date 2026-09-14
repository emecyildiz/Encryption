#include "PreviewWindow.h"
#include "preview_text.h"
#include "preview_image.h"
#include "preview_job.h"
#include "preview_input.h"
#include "operation_password.h"
#include <GL/glew.h>
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <openssl/crypto.h>
#include <array>
#include <atomic>
#include <thread>
#include <string>
#include <vector>
#include <algorithm>

namespace {
using namespace kasa::preview;
struct Texture {
    GLuint id=0;
    int width=0,height=0;
    ~Texture(){clear();}
    void clear(){if(id)glDeleteTextures(1,&id);id=0;width=height=0;}
    bool upload(const ImagePreview& image) {
        clear();
        while(glGetError()!=GL_NO_ERROR){}
        GLint limit=0;glGetIntegerv(GL_MAX_TEXTURE_SIZE,&limit);
        if(image.width()>static_cast<unsigned>(limit)||image.height()>static_cast<unsigned>(limit))return false;
        GLint previous=0;glGetIntegerv(GL_TEXTURE_BINDING_2D,&previous);
        glGenTextures(1,&id);glBindTexture(GL_TEXTURE_2D,id);
        glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_S,GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_T,GL_CLAMP_TO_EDGE);
        glTexImage2D(GL_TEXTURE_2D,0,GL_RGBA8,image.width(),image.height(),0,GL_RGBA,GL_UNSIGNED_BYTE,image.pixels().data());
        const bool success=glGetError()==GL_NO_ERROR&&id!=0;
        glBindTexture(GL_TEXTURE_2D,previous);
        if(!success){clear();return false;}
        width=static_cast<int>(image.width());height=static_cast<int>(image.height());return true;
    }
};
struct PreviewContent {
    std::unique_ptr<TextPreview> text;
    std::unique_ptr<ImagePreview> image;
    const char* message="";
};
struct Session {
    std::array<char,128> password{};
    std::unique_ptr<TextPreview> text;
    Texture texture; // GUI-thread only; destroyed before the GL context.
    PreviewJob<PreviewContent> job;
    std::string message;
    std::vector<std::size_t> lines;
    void wipePassword() {OPENSSL_cleanse(password.data(),password.size());}
    void clearText() {lines.clear();text.reset();texture.clear();}
    ~Session(){wipePassword();clearText();}
    void start(const std::filesystem::path& path,Kind kind) {
        if(job.busy()||job.pending()||job.closing())return;
        clearText();message.clear();
        try {
            auto secret=std::make_unique<OperationPassword>(password.data());
            const bool started=job.start([path,kind,secret=std::move(secret)]() mutable {
                    auto content=std::make_unique<PreviewContent>();
                    encryption_engine engine;
                    auto result=engine.decrypt_preview_aes(path,secret->value(),kind==Kind::Text?max_text_bytes:max_encrypted_bytes);
                    if(result.status==PreviewDecryptStatus::Success) {
                        if(kind==Kind::Text) {
                        TextStatus status{};
                        content->text=TextPreview::create(std::move(result.content),status);
                        if(!content->text)content->message=status==TextStatus::LayoutLimit ? text_layout_notice
                            : status==TextStatus::TooLarge ? size_notice : invalid_text_notice;
                        } else {
                            ImageStatus status{};
                            content->image=ImagePreview::create(std::move(result.content),kind,status);
                            if(!content->image)content->message=status==ImageStatus::TooLarge?size_notice:
                                status==ImageStatus::DecoderUnavailable?"The Windows image decoder is unavailable. Nothing was saved.":
                                "This is not a supported, intact PNG/JPEG image matching its filename. Nothing was saved.";
                        }
                    } else if(result.status==PreviewDecryptStatus::TooLarge)content->message=size_notice;
                    else if(result.status==PreviewDecryptStatus::UnsupportedCipher)
                        content->message="Preview currently supports AES-256-GCM files only. The source was not changed.";
                    else if(result.status==PreviewDecryptStatus::Unavailable)
                        content->message=unavailable_notice;
                    else content->message=authentication_error;
                secret.reset();
                return content;
            });
            if(!started)message="Preview could not start. Please try again.";
            wipePassword();
        } catch(...) {wipePassword();message="Preview could not start. Please try again.";}
    }
    void finish() {
        std::unique_ptr<PreviewContent> content;
        const auto outcome=job.poll(content);
        if(outcome==PreviewJob<PreviewContent>::Poll::Failed){message="Preview could not be prepared. Nothing was saved.";return;}
        if(outcome==PreviewJob<PreviewContent>::Poll::Ready) {
            message=content->message;text=std::move(content->text);
            if(content->image) {
                if(!texture.upload(*content->image))message="This image could not be displayed by the graphics device. Nothing was saved.";
                content->image.reset(); // Wipe CPU pixels after the synchronous GL upload.
            }
            if(text) {
                const auto b=text->bytes();
                lines.push_back(0);
                for(std::size_t i=0;i<b.size();++i)if(b[i]=='\n')lines.push_back(i+1);
            }
        }
    }
};
struct Gui {
    GLFWwindow* window=nullptr;
    bool context=false,platform=false,renderer=false;
    ~Gui(){if(renderer)ImGui_ImplOpenGL3_Shutdown();if(platform)ImGui_ImplGlfw_Shutdown();
        if(context)ImGui::DestroyContext();if(window)glfwDestroyWindow(window);glfwTerminate();}
};
}

int runTextPreviewWindow(const std::filesystem::path& file) {
    Gui gui;
    if(!glfwInit())return 1;
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR,3);glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR,3);
    glfwWindowHint(GLFW_OPENGL_PROFILE,GLFW_OPENGL_CORE_PROFILE);
    gui.window=glfwCreateWindow(720,500,"KASA - Read-only preview",nullptr,nullptr);
    if(!gui.window)return 1;
    glfwSetWindowSizeLimits(gui.window,600,430,GLFW_DONT_CARE,GLFW_DONT_CARE);
    glfwMakeContextCurrent(gui.window);glfwSwapInterval(1);
    glewExperimental=GL_TRUE;if(glewInit()!=GLEW_OK)return 1;
    ImGui::CreateContext();gui.context=true;
    auto& io=ImGui::GetIO();io.IniFilename=nullptr;io.LogFilename=nullptr;
    io.ConfigFlags|=ImGuiConfigFlags_NavEnableKeyboard;
    if(std::filesystem::exists("C:/Windows/Fonts/segoeui.ttf"))
        io.Fonts->AddFontFromFileTTF("C:/Windows/Fonts/segoeui.ttf",18.0f);
    ImGui::StyleColorsLight();auto& style=ImGui::GetStyle();
    style.WindowPadding=ImVec2(22,20);style.FramePadding=ImVec2(10,8);
    style.FrameRounding=5;style.ChildRounding=6;style.ItemSpacing=ImVec2(10,12);
    style.Colors[ImGuiCol_Button]=ImVec4(.18f,.35f,.56f,1);
    gui.platform=ImGui_ImplGlfw_InitForOpenGL(gui.window,true);
    gui.renderer=ImGui_ImplOpenGL3_Init("#version 330");
    if(!gui.platform||!gui.renderer)return 1;
    // Declared after GUI: plaintext ownership is released before GUI teardown.
    Session session;
    const auto u8=file.filename().u8string();const std::string name(u8.begin(),u8.end());
    const auto kind=kind_from_path(file);
    const bool supported=kind!=Kind::Unsupported;
    auto input_status=supported?inspect_preview_input(file):InputStatus::Unavailable;
    bool closing=false;
    while(!closing) {
        glfwPollEvents();
        if(glfwWindowShouldClose(gui.window)){
            session.job.request_close();
            glfwSetWindowShouldClose(gui.window,GLFW_FALSE);
        }
        // Remember a close request during verification. Do not display plaintext
        // once verification completes if the user has already asked to close.
        if(session.job.should_close())break;
        session.finish();
        ImGui_ImplOpenGL3_NewFrame();ImGui_ImplGlfw_NewFrame();ImGui::NewFrame();
        ImGui::SetNextWindowPos(ImVec2(0,0));ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("Preview",nullptr,ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoSavedSettings);
        ImGui::TextUnformatted("KASA / READ-ONLY PREVIEW");
        ImGui::TextWrapped("%s",name.c_str());ImGui::Separator();
        if(session.job.closing() || session.job.busy()) {
            ImGui::TextWrapped("%s",session.job.closing()
                ? "Closing after verification finishes..."
                : "Verifying file... You can close this window to dismiss the result.");
            ImGui::TextWrapped("No decrypted file is being saved.");
        } else if(session.texture.id) {
            ImGui::TextWrapped("%s",privacy_notice);
            ImGui::Text("%d x %d pixels / Read-only",session.texture.width,session.texture.height);
            ImGui::PushStyleColor(ImGuiCol_Text,ImVec4(1,1,1,1));
            if(ImGui::Button("Close preview")){session.clearText();closing=true;}
            ImGui::PopStyleColor();
            if(!closing) {
                ImGui::BeginChild("Image",ImVec2(0,0),ImGuiChildFlags_Borders);
                const auto available=ImGui::GetContentRegionAvail();
                const float scale=std::min({1.0f,std::max(1.0f,available.x)/session.texture.width,
                                                std::max(1.0f,available.y)/session.texture.height});
                const ImVec2 size(session.texture.width*scale,session.texture.height*scale);
                auto pos=ImGui::GetCursorPos();
                ImGui::SetCursorPos(ImVec2(pos.x+std::max(0.0f,(available.x-size.x)/2),pos.y+std::max(0.0f,(available.y-size.y)/2)));
                ImGui::Image(static_cast<ImTextureID>(session.texture.id),size);
                ImGui::EndChild();
            }
        } else if(session.text) {
            ImGui::TextWrapped("%s",privacy_notice);
            ImGui::TextWrapped("Display-only: some characters may not be available in the installed font.");
            ImGui::PushStyleColor(ImGuiCol_Text,ImVec4(1,1,1,1));
            if(ImGui::Button("Close preview")) {session.clearText();closing=true;}
            ImGui::PopStyleColor();
            ImGui::BeginChild("Text",ImVec2(0,0),ImGuiChildFlags_Borders,ImGuiWindowFlags_HorizontalScrollbar);
            const auto bytes=session.text ? session.text->bytes() : std::span<const unsigned char>{};
            ImGuiListClipper clipper;clipper.Begin(static_cast<int>(session.lines.size()),ImGui::GetTextLineHeightWithSpacing());
            while(clipper.Step())for(int line=clipper.DisplayStart;line<clipper.DisplayEnd;++line){
                auto start=session.lines[line];auto end=static_cast<std::size_t>(line+1)<session.lines.size()?session.lines[line+1]-1:bytes.size();
                if(end>start&&bytes[end-1]=='\r')--end;
                // Draw directly from the authenticated buffer; never use InputText
                // (editable copies/undo), formatting strings, or clipboard export.
                if(end==start)ImGui::Dummy(ImVec2(0,ImGui::GetTextLineHeight()));
                else ImGui::TextUnformatted(reinterpret_cast<const char*>(bytes.data()+start),reinterpret_cast<const char*>(bytes.data()+end));
            }
            ImGui::EndChild();
        } else if(!supported) {
            ImGui::TextWrapped("%s",unsupported_notice);
            ImGui::TextWrapped("Use the main KASA application to decrypt and save other file types.");
            ImGui::TextWrapped("%s",export_notice);
        } else if(input_status!=InputStatus::Available) {
            ImGui::TextWrapped("%s",input_status==InputStatus::TooLarge?size_notice:unavailable_notice);
            ImGui::TextWrapped("Check the file location and access, then retry. No password is needed for this check.");
            ImGui::PushStyleColor(ImGuiCol_Text,ImVec4(1,1,1,1));
            if(ImGui::Button("Check file again"))input_status=inspect_preview_input(file);
            ImGui::PopStyleColor();
            ImGui::TextWrapped("%s",privacy_notice);
        } else {
            ImGui::TextWrapped("%s",password_notice);
            ImGui::TextUnformatted("Password");ImGui::SetNextItemWidth(-1);
            const bool enter=ImGui::InputText("##preview-password",session.password.data(),session.password.size(),
                ImGuiInputTextFlags_Password|ImGuiInputTextFlags_EnterReturnsTrue);
            ImGui::BeginDisabled(session.password[0]=='\0');
            ImGui::PushStyleColor(ImGuiCol_Text,ImVec4(1,1,1,1));
            const bool clicked=ImGui::Button("Unlock preview",ImVec2(-1,40));
            ImGui::PopStyleColor();
            ImGui::EndDisabled();
            if((clicked||enter)&&session.password[0]!='\0')session.start(file,kind);
            // Show status only after the GUI thread has consumed the completed job.
            if(!session.job.busy() && !session.job.pending() && !session.message.empty())
                ImGui::TextWrapped("%s",session.message.c_str());
            ImGui::TextWrapped("%s",privacy_notice);
        }
        ImGui::End();ImGui::Render();
        int w,h;glfwGetFramebufferSize(gui.window,&w,&h);glViewport(0,0,w,h);
        glClearColor(.95f,.96f,.97f,1);glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());glfwSwapBuffers(gui.window);
    }
    return 0;
}
