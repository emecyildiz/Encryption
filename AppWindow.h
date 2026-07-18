#ifndef ENCRYPTION_APPWINDOW_H
#define ENCRYPTION_APPWINDOW_H

#include <GLFW/glfw3.h>
#include "encryption_engine.h"


class AppWindow {
    private:
    GLFWwindow* window;

    char folder_path[256];
    char encryption_key[64];

    encryption_engine engine;
    void setupImGui();
    void renderUI();

    public:
    AppWindow();
    ~AppWindow();

    bool init();
    void run();

    char* getFolderPathBuffer() { return folder_path; }

};


#endif //ENCRYPTION_APPWINDOW_H