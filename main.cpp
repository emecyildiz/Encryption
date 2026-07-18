#include "AppWindow.h"
#include <windows.h>
#include "encryption_engine.h"


int main() {
    encryption_engine eng;
    eng.dencrypt_aes256( "C:/Users/Lenovo/OneDrive/Desktop/test aes.txt.kasa", "123456");

    return 0;
}