#include <Windows.h>
int main(){
	HMODULE hDll = LoadLibraryA("BrLogAPI.dll");
	if (!hDll) {
        MessageBoxA(NULL, "BrLogAPI.dll not found", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    FreeLibrary(hDll);
    return 0;
}
