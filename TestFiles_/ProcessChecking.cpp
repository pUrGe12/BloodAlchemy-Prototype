#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>
#include <vector>

bool IsAnyProcessRunning(const std::vector<const TCHAR*>& processNames)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            for (const auto& processName : processNames) {
                if (_tcscmp(pe32.szExeFile, processName) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return false;
}

int main()
{
    std::vector<const TCHAR*> processNames = { _T("notepad.exe"), _T("svchost.exe") };                  // to check if the correct output is given 

    if (IsAnyProcessRunning(processNames)) {
        std::wcout << L"Process running." << std::endl;
    } else {
        std::wcout << L"No specified process is running." << std::endl;
    }

    return 0;
}
