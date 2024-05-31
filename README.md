# BloodAlchemy-Prototype

### The actual working of BloodAlchemy:

1.	Run the executable `BrDifaxpi.exe`. This is linked to the DLL `BrLogAPI.dll` which resides inside the “Brother Industry” directory.
2.	The BloodAlchemy malware comes with a malicious DLL with the same name. This is placed in the directory of the BrDifaxpi.exe, and according to the search order of windows, this DLL is loaded before that.
>   This is `DLL search order hijacking`.
4.	This DLL opens a file called `DIFX` which resides in the same directory. This file is encrypted using `AES 128-bit CBC mode encryption`. The DLL decrypts this to reveal an `encrypted and compressed` shell-code. The DLL also has `Anti-Sandbox capabilities`, but the exact mechanisms aren’t provided.
5.	The encryption is a custom one which uses the `FNV-1a` hashing algorithm and the compression is done using the `lznt1 compression algorithm`. The DLL decrypts and decompresses this to reveal the shell-code for a `backdoor`.
6.	This backdoor is injected into a process like `svchost.exe`. This backdoor has functionality to uninstall itself, create registry keys for further persistence and send and receive information from the C2 server. The information received by the backdoor controls what the backdoor sends back to the C2, where its injected and uninstall commands.

### What this prototype does:

1.	It contains a BrDifaxpi.exe file which loads a DLL BrLogAPI.dll. This DLL resides in the same directory as the BrDifaxpi.exe and it **not linked to DLL during compilation**. This is because I found it easier to just load the DLL using the _LoadLibraryA()_ function.
2.	The executable once run loads the DLL. This DLL checks if it is being run inside a _sandbox environment or a virtual machine_, and if it is, then it terminates the entire program and stops all everything. It keeps track of a variable value and if the value is 2, it terminates the program.
3.	There is **no backdoor** involved in this prototype because I couldn’t find a good way to do that. Instead, for demonstration purposes, I am using a _keylogger_ to add to registry keys, and a _windows TCP reverse shell_, to inject into a process. This is to demonstrate how the actual backdoor might work.
4.	If the variable value is 0, the DLL opens the _DIFX_ file which resides in the same directory. This file contains **AES 128-bit ECB** mode encrypted form of the **keylogger CPP code**. I used ECB because it doesn’t use an **IV** and I was having troubles with the IV. The decryption is done using **python**, because I couldn’t find a reliable way to do this using C++. 
5.	This keylogger is compiled and put into registry keys and thus, is executed every time the system reboots. There is **no C2 server** involved in this demonstration because I couldn’t find a way to do it. The data is saved in the victim desktop itself, whereas ideally, it should be sent to C2 server back. 
6.	If the variable value is 1, the DLL initialises a string which contains **base64 encoded shell-code** for a **windows TCP-reverse-shell**. It decodes this and injects this shell-code into svchost.exe. We can catch the shell using a _netcat_ listener or the _Metasploit_ modules.

### Things left unimplemented

`LNZT1 compression and FNV-1a hashing` --> didn’t understand their custom encryption algorithm, as for lnzt1, I couldn’t find a reliable way.
`The actual backdoor` --> no idea how that works
`C2 socket communication` --> would take too much work

### The following files make up the requirements for this proof-of-concept.
```
BrDifaxpi.exe
gBrLogAPI.dll (good)
BrLogAPI.dll (malicious)
decrypt.py
DIFX.txt
```
### Additionally, the following assumptions have been made,

> Victim’s computer has mingw installed (that is, the compiler g++ is present) and is added to path

> Victim’s computer has python installed, along with the Crypto module (or an anaconda installation also works)

Note that these are `not the necessary conditions for BloodAlchemy`, only for this prototype. The process injection of the backdoor does not require any of the assumptions.

Additional details will be present in individual README files inside the directories.
