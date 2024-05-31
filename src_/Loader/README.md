This program will simply load a DLL named `BrLogAPI.dll`. This program has not been linked to the DLL during runtime. This is why I have used the function 
`LoadLibraryA` from the windows API library.

To compile on windows (using wingw) run,

    g++ -o BrDifxapi.dll BrDifxapi.cpp
