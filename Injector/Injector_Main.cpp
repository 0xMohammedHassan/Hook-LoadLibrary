#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include "injection.h"

using namespace std;

#define s getchar

BOOL isFileExist(LPCSTR filename) {

    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

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

BOOL Err(LPCSTR errormessage) {

    cout << errormessage << "  ->" << GetLastError() << endl;

    s;
    return FALSE;
}

DWORD GetProcId(LPCSTR processname) {

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(snapshot, &pe)) {

        do {

            if (lstrcmpi(pe.szExeFile, processname) == 0) {

                pid = pe.th32ProcessID;
                CloseHandle(snapshot);
                return pid;
                break;
            }

        } while (Process32Next(snapshot, &pe));
    }

    while (pid == NULL) {

        cout << "Cant find the process , trying again in 2 seconds..." << endl;

        Sleep(2000);

        pid = GetProcId(processname);

    }
    if (pid != NULL) {

        cout << "Attached to the process now ...." << endl;
    }

    CloseHandle(snapshot);
    return pid;
}

BOOL inject(LPCSTR procname, LPCSTR Payload) {

    DWORD pid = GetProcId(procname);

   
    if (!isFileExist(Payload)) {

        Err("Payload not found!");
    }
    LPSTR dllPath[MAX_PATH] ;

    GetDllPath(Payload, (LPSTR)dllPath);


    HANDLE hOpen = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (hOpen == INVALID_HANDLE_VALUE) {

        Err("Cant open the process");
    }

    LPVOID mem = VirtualAllocEx(hOpen, 0, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (mem == NULL) {

        Err("Cant allocate memory!");
    }

    if (!WriteProcessMemory(hOpen, mem, dllPath, MAX_PATH, 0)) {
        Err("Cant inject to the remote process!");
    }
    PTHREAD_START_ROUTINE pLoadLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hOpen, 0, 0, pLoadLibrary, mem, 0, 0);

    if (hThread == INVALID_HANDLE_VALUE) {
        Err("Cant create remote thread!");
    }



    CloseHandle(hOpen);
    CloseHandle(hThread);
    VirtualFreeEx(hOpen, mem, 0, MEM_RELEASE);

    return TRUE;
    
}
void clear() {
    COORD topLeft = { 0, 0 };
    HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO screen;
    DWORD written;

    GetConsoleScreenBufferInfo(console, &screen);
    FillConsoleOutputCharacterA(
        console, ' ', screen.dwSize.X * screen.dwSize.Y, topLeft, &written
    );
    FillConsoleOutputAttribute(
        console, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE,
        screen.dwSize.X * screen.dwSize.Y, topLeft, &written
    );
    SetConsoleCursorPosition(console, topLeft);
}
int main() {

    LPCSTR processname = "HookMe.exe";
    LPCSTR Payload = "Hook_LoadLibrary.dll";
  
    int choice;

   
    cout << "[1] Classic Injection" << endl;
    cout << "[2] ManualMap Injection" << endl << endl;
    
    cout << "Option: ";

    cin >> choice;



    if(choice == 1)
    {
    if (inject(processname, Payload)) {

        MessageBoxA(0, "Injected successfully!", "Sucess", MB_ICONINFORMATION);
    }

    }
    else if (choice == 2) {
       
        DWORD pid = GetProcId(processname);
        HANDLE hOpen = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (ManualMap(hOpen, Payload)) {

            MessageBoxA(0, "Injected successfully!", "Sucess", MB_ICONINFORMATION);

        }
        else {
            MessageBoxA(0, "Injected Fail", "Fail", MB_ICONINFORMATION);

        }
    }
    else {
        cout << "Wrong choice try again !" << endl;
        clear();
        main();
    }
    s;
	return EXIT_SUCCESS;
}