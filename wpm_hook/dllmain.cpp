
#include <Windows.h>

#include <iostream>
#include <sstream>
#include <fstream>


// include ms detours or a hooking lib of your choosing (minhook, diy)
#include "detours.h"
#pragma comment(lib, "detours.lib")

int part = 0; //every call gets a new part name, iterate each call to rebuild stream chronologically.

using WriteProcessMemory_t = BOOL( APIENTRY* )( HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T* ); // WriteProcessMemory syscall prototype

WriteProcessMemory_t orig_WriteProcessMemory = ( WriteProcessMemory_t )( ( uintptr_t ) GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "WriteProcessMemory" ) ); //get address of writeprocessmemory function from kernel32.dll

// Detour hook function, redirected flow on syscall
BOOL APIENTRY hkWriteProcessMemory( _In_ HANDLE hProcess,  _In_ LPVOID lpBaseAddress,  _In_ LPCVOID lpBuffer, _In_ SIZE_T nSize, _Out_ SIZE_T* lpNumberOfBytesWritten )
{
    std::stringstream temp_str;
    temp_str << (part);
    std::string partfile = temp_str.str();

    std::string concat = "C:\\wpm_hook\\" + partfile + ".bin"; //output in C:\\wpm_hook\\ folders as [0-999...].bin
    part++;

    HANDLE hFile = CreateFile((LPCSTR)concat.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL); //create file in  C:\\wpm_hook\\ with assigned name to write contents of syscall into

    if (!WriteFile(hFile, lpBuffer, nSize, reinterpret_cast<DWORD*>(lpNumberOfBytesWritten), NULL)) //get handle of file, then write the syscalls lpBuffer we desire, nSize and lpNumberOfBytesWritten.
    {
        std::cout << "syscall-hook- > WriteFile: Failed to write buffer to file\n";
    }
    CloseHandle(hFile);

    std::cout << "syscall-hook -> WriteFile: Successfully wrote buffer to file [ " << std::to_string(part) << ".bin ]\n";

    return orig_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten); //call original syscall to not interfere with functioning / evade detection
}

// Used as a manually mapped or reflectively loaded .dll into the target process.
BOOL APIENTRY DllMain( HMODULE hModule, DWORD reason, LPVOID lpParam ) 
{
    if ( reason == DLL_PROCESS_ATTACH )
    {
        AllocConsole();                     //open debug console
        freopen("CONOUT$", "w", stdout);    //redirect stdout only (ignore stderr etc)

        std::cout << "syscall-hook -> Initializing hook for WriteProcessMemory!\n";

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread()); //get target process (currently loaded into)
        DetourAttach(&(LPVOID&)orig_WriteProcessMemory, (PBYTE)hkWriteProcessMemory); //detour the syscall to our hk function
        DetourTransactionCommit();
    }
    return TRUE;
}