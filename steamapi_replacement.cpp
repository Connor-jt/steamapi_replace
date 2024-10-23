// steamapi_replacement.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include "C:\Users\Joe bingle\Downloads\steamworks_sdk_160\SteamLiteshop\sdk\public\steam\steam_api.h"

#include <string>
#include <iostream>
#include <cstdio>

#include <Libloaderapi.h>
#include <Processenv.h>
#include <winreg.h>
#include <stringapiset.h>
#include <processthreadsapi.h>
#include <handleapi.h>
#include <thread>

using namespace std;


namespace SteamReplace {


typedef unsigned long ulonglong;
typedef unsigned long __uint64;
typedef long longlong;
typedef unsigned int uint;
//typedef int DWORD;
typedef char CHAR;

typedef unsigned long  undefined8;
typedef unsigned int   undefined4;
typedef unsigned short undefined2;
typedef unsigned char  undefined;

// func typedefs
typedef void* (*CreateInterface)(const char* pName, int* pReturnCode);
typedef void* (*ReleaseThreadLocalMemory)(bool thread_exit);
typedef bool  (*Steam_IsKnownInterface)(const char* str);


static ISteamClient* DAT_ISteamClient_ptr;
static long* DAT_steam_client_interface17;
static uint DAT_modules_retrieved_count;
static char DAT_is_anon_user;
static HMODULE DAT_steamclient_hmodule;
//static HMODULE DAT_steamclient_ALT_module;
static HSteamPipe DAT_steam_IPC_pipe;
static HSteamPipe DAT_steam_alt_IPC_pipe;
static HSteamUser DAT_steam_user;
static ReleaseThreadLocalMemory DAT_steamclient_ReleaseThreadLocalMemory;
static uint _DAT_register_callback_mode_manual;


namespace Threaded {
    static uint DAT_tls_header;
    static steam_thread* DAT_tls_struct;
    static steam_thread* DAT_tls_struct2;
    static steam_thread* DAT_tls_struct_cpy;
    static uint _DAT_register_callback_mode_manual;
    static uint _DAT_register_callback_mode_manual;
    static uint _DAT_register_callback_mode_manual;
    static uint _DAT_register_callback_mode_manual;

class steam_thread {

};
steam_thread** FUN_ISteam_thread(void){
    longlong unaff_GS_OFFSET;

    if (*(int*)(*(longlong*)(*(longlong*)(unaff_GS_OFFSET + 0x58) + (ulonglong)_tls_index * 8) + 4) < (int)DAT_tls_header) {
        _Init_thread_header(&DAT_tls_header);
        if ((int)DAT_tls_header == -1) {
            PTR_tls_struct = (steam_thread*)new char[0x30];
            PTR_tls_struct->self_ptr1 = PTR_tls_struct;
            PTR_tls_struct->self_ptr2 = PTR_tls_struct;
            PTR_tls_struct->self_ptr3 = PTR_tls_struct;
            *(undefined2*)&PTR_tls_struct->flags = 0x101;
            DAT_tls_struct_cpy = 0;
            DAT_tls_has_functable = 0;
            DAT_tls_dat3 = 0;
            DAT_tls_dat4 = 0;
            DAT_tls_dat5 = 0;
            DAT_tls_ISteam_functable = (undefined*)&PTR_SteamAPI_ISteam_functable_13b4287f0;
            DAT_tls_dat6 = 0;
            DAT_tls_dat7 = 0;
            DAT_tls_dat8 = 0;
            DAT_tls_has_functable2 = 2;
            DAT_tls_ISteam_functable2 = (undefined*)&PTR_SteamAPI_ISteam_functable_13b428818;
            DAT_tls_struct2 = (astruct*)0x0;
            DAT_tls_dat11 = 0;
            DAT_tls_struct2 = (astruct*)operator_new(0x30);
            DAT_tls_struct2->self_ptr1 = DAT_tls_struct2;
            DAT_tls_struct2->self_ptr2 = DAT_tls_struct2;
            DAT_tls_struct2->self_ptr3 = DAT_tls_struct2;
            *(undefined2*)&DAT_tls_struct2->flags = 0x101;
            DAT_tls_is_active = 1;
            DAT_tls_dat13 = 0;
            DAT_tls_dat14 = 0;
            DAT_tls_struct_cpy = PTR_tls_struct;
            atexit(tls_exit);
            _Init_thread_footer(&DAT_tls_header);
            return &PTR_tls_struct;
        }
    }
    return &PTR_tls_struct;
}

int SteamAPI_CheckCallbackRegistered_t_func(int param_1){
    char cVar1;
    steam_thread* paVar2;
    steam_thread* paVar3;
    steam_thread** ppaVar4;
    steam_thread* paVar5;
    int iVar6;
    steam_thread* paVar7;

    ppaVar4 = FUN_ISteam_thread();
    paVar2 = *ppaVar4;
    cVar1 = paVar2->next_thread->flag_is_child;
    paVar3 = paVar2;
    paVar5 = paVar2->next_thread;
    while (cVar1 == '\0') {
        if (*(int*)&paVar5->field_0x20 < param_1) {
            paVar7 = (astruct*)paVar5->self_ptr3;
            paVar5 = paVar3;
        }
        else {
            paVar7 = (astruct*)paVar5->self_ptr1;
        }
        paVar3 = paVar5;
        paVar5 = paVar7;
        cVar1 = paVar7->flag_is_child;
    }
    iVar6 = 0;
    if ((paVar3->flag_is_child == '\0') && (iVar6 = 0, *(int*)&paVar3->field_0x20 <= param_1)) {
        while ((paVar3 != paVar2 && (*(int*)&paVar3->field_0x20 == param_1))) {
            paVar5 = (astruct*)paVar3->self_ptr3;
            iVar6 += 1;
            if (paVar5->flag_is_child == '\0') {
                cVar1 = ((astruct*)paVar5->self_ptr1)->flag_is_child;
                paVar3 = paVar5;
                paVar5 = (astruct*)paVar5->self_ptr1;
                while (cVar1 == '\0') {
                    cVar1 = ((astruct*)paVar5->self_ptr1)->flag_is_child;
                    paVar3 = paVar5;
                    paVar5 = (astruct*)paVar5->self_ptr1;
                }
            }
            else {
                cVar1 = paVar3->next_thread->flag_is_child;
                paVar7 = paVar3->next_thread;
                paVar5 = paVar3;
                while ((paVar3 = paVar7, cVar1 == '\0' && (paVar5 == (astruct*)paVar3->self_ptr3))) {
                    cVar1 = paVar3->next_thread->flag_is_child;
                    paVar7 = paVar3->next_thread;
                    paVar5 = paVar3;
                }
            }
        }
    }
    return iVar6;
}
}


HKEY check_HKEY(const char* comp){ // seems like a bit a pointless function, but we'll keep it for now
    if (!strcmp(comp, "HKEY_CLASSES_ROOT")
    ||  !strcmp(comp, "HKCR"))
        return (HKEY)0xffffffff80000000;

    if (!strcmp(comp, "HKEY_CURRENT_USER")
    ||  !strcmp(comp, "HKCU"))
        return (HKEY)0xffffffff80000001;

    if (!strcmp(comp, "HKEY_LOCAL_MACHINE")
    ||  !strcmp(comp, "HKLM"))
        return (HKEY)0xffffffff80000002;
    return 0;
}

bool SteamAPI_IsSteamRunning(){
    DWORD dwProcessId = 0;
    DWORD exit_code = 0;
    DWORD cbdata = 4;
    DWORD type = 0;
    HKEY proc_key = 0;

    char str_buf[70] = {0}; 
    if (!MultiByteToWideChar(0xfde9, 0, "Software\\Valve\\Steam\\ActiveProcess", -1, (LPWSTR)str_buf, 35))
        return false;
    if (RegOpenKeyExW(check_HKEY("HKCU"), (LPWSTR)str_buf, 0, 0x20219, &proc_key))
        return false;

    memset(str_buf, 0, 70); // clean the buffer
    if (!MultiByteToWideChar(0xfde9, 0, "pid", -1, (LPWSTR)str_buf, 4)){
        RegCloseKey(proc_key);
        return false;}
    if (RegQueryValueExW(proc_key, (LPWSTR)str_buf, 0, &type, (LPBYTE)&dwProcessId, &cbdata)) {
        RegCloseKey(proc_key);
        return false;}
    RegCloseKey(proc_key);
    
    HANDLE hProcess = OpenProcess(0x400, 0, dwProcessId);
    if (!hProcess)
        return false;

    if ((GetExitCodeProcess(hProcess, &exit_code))
    && (exit_code == STILL_ACTIVE)) {
        CloseHandle(hProcess);
        return true;
    }

    CloseHandle(hProcess);
    return false;
}

bool steam_write_install_path(char* out_buf, int out_buf_size){
    //char* pcVar1;
    //int iVar3;
    //LSTATUS LVar4;
    //DWORD DVar5;
    //HKEY hKey;
    //LPCWSTR pWVar6;
    //LPCWSTR lpWideCharStr;
    //HMODULE hModule;
    //ulonglong length;
    //char* pcVar8;
    //longlong lVar9;
    //longlong lVar10;
    //bool bVar11;
    //uint local_res18[2];
    //DWORD local_res20[2];
    //HKEY local_658[2];
    //char local_648[1040];
    //ulonglong uVar7;
    //if ((DAT_steam_install_path != '\0') && (param_1 == (char*)0x0)) {
    //    return true;
    //}
    //steam_memset(local_648, 0, 0x410);
    //hKey = (HKEY)check_HKEY(&DAT_str_HKCU);
    //local_658[0] = (HKEY)0x0;
    //pWVar6 = (LPCWSTR)operator_new(0x46);
    //iVar3 = MultiByteToWideChar(0xfde9, 0, "Software\\Valve\\Steam\\ActiveProcess", -1, pWVar6, 0x23);
    //if (iVar3 == 0) {
    //    *pWVar6 = L'\0';
    //}
    //LVar4 = RegOpenKeyExW(hKey, pWVar6, 0, 0x20219, local_658);
    //free_mem(pWVar6);

    HKEY proc_key = 0;

    char str_buf[70] = { 0 }; // added 2 extra bytes at the end
    if (!MultiByteToWideChar(0xfde9, 0, "Software\\Valve\\Steam\\ActiveProcess", -1, (LPWSTR)str_buf, 35))
        return false;
    if (RegOpenKeyExW(check_HKEY("HKCU"), (LPWSTR)str_buf, 0, 0x20219, &proc_key))
        return false;


    //bVar11 = LVar4 == 0;
    //if (bVar11) {
    //    pWVar6 = (LPCWSTR)operator_new(0x822);
    //    local_res18[0] = 0x820;
    //    lpWideCharStr = (LPCWSTR)operator_new(0x22);
    //    iVar3 = MultiByteToWideChar(0xfde9, 0, "SteamClientDll64", -1, lpWideCharStr, 0x11);
    //    if (iVar3 == 0) {
    //        *lpWideCharStr = L'\0';
    //    }
    //    LVar4 = RegQueryValueExW(proc_key, lpWideCharStr, (LPDWORD)0x0, local_res20, (LPBYTE)pWVar6, local_res18);
    //    free_mem(lpWideCharStr);
    //    if (LVar4 == 0) {
    //        pWVar6[local_res18[0] >> 1] = L'\0';
    //        iVar3 = WideCharToMultiByte(0xfde9, 0, pWVar6, -1, local_648, 0x410, (LPCSTR)0x0, (LPBOOL)0x0);
    //        if (iVar3 == 0) {
    //            LVar4 = 0x7a;
    //        }
    //    }
    //    free_mem(pWVar6);
    //    RegCloseKey(local_658[0]);
    //    bVar11 = LVar4 == 0;
    //}


    char processPath[0x410]; {
        BYTE processPath_wstr[0x822];
        DWORD cbdata = 0x820;
        DWORD type = 0;

        memset(str_buf, 0, 70); // clean the buffer
        if (!MultiByteToWideChar(0xfde9, 0, "SteamClientDll64", -1, (LPWSTR)str_buf, 17)) {
            RegCloseKey(proc_key);
            return false;
        }
        if (RegQueryValueExW(proc_key, (LPWSTR)str_buf, 0, &type, processPath_wstr, &cbdata)) {
            RegCloseKey(proc_key);
            return false;
        }
        RegCloseKey(proc_key);

        // manually terminate wstring
        processPath_wstr[cbdata] = 0;
        processPath_wstr[cbdata + 1] = 0;
        if (!WideCharToMultiByte(0xfde9, 0, (LPCWSTR)processPath_wstr, -1, processPath, 0x410, 0, 0))
            return false;

        // alternative method to get filename if that failed (pretty sure this cant work with our setup)
        if (!processPath[0]) {
            WCHAR alt_proc_path[0x103];
            alt_proc_path[0] = L'\0';
            if (!GetModuleFileNameW(GetModuleHandleA("steamclient64.dll"), alt_proc_path, 0x104) < 0x104)
                return false;
            if (!WideCharToMultiByte(0xfde9, 0, alt_proc_path, -1, processPath, 0x410, 0, 0))
                return false;
        }
    }

    // copy over path to output and null terminate
    if (out_buf && out_buf_size) {
        auto i = 0;
        auto last_pos = 0;
        while (i < out_buf_size) {
            last_pos = i;
            out_buf[i] = processPath[i];
            if (!processPath[i]) break;
            i++;
        }
        out_buf[last_pos] = 0;
    }
    return true;
    // none of this seems to be relevant
    //uVar7 = 0xffffffffffffffff;
    //do {
    //    length = uVar7 + 1;
    //    lVar10 = uVar7 + 1;
    //    uVar7 = length;
    //} while (processPath[lVar10] != '\0');
    //if (0x40f < length) {
    //    length = 0x40f;
    //}
    //steam_memcpy(&DAT_steam_install_path, processPath, length);
    //(&DAT_steam_install_path)[length] = 0;
    //lVar10 = -1;
    //do {
    //    lVar9 = lVar10 + 1;
    //    pcVar1 = &DAT_13b445371 + lVar10;
    //    lVar10 = lVar9;
    //} while (*pcVar1 != '\0');
    //iVar3 = (int)lVar9 + -1;
    //if (0 < iVar3) {
    //    lVar10 = (longlong)iVar3;
    //    do {
    //        if (((&DAT_steam_install_path)[lVar10] == '\\') || ((&DAT_steam_install_path)[lVar10] == '/')) break;
    //        iVar3 += -1;
    //        lVar10 += -1;
    //    } while (0 < lVar10);
    //    (&DAT_steam_install_path)[iVar3] = 0;
    //}
    //return bVar11;
}

INT_PTR init_steam_client(HMODULE* resulting_hmodule, char* is_anon_user, undefined zero, const char* SteamClient021, char* error_output_buffer){
    //undefined auVar1[16];
    //longlong lVar2;
    char install_path_str_ptr;
    //int iVar3;
    HMODULE steamclient_library;
    //longlong lVar4;
    //__uint64 _Var5;
    LPWSTR steamclient_path_wstr;
    CreateInterface create_interface_func;
    INT_PTR resulting_interface;
    int path_chars = 0;
    CHAR steam_install_path[0x410] = { 0 };
    //char acStack_427[1039];
    //CHAR error_output[1040];

    //*resulting_hmodule = (HMODULE)0x0;

    //if (*is_anon_user != 0) {
    //    steamclient_library = (HMODULE)load_library_wstr(PTR_s_steamclient64.dll_13b444378, 1, zero);
    //    *resulting_hmodule = steamclient_library;
    //    if (steamclient_library != (HMODULE)0x0) {
    //        steam_format_string_s_ptr(error_output, "[S_API] SteamAPI_Init(): Loaded local \'%s\' OK.\n", PTR_s_steamclient64.dll_13b444378);
    //        OutputDebugStringA(error_output);
    //    }
    //}
    //if (*resulting_hmodule == (HMODULE)0x0) {
    //if ((*is_anon_user == 0) && (steam_running = SteamAPI_IsSteamRunning(), steam_running == '\0')) {
    if (!SteamReplace::SteamAPI_IsSteamRunning())
        //OutputDebugStringA("[S_API] SteamAPI_Init(): SteamAPI_IsSteamRunning() did not locate a running instance of Steam.\n");
        goto init_steam_client_fail;

    //SteamAPI_GetSteamInstallPath();
    ////DAT_13b445870 = 0;
    ////DAT_13b445878 = 0;
    ////DAT_13b445880 = 0;
    //DAT_steam_install_path = 0;
    if (!steam_write_install_path(steam_install_path, 0x410))
        // "Could not determine Steam client install directory."
        goto init_steam_client_fail;
    
    // count chars in string (including the null terminator)
    while (steam_install_path[path_chars++]);

    steamclient_path_wstr = (LPWSTR)new char[path_chars*2];
    if (!MultiByteToWideChar(0xfde9, 0, steam_install_path, -1, steamclient_path_wstr, path_chars)) {
        delete[] steamclient_path_wstr;
        goto init_steam_client_fail;
    }

    steamclient_library = LoadLibraryExW(steamclient_path_wstr, (HANDLE)0x0, 8);
    delete[] steamclient_path_wstr;
    if (!steamclient_library) 
        steamclient_library = LoadLibraryExA(steam_install_path, (HANDLE)0x0, 8);
    if (!steamclient_library)
        //steam_format_error(error_output_buffer, "Failed to load module \'%s\'");
        goto init_steam_client_fail;
    
    //if (*is_anon_user == '\0') {
    //    steam_format_string_s_ptr(error_output, "[S_API] SteamAPI_Init(): Loaded \'%s\' OK.\n", &steam_install_path);
    //    OutputDebugStringA(error_output);
    //}
    //else {
    //    steam_format_string_s_ptr(error_output, "[S_API] SteamAPI_Init(): Loaded \'%s\' OK.  (First tried local \'%s\')\n", &steam_install_path, PTR_s_steamclient64.dll_13b444378);
    //    OutputDebugStringA(error_output);
    //    *is_anon_user = '\0';
    //}
    //}
    create_interface_func = (CreateInterface)GetProcAddress(steamclient_library, "CreateInterface");
    if (!create_interface_func) {
        //steam_format_error(error_output_buffer, "Unable to locate interface factory in %s.\n", "steamclient64.dll");
        FreeLibrary(steamclient_library);
        goto init_steam_client_fail;
    }

    DAT_steamclient_ReleaseThreadLocalMemory = (ReleaseThreadLocalMemory)GetProcAddress(DAT_steamclient_hmodule, "Steam_ReleaseThreadLocalMemory");

    DAT_steam_client_interface17 = (long*)(*create_interface_func)("SteamClient017", 0);
    resulting_interface = (INT_PTR)(*create_interface_func)(SteamClient021, 0);
    DAT_modules_retrieved_count += 1;

    *resulting_hmodule = steamclient_library; // not sure why this is set without resulting_interface being true
    if (resulting_interface) 
        return resulting_interface;
    //steam_format_error(error_output_buffer, "No %s", SteamClient021);
    
init_steam_client_fail:
    //steam_format_string_s_ptr(error_output, "[S_API] SteamAPI_Init(): %s\n", error_output_buffer);
    //OutputDebugStringA(error_output);
    return 0;
}

undefined4 init_steam(char is_anon, const char* pszInternalCheckInterfaceVersions, char* error_output_buffer){
    //undefined auVar2[16];
    uint app_id;
    ulonglong game_id;
    //DWORD result;
    Steam_IsKnownInterface interface_check_func;
    //INT_PTR IVar5;
    //longlong lVar6;
    ISteamUtils* steam_utils;
    ISteamUser* steam_user;
    //longlong lVar7;
    //__uint64 _Var8;
    //LPCWSTR lpWideCharStr;
    //CSteamID user_id;
    undefined4 shutdown_Code;
    //ulonglong local_res20;
    //CHAR string_buf32[32];
    //CHAR local_438;
    //char acStack_437[1039];
    //HMODULE temp_module;

    if (!DAT_ISteamClient_ptr) return 0;

    DAT_is_anon_user = is_anon;
    DAT_ISteamClient_ptr = (ISteamClient*)init_steam_client(&DAT_steamclient_hmodule, &DAT_is_anon_user, 0, "SteamClient021", error_output_buffer);
    if (!DAT_ISteamClient_ptr) return 1;
    
    //DAT_13b445870 = 0;
    shutdown_Code = 1;

    DAT_steam_IPC_pipe = DAT_ISteamClient_ptr->CreateSteamPipe();
    DAT_steam_user = DAT_ISteamClient_ptr->ConnectToGlobalUser(DAT_steam_IPC_pipe);

    if (DAT_steam_IPC_pipe == 0) {
        shutdown_Code = 2;
        // "Cannot create IPC pipe to Steam client process.  Steam is probably not running."
        goto return_failure;
    }
    if (DAT_steam_user == 0) {
        // "ConnectToGlobalUser failed."
        DAT_ISteamClient_ptr->BReleaseSteamPipe(DAT_steam_IPC_pipe);
        goto return_failure;
    }

    // verify interface versions
    if (pszInternalCheckInterfaceVersions != 0) {
        //temp_module = DAT_steamclient_hmodule;
        //if (DAT_steamclient_ALT_module != (HMODULE)0x0) {
        //    temp_module = DAT_steamclient_ALT_module;
        //}
        interface_check_func = (Steam_IsKnownInterface)GetProcAddress(DAT_steamclient_hmodule, "Steam_IsKnownInterface");
        if (interface_check_func) {
            while (*pszInternalCheckInterfaceVersions) {
                if (!(*interface_check_func)(pszInternalCheckInterfaceVersions)) {
                    //steam_format_error(error_output_buffer, "No %s", pszInternalCheckInterfaceVersions);
                    //steam_missing_feature(IPC_pipe, pszInternalCheckInterfaceVersions);
                    shutdown_Code = 3;
                    goto return_failure;
                }
                // iterate string till we reach the next null terminator
                while (*pszInternalCheckInterfaceVersions++);
            }
        }
    }
    if (!DAT_steamclient_ReleaseThreadLocalMemory) 
        DAT_steam_alt_IPC_pipe = DAT_ISteamClient_ptr->CreateSteamPipe();
    
    steam_utils = (ISteamUtils*)DAT_ISteamClient_ptr->GetISteamGenericInterface(0, DAT_steam_IPC_pipe, "SteamUtils010");
    if (!steam_utils) {
        goto return_failure;
        //steam_format_error(error_output_buffer, "No %s", "SteamUtils010");
        // IPC_pipe = DAT_steam_IPC_pipe;
        //temp_module = DAT_steamclient_hmodule;
        //if (DAT_steamclient_ALT_module != (HMODULE)0x0) {
        //    temp_module = DAT_steamclient_ALT_module;
        //}
        //pFVar4 = GetProcAddress(temp_module, "Steam_NotifyMissingInterface");
        //if (pFVar4 != (FARPROC)0x0) {
        //    (*pFVar4)((ulonglong)(uint)IPC_pipe, "SteamUtils010");
        //}
    }

    steam_user = DAT_ISteamClient_ptr->GetISteamUser(DAT_steam_IPC_pipe, DAT_steam_user, "SteamUser023");
    if (!steam_user) {
        shutdown_Code = 3;
        goto return_failure;
    }
    app_id = steam_utils->GetAppID();
    game_id = (ulonglong)app_id & 0xffffffff00ffffff; // not sure why this is a thing??
    if (!app_id) {
        // No appID found.  Either launch the game from Steam, or put the file steam_appid.txt containing the correct appID in your game folder.
        goto return_failure;
        //steam_format_error(error_output_buffer, "No %s", "SteamUser023");
        //temp_module = DAT_steamclient_hmodule;
        //if (DAT_steamclient_ALT_module != (HMODULE)0x0) {
        //    temp_module = DAT_steamclient_ALT_module;
        //}
        //pFVar4 = GetProcAddress(temp_module, "Steam_NotifyMissingInterface");
        //if (pFVar4 != (FARPROC)0x0) {
        //    (*pFVar4)((ulonglong)(uint)IPC_pipe, "SteamUser023");
        //    shutdown_Code = 3;
        //    goto return_failure;
        //}
    }
    if (!GetEnvironmentVariableA("SteamAppId", (LPSTR)0x0, 0)) {
        char str_buf[32] = { 0 }; // steam had a nice optimization for this actually, only set the first char and last char to \0
        sprintf(str_buf, "%u", app_id, "SteamUser023");// WARNING: bad code -> fails
        SetEnvironmentVariableA("SteamAppId", str_buf);
    }
    if (!GetEnvironmentVariableA("SteamGameId", (LPSTR)0x0, 0)) {
        char str_buf[32] = { 0 };
        sprintf(str_buf, "%llu", game_id, "SteamUser023");
        SetEnvironmentVariableA("SteamGameId", str_buf);
        SetEnvironmentVariableA("SteamOverlayGameId", str_buf);
    }
    if (!GetEnvironmentVariableA("SteamOverlayGameId", (LPSTR)0x0, 0)) {
        char str_buf[32] = { 0 };
        sprintf(str_buf, "%llu", game_id, "SteamUser023");
        SetEnvironmentVariableA("SteamOverlayGameId", str_buf);
    }
    //SteamAPI_SetBreakpadAppID(app_id);
    steam_config_callbacks(DAT_steamclient_hmodule);
    //config_breakpad_thing();
    
    // probably this stuff isn't needed?? doesn't seem to store anything but check whether the module can be loaded via various means??
    //if ((app_id != 0x301) && (temp_module = GetModuleHandleA("gameoverlayrenderer64.dll"), temp_module == (HMODULE)0x0)) {
    //    steam_write_install_path(0, 0);
    //    //steam_print_s_c_s(&local_438, "%s\\%s", &DAT_steam_install_path, "gameoverlayrenderer64.dll");
    //    lVar6 = -1;
    //    do {
    //        lVar7 = lVar6;
    //        lVar6 = lVar7 + 1;
    //    } while ((&local_438)[lVar7 + 1] != 0);
    //    auVar2 = ZEXT816(2) * ZEXT816((longlong)(int)(lVar7 + 1) + 1);
    //    _Var8 = SUB168(auVar2, 0);
    //    if (SUB168(auVar2 >> 0x40, 0) != 0) {
    //        _Var8 = 0xffffffffffffffff;
    //    }
    //    lpWideCharStr = (LPCWSTR)operator_new(_Var8);
    //    if (MultiByteToWideChar(0xfde9, 0, &local_438, -1, lpWideCharStr, (int)lVar7 + 2) == 0) {
    //        *lpWideCharStr = L'\0';
    //    }
    //    temp_module = LoadLibraryExW(lpWideCharStr, (HANDLE)0x0, 8);
    //    free(lpWideCharStr);
    //    if ((temp_module == (HMODULE)0x0) && (temp_module = LoadLibraryExA(&local_438, (HANDLE)0x0, 8), temp_module == (HMODULE)0x0)) {
    //        load_library_wstr("gameoverlayrenderer64.dll", 1, 0);
    //    }
    //}


    if (_DAT_register_callback_mode_manual < 1)
        DAT_ISteamClient_ptr->Set_SteamAPI_CCheckCallbackRegisteredInProcess(SteamAPI_CheckCallbackRegistered_t_func);
    
    // minidump write steam id
    //user_id = steam_user->GetSteamID();
    //FUN_13b4074c0(*user_id);
    return 0;
        
    
return_failure:
    SteamReplace::SteamAPI_Shutdown();
    return shutdown_Code;
}

ulonglong SteamInternal_SteamAPI_Init(const char* pszInternalCheckInterfaceVersions, char* pOutErrMsg) {
    ulonglong SteamInit_result;
    ulonglong last_char_index;
    char error_output_buffer[1024];
    longlong i;

    memset(error_output_buffer, 0, 0x400);
    SteamInit_result = init_steam(0, pszInternalCheckInterfaceVersions, error_output_buffer);
    if (pOutErrMsg != (char*)0x0) {
        SteamInit_result = 0xffffffffffffffff;
        do {
            last_char_index = SteamInit_result + 1;
            i = SteamInit_result + 1;
            SteamInit_result = last_char_index;
        } while (error_output_buffer[i] != '\0');

        if (last_char_index > 0x3ff)
            last_char_index = 0x3ff;

        memcpy(pOutErrMsg, error_output_buffer, last_char_index);
        pOutErrMsg[last_char_index] = '\0';
    }
    return SteamInit_result;
}

}


int main(){
    const char* pszInternalCheckInterfaceVersions =
        STEAMUTILS_INTERFACE_VERSION "\0"
        STEAMNETWORKINGUTILS_INTERFACE_VERSION "\0"
        STEAMAPPS_INTERFACE_VERSION "\0"
        STEAMCONTROLLER_INTERFACE_VERSION "\0"
        STEAMFRIENDS_INTERFACE_VERSION "\0"
        STEAMGAMESEARCH_INTERFACE_VERSION "\0"
        STEAMHTMLSURFACE_INTERFACE_VERSION "\0"
        STEAMHTTP_INTERFACE_VERSION "\0"
        STEAMINPUT_INTERFACE_VERSION "\0"
        STEAMINVENTORY_INTERFACE_VERSION "\0"
        STEAMMATCHMAKINGSERVERS_INTERFACE_VERSION "\0"
        STEAMMATCHMAKING_INTERFACE_VERSION "\0"
        STEAMMUSICREMOTE_INTERFACE_VERSION "\0"
        STEAMMUSIC_INTERFACE_VERSION "\0"
        STEAMNETWORKINGMESSAGES_INTERFACE_VERSION "\0"
        STEAMNETWORKINGSOCKETS_INTERFACE_VERSION "\0"
        STEAMNETWORKING_INTERFACE_VERSION "\0"
        STEAMPARENTALSETTINGS_INTERFACE_VERSION "\0"
        STEAMPARTIES_INTERFACE_VERSION "\0"
        STEAMREMOTEPLAY_INTERFACE_VERSION "\0"
        STEAMREMOTESTORAGE_INTERFACE_VERSION "\0"
        STEAMSCREENSHOTS_INTERFACE_VERSION "\0"
        STEAMUGC_INTERFACE_VERSION "\0"
        STEAMUSERSTATS_INTERFACE_VERSION "\0"
        STEAMUSER_INTERFACE_VERSION "\0"
        STEAMVIDEO_INTERFACE_VERSION "\0"
        "\0";
    SteamReplace::SteamInternal_SteamAPI_Init(pszInternalCheckInterfaceVersions);
}

