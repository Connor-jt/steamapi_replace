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

typedef bool (*Steam_BGetCallback    )(HSteamPipe hSteamPipe, CallbackMsg_t* pCallbackMsg);
typedef bool (*Steam_FreeLastCallback)(HSteamPipe hSteamPipe);
typedef bool (*Steam_GetAPICallResult)(HSteamPipe hSteamPipe, SteamAPICall_t hSteamAPICall, void* pCallback, int cubCallback, int iCallbackExpected, bool* pbFailed);

static ReleaseThreadLocalMemory DAT_steamclient_ReleaseThreadLocalMemory;
static Steam_BGetCallback     DAT_steam_BGetCallback_func;
static Steam_FreeLastCallback DAT_steam_FreeLastCallback_func;
static Steam_GetAPICallResult DAT_steam_GetAPICallResult_func;

// statics
static ISteamClient* DAT_ISteamClient_ptr;
static long* DAT_steam_client_interface17;
static uint DAT_modules_retrieved_count;
static char DAT_is_anon_user;
static HMODULE DAT_steamclient_hmodule;
//static HMODULE DAT_steamclient_ALT_module;
static HSteamPipe DAT_steam_IPC_pipe;
static HSteamPipe DAT_steam_alt_IPC_pipe;
static HSteamUser DAT_steam_user;
static int _DAT_register_callback_mode_manual;



namespace Threaded {
class ISteamObjMap { // size: 0x30
public:
    ISteamObjMap* prev_obj;
    ISteamObjMap* self_ptr2;
    ISteamObjMap* next_obj;
    char flag1;
    char flag2;
    USHORT unk1;
    uint unk2;
    int cb_index;
    uint unk3;
    CCallbackBase* callback;
};
class ISteamObj { // size: 0x80
public:
    ISteamObjMap* map_struct;
    undefined8 field1_0x8;
        
    ISteamObjMap* active_map_struct;
    HSteamUser userid;
    HSteamPipe ipc_pipe;
    void* unk_ptr2;

    CCallbackBase* callback1;
    uint has_callback1;
    uint unk_int3;
    void* unk_ptr4;
    void* unk_ptr5;

    CCallbackBase* callback2;
    uint has_callback2;
    uint unk_int6;
    void* unk_ptr7;
    void* unk_ptr8;

    ISteamObjMap* map_struct2;
    void* unk_ptr9;

    longlong tls_header;
};

static ISteamObj callbacks;
static uint DAT_tls_is_active = 0;

// FINISHED
void cleanup_child_thread(ISteamObjMap* curr_obj){
    while (!curr_obj->flag2) {
        cleanup_child_thread(curr_obj->next_obj);
        ISteamObjMap* pIVar2 = curr_obj->prev_obj;
        delete curr_obj;
        curr_obj = pIVar2;
    }
}

// 
void tls_exit(void){
    DAT_tls_is_active = 0;

    cleanup_child_thread(callbacks.map_struct2->self_ptr2);
    delete callbacks.map_struct2;

    callbacks.callback2 = PTR_SteamAPI_ISteam_functable_13b4287c8;
    if ((callbacks.has_callback2 & 1) != 0)
        SteamReplace::SteamAPI_UnregisterCallback(callbacks.callback2);
 
    callbacks.callback1 = PTR_SteamAPI_ISteam_functable_13b4287c8;
    if ((callbacks.has_callback1 & 1) != 0)
        SteamReplace::SteamAPI_UnregisterCallback(callbacks.callback1);
    
    cleanup_child_thread(callbacks.map_struct->self_ptr2);
    delete callbacks.map_struct;
}

// MOSTLY FINISHED???
ISteamObj* FUN_ISteam_thread(void){
    //longlong unaff_GS_OFFSET;

    //if (*(int*)(*(longlong*)(*(longlong*)(unaff_GS_OFFSET + 0x58) + (ulonglong)_tls_index * 8) + 4) < (int)callbacks.tls_header) {
        //_Init_thread_header(callbacks.tls_header);
        if ((int)callbacks.tls_header == -1) {
            callbacks.map_struct = new(ISteamObjMap);
            callbacks.map_struct->prev_obj = callbacks.map_struct;
            callbacks.map_struct->self_ptr2 = callbacks.map_struct;
            callbacks.map_struct->next_obj = callbacks.map_struct;
            callbacks.map_struct->flag1 = 1;
            callbacks.map_struct->flag2 = 1;
            callbacks.active_map_struct = 0;
            callbacks.has_callback1 = 0;
            callbacks.unk_int3 = 0;
            callbacks.unk_ptr4 = 0;
            callbacks.unk_ptr5 = 0;
            //callbacks.callback1 = &PTR_SteamAPI_ISteam_functable_1;
            callbacks.unk_int6 = 0;
            callbacks.unk_ptr7 = 0;
            callbacks.unk_ptr8 = 0;
            callbacks.has_callback2 = 2;
            //callbacks.callback2 = &PTR_SteamAPI_ISteam_functable_2;
            callbacks.map_struct2 = 0;
            callbacks.unk_ptr9 = 0;
            callbacks.map_struct2 = new(ISteamObjMap);
            callbacks.map_struct2->prev_obj = callbacks.map_struct2;
            callbacks.map_struct2->self_ptr2 = callbacks.map_struct2;
            callbacks.map_struct2->next_obj = callbacks.map_struct2;
            callbacks.map_struct2->flag1 = 1;
            callbacks.map_struct2->flag2 = 1;
            DAT_tls_is_active = 1;
            callbacks.unk_ptr2 = 0;
            callbacks.userid = 0;
            callbacks.ipc_pipe = 0;
            callbacks.active_map_struct = (ISteamObj*)callbacks.map_struct;
            atexit(tls_exit);
            //_Init_thread_footer(callbacks.tls_header);
            return &callbacks;
        }
    //}
    return &callbacks;
}

// 
int SteamAPI_CheckCallbackRegistered_t_func(int iCallbackNum){
    char cVar1;
    int iVar6 = 0;
    ISteamObjMap* callbacks_root;
    ISteamObjMap* pIVar3;
    ISteamObjMap* pIVar5;
    ISteamObjMap* pIVar7;

    callbacks_root = FUN_ISteam_thread()->map_struct;

    pIVar3 = callbacks_root;
    pIVar5 = callbacks_root->self_ptr2;

    while (!pIVar5->flag2) {
        if (pIVar5->cb_index < iCallbackNum) {
            pIVar7 = pIVar5->next_obj;
            pIVar5 = pIVar3;
        }else
            pIVar7 = pIVar5->prev_obj;
       
        pIVar3 = pIVar5;
        pIVar5 = pIVar7;
    }

    if ((pIVar3->flag2 == 0) 
    && ( pIVar3->cb_index <= iCallbackNum)) {
        while ((pIVar3 != callbacks_root && (pIVar3->cb_index == iCallbackNum))) {
            pIVar5 = pIVar3->next_obj;
            iVar6 += 1;
            if (!pIVar5->flag2) {
                cVar1 = pIVar5->prev_obj->flag2;
                pIVar3 = pIVar5;
                pIVar5 = pIVar5->prev_obj;
                while (!cVar1) {
                    cVar1 = pIVar5->prev_obj->flag2;
                    pIVar3 = pIVar5;
                    pIVar5 = pIVar5->prev_obj;
                }
            }
            else {
                cVar1 = pIVar3->self_ptr2->flag2;
                pIVar7 = pIVar3->self_ptr2;
                pIVar5 = pIVar3;
                while ((pIVar3 = pIVar7, !cVar1 && (pIVar5 == pIVar3->next_obj))) {
                    cVar1 = pIVar3->self_ptr2->flag2;
                    pIVar7 = pIVar3->self_ptr2;
                    pIVar5 = pIVar3;
                }
            }
        }
    }
    return iVar6;
}



}


// FINISHED
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

// FINISHED
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

// FINISHED 
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

// MOSTLY FINISHED!!
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

// FINISHED
void steam_config_callbacks(HMODULE steamc_module){
    Threaded::FUN_ISteam_thread();
    DAT_steam_BGetCallback_func     = (Steam_BGetCallback)GetProcAddress(steamc_module, "Steam_BGetCallback");
    DAT_steam_FreeLastCallback_func = (Steam_FreeLastCallback)GetProcAddress(steamc_module, "Steam_FreeLastCallback");
    DAT_steam_GetAPICallResult_func = (Steam_GetAPICallResult)GetProcAddress(steamc_module, "Steam_GetAPICallResult");
    return;
}

// FINISHED
void SteamAPI_Shutdown() {
    // 0x85e0  957  SteamAPI_Shutdown
    //DAT_13b445870 = 0;
    //DAT_13b445878 = 0;
    //DAT_13b445880 = 0;
    if (DAT_steam_IPC_pipe && DAT_steam_user)
        DAT_ISteamClient_ptr->ReleaseUser(DAT_steam_IPC_pipe, DAT_steam_user);

    DAT_steam_user = 0;
    if (DAT_steam_IPC_pipe)
        DAT_ISteamClient_ptr->BReleaseSteamPipe(DAT_steam_IPC_pipe);

    DAT_steam_IPC_pipe = 0;
    if (DAT_steam_alt_IPC_pipe) {
        DAT_ISteamClient_ptr->BReleaseSteamPipe(DAT_steam_alt_IPC_pipe);
        DAT_steam_alt_IPC_pipe = 0;
    }
    DAT_steamclient_ReleaseThreadLocalMemory = 0;
    if (DAT_ISteamClient_ptr)
        DAT_ISteamClient_ptr->BShutdownIfAllPipesClosed();

    DAT_ISteamClient_ptr = 0;
    DAT_steam_client_interface17 = 0;
    if (DAT_steamclient_hmodule) {
        FreeLibrary(DAT_steamclient_hmodule);
        //DAT_13b445780 = 0;
        //_DAT_Breakpad_SteamSendMiniDump = 0;
        //DAT_Breakpad_SteamWriteMiniDumpSetComment = 0;
        //if (DAT_13b445800 != '\0') {
        //    if (DAT_steambreakpad_module != (HMODULE)0x0) {
        //        FreeLibrary(DAT_steambreakpad_module);
        //    }
        //    DAT_steambreakpad_module = (HMODULE)0x0;
        //}
        DAT_modules_retrieved_count += 1;
    }
    DAT_steamclient_hmodule = 0;
}

//
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
        DAT_ISteamClient_ptr->Set_SteamAPI_CCheckCallbackRegisteredInProcess(Threaded::SteamAPI_CheckCallbackRegistered_t_func);
    
    // minidump write steam id
    //user_id = steam_user->GetSteamID();
    //FUN_13b4074c0(*user_id);
    return 0;
        
    
return_failure:
    SteamReplace::SteamAPI_Shutdown();
    return shutdown_Code;
}

// FINISHED
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





// SET REGISTER THING
//
//void SteamAPI_RegisterCallResult(void* CCallBackBase, int hAPICall){
//    // 0x7e40  949  SteamAPI_RegisterCallResult
//    if (0 < _DAT_register_callback_mode_manual) {
//        // WARNING: Could not recover jumptable at 0x00013b407e50. Too many branches
//        // WARNING: Treating indirect jump as call
//        //OutputDebugStringA("[S_API FAIL] SteamAPI_RegisterCallResult cannot be used; manual dispatch has already been selected.\n");
//        return;
//    }
//    _DAT_register_callback_mode_manual = 0xffffffff;
//    FUN_register_callback(CCallBackBase, hAPICall);
//    return;
//}

// SteamAPI_RunCallbacks
int DAT_13b445894 = 0;
int DAT_13b445890 = 0;
// process_callbacks
int process_callbacks_lock = 0;
int DAT_13b444360 = 0;

ISteamInput* DAT_SteamInput006;
ISteamUtils* DAT_SteamUtils010;
ISteamController* DAT_SteamController008;

// FINISHED
void Steam_RunFrames(){
    if (!DAT_ISteamClient_ptr) return;
    
    // init/run steam untils
    if (!DAT_SteamUtils010) {
        DAT_SteamUtils010 = (ISteamUtils*)DAT_ISteamClient_ptr->GetISteamGenericInterface(0, DAT_steam_IPC_pipe, "SteamUtils010");
        if (DAT_SteamUtils010) DAT_SteamUtils010->GetAppID();} // not sure why this is called
    if (DAT_SteamUtils010) 
        DAT_SteamUtils010->RunFrame();
    
    // init/run steam input
    if (!DAT_SteamInput006)
        DAT_SteamInput006 = (ISteamInput*)DAT_ISteamClient_ptr->GetISteamGenericInterface(DAT_steam_user, DAT_steam_IPC_pipe, "SteamInput006");
    if (DAT_SteamInput006)
        DAT_SteamInput006->RunFrame(0);

    // init/run steam controller
    if (!DAT_SteamController008)
        DAT_SteamController008 = (ISteamController*)DAT_ISteamClient_ptr->GetISteamGenericInterface(DAT_steam_user, DAT_steam_IPC_pipe, "SteamController008");
    if (DAT_SteamController008)
        DAT_SteamController008->RunFrame();
}

// 
void process_callbacks(Threaded::ISteamObj* steam, HSteamPipe ipc_pipe, char is_server) {
    char bVar1;
    CCallbackBase* plVar2;
    char cVar3;
    Threaded::ISteamObjMap* pIVar4;
    Threaded::ISteamObjMap* pIVar5;
    Threaded::ISteamObjMap* pIVar6;
    Threaded::ISteamObjMap* pIVar7;
    undefined8 uVar8;
    int iVar9;
    bool bVar10;
    undefined local_res20[8];
    //uint local_48;
    CallbackMsg_t cb_output;
    //int local_44;
    //undefined8 local_40;
    int local_38;

    if (DAT_steam_BGetCallback_func && DAT_steam_FreeLastCallback_func && !process_callbacks_lock) {
        process_callbacks_lock = 1;
        steam->ipc_pipe = ipc_pipe;
        while (DAT_steam_BGetCallback_func && (*DAT_steam_BGetCallback_func)(ipc_pipe, &cb_output) ) {

            steam->userid = cb_output.m_hSteamUser;
            if (DAT_13b444360 == 0) {


                pIVar5 = steam->map_struct;
                uVar8 = 0;
                bVar1 = pIVar5->self_ptr2->flag2;
                pIVar7 = pIVar5;
                pIVar6 = pIVar5->self_ptr2;
                while (bVar1 == 0) {
                    if (pIVar6->cb_index < cb_output.m_iCallback) {
                        pIVar4 = pIVar6->next_obj;
                        pIVar6 = pIVar7;
                    }
                    else
                        pIVar4 = pIVar6->prev_obj;
                    
                    pIVar7 = pIVar6;
                    pIVar6 = pIVar4;
                    bVar1 = pIVar4->flag2;
                }
                if (!pIVar7->flag2 && (pIVar7->cb_index <= cb_output.m_iCallback)) {
                    steam->active_map_struct = pIVar7;
                    while (pIVar7 != pIVar5){
                        if (pIVar7->cb_index != cb_output.m_iCallback) break;


                        FUN_13b403b30(&steam->active_map_struct);
                        plVar2 = pIVar7->callback;
                        if ((plVar2->m_nCallbackFlags & 2) == is_server) { 
                            uVar8 = 1;
                            plVar2->Run(cb_output.m_pubParam);
                        }


                        pIVar5 = steam->map_struct;
                        pIVar7 = (SteamReplace::Threaded::ISteamObjMap*)steam->active_map_struct;
                    } 
                }
                
                steam->active_map_struct = pIVar5;
                // this is probably for debugging?? not quite sure because we never set self_ptr2
                //if (steam->unk_ptr2)
                //    (*steam->unk_ptr2)(&cb_output, uVar8);
                
            }
            else {
                // doesn't happen because 'DAT_13b444360' is always zero
                //FUN_13b4041f0(steam, &cb_output, is_server); 
            }
            memset(cb_output.m_pubParam, 0, cb_output.m_cubParam);
            if (DAT_steam_FreeLastCallback_func)
                (*DAT_steam_FreeLastCallback_func)(ipc_pipe);
        }
        steam->ipc_pipe = 0;
        process_callbacks_lock = 0;
    }
}

void process_callbacks_wrapper(HSteamPipe ipc_pipe) {
    process_callbacks(Threaded::FUN_ISteam_thread(), ipc_pipe, 0);
}
void process_alt_callbacks(undefined4 ipc_pipe){
    //undefined local_res10[24]; // goes into DAT_steam_BGetCallback_func() supposedly
    CallbackMsg_t cb_output;

    while (true) {
        Threaded::FUN_ISteam_thread();
        if (!DAT_steam_BGetCallback_func) return;
        if (!(*DAT_steam_BGetCallback_func)(ipc_pipe, &cb_output)) break;

        Threaded::FUN_ISteam_thread();
        if (DAT_steam_FreeLastCallback_func)
            (*DAT_steam_FreeLastCallback_func)(ipc_pipe);
    }
}

void SteamAPI_RunCallbacks(void){
    int iVar1;
    bool bVar2;
    int iVar3;

    // 0x8420  953  SteamAPI_RunCallbacks
    bVar2 = false;
    if (DAT_steam_IPC_pipe != 0) {
        do {
            DAT_13b445894 = '\0';
            //LOCK();
            iVar1 = DAT_13b445890 + 1;
            if (DAT_13b445890 == 0) {
                if (_DAT_register_callback_mode_manual < 1) {
                    _DAT_register_callback_mode_manual = -1;
                    DAT_13b445890 = iVar1;
                    Steam_RunFrames();
                    process_callbacks_wrapper(DAT_steam_IPC_pipe);
                    if (DAT_steam_alt_IPC_pipe)
                        process_alt_callbacks(DAT_steam_alt_IPC_pipe);
                    
                    bVar2 = true;
                }
                else {
                    DAT_13b445890 = iVar1;
                    //OutputDebugStringA("[S_API FAIL] Standard callback dispatch cannot be used; manual dispatch has already been selected.\n");
                    bVar2 = true;
                }
            }
            else {
                DAT_13b445894 = 1;
                DAT_13b445890 = iVar1;
            }
            //LOCK();
            iVar1 = DAT_13b445890 - 1;
        } while ((DAT_13b445890 == 1) && (DAT_13b445890 = iVar1, DAT_13b445894 != 0));


        DAT_13b445890 = iVar1;
        if (bVar2)
            return;
    }

    if (DAT_steamclient_ReleaseThreadLocalMemory != 0)
        (*DAT_steamclient_ReleaseThreadLocalMemory)(0);
    
    if (DAT_steam_alt_IPC_pipe)
        process_alt_callbacks(DAT_steam_alt_IPC_pipe);
    return;
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

