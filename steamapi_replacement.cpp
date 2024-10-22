// steamapi_replacement.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include "C:\Users\Joe bingle\Downloads\steamworks_sdk_160\SteamLiteshop\sdk\public\steam\steam_api.h"

#include <string>
#include <iostream>
#include <cstdio>

#include <Libloaderapi.h>

#include <Processenv.h>

using namespace std;
namespace SteamReplace {


typedef unsigned long ulonglong;
typedef unsigned long __uint64;
typedef long longlong;
typedef unsigned int uint;
typedef int DWORD;
typedef char CHAR;

typedef unsigned long  undefined8;
typedef unsigned int   undefined4;
typedef unsigned short undefined2;
typedef unsigned char  undefined;

// func typedefs
typedef void* (*CreateInterface)(const char* pName, int* pReturnCode);
typedef void* (*ReleaseThreadLocalMemory)(bool thread_exit);


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

INT_PTR init_steam_client(HMODULE* resulting_hmodule, char* is_anon_user, undefined zero, const char* SteamClient021, char* error_output_buffer){
    //undefined auVar1[16];
    //longlong lVar2;
    char install_path_str_ptr;
    //int iVar3;
    HMODULE steamclient_library;
    //longlong lVar4;
    //__uint64 _Var5;
    LPCWSTR steamclient_path_wstr;
    CreateInterface create_interface_func;
    INT_PTR resulting_interface;
    //CHAR error_output[1040];
    //CHAR steam_install_path;
    //char acStack_427[1039];

    // TODO: dont even bother RE'ing this, just write our own thing??
    //SteamAPI_GetSteamInstallPath();
    //DAT_steam_install_path = 0;
    ////DAT_13b445870 = 0;
    ////DAT_13b445878 = 0;
    ////DAT_13b445880 = 0;
    //*resulting_hmodule = (HMODULE)0x0;
    //memset(&steam_install_path, 0, 0x410);
    //install_path_str_ptr = steam_write_install_path(&steam_install_path, 0x410);


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
    if (!SteamReplace::SteamAPI_IsSteamRunning()) {
        //OutputDebugStringA("[S_API] SteamAPI_Init(): SteamAPI_IsSteamRunning() did not locate a running instance of Steam.\n");
        goto init_steam_client_fail;
    }
    if (install_path_str_ptr == 0) {
        // "Could not determine Steam client install directory."
        goto init_steam_client_fail;
    }
    // more stuff related to getting the steam path string
    //lVar2 = -1;
    //do {
    //    lVar4 = lVar2;
    //    lVar2 = lVar4 + 1;
    //} while ((&steam_install_path)[lVar4 + 1] != '\0');
    //auVar1 = ZEXT816(2) * ZEXT816((longlong)(int)(lVar4 + 1) + 1);
    //_Var5 = SUB168(auVar1, 0);
    //if (SUB168(auVar1 >> 0x40, 0) != 0) {
    //    _Var5 = 0xffffffffffffffff;
    //}
    //steamclient_path_wstr = (LPCWSTR)operator_new(_Var5);
    //iVar3 = MultiByteToWideChar(0xfde9, 0, &steam_install_path, -1, steamclient_path_wstr, (int)lVar4 + 2);
    //if (iVar3 == 0) {
    //    *steamclient_path_wstr = L'\0';
    //}
    //free(steamclient_path_wstr);

    steamclient_library = LoadLibraryExW(steamclient_path_wstr, (HANDLE)0x0, 8);
    if (!steamclient_library) 
        steamclient_library = LoadLibraryExA(&steam_install_path, (HANDLE)0x0, 8);
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

undefined4 init_steam(char is_anon, const char* pszInternalCheckInterfaceVersions, char* error_output_buffer)
{
    char cVar1;
    undefined auVar2[16];
    uint app_id;
    ulonglong game_id;
    DWORD result;
    FARPROC pFVar4;
    INT_PTR IVar5;
    longlong lVar6;
    ISteamUtils* steam_utils;
    ISteamUser* steam_user;
    longlong lVar7;
    __uint64 _Var8;
    LPCWSTR lpWideCharStr;
    CSteamID user_id;
    undefined4 shutdown_Code;
    ulonglong local_res20;
    CHAR string_buf32[32];
    CHAR local_438;
    char acStack_437[1039];
    HMODULE temp_module;

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
        temp_module = DAT_steamclient_hmodule;
        //if (DAT_steamclient_ALT_module != (HMODULE)0x0) {
        //    temp_module = DAT_steamclient_ALT_module;
        //}
        pFVar4 = GetProcAddress(temp_module, "Steam_IsKnownInterface");
        if (pFVar4 != (FARPROC)0x0) {
            cVar1 = *pszInternalCheckInterfaceVersions;
            while (cVar1) {
                IVar5 = (*pFVar4)(pszInternalCheckInterfaceVersions);
                if ((char)IVar5 == '\0') {
                    //steam_format_error(error_output_buffer, "No %s", pszInternalCheckInterfaceVersions);
                    //steam_missing_feature(IPC_pipe, pszInternalCheckInterfaceVersions);
                    shutdown_Code = 3;
                    goto return_failure;
                }
                lVar6 = -1;
                do {
                    lVar7 = lVar6;
                    lVar6 = lVar7 + 1;
                } while (pszInternalCheckInterfaceVersions[lVar6] != '\0');
                pszInternalCheckInterfaceVersions = pszInternalCheckInterfaceVersions + lVar7 + 2;
                cVar1 = *pszInternalCheckInterfaceVersions;
            }
        }
    }
    if (!DAT_steamclient_ReleaseThreadLocalMemory) 
        DAT_steam_alt_IPC_pipe = DAT_ISteamClient_ptr->CreateSteamPipe();
    
    steam_utils = (ISteamUtils*)DAT_ISteamClient_ptr->GetISteamGenericInterface(0, DAT_steam_IPC_pipe, "SteamUtils010");
    if (!steam_utils) {
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
        sprintf(str_buf, "%u", app_id, "SteamUser023");
        SetEnvironmentVariableA("SteamAppId", string_buf32);
    }
    if (!GetEnvironmentVariableA("SteamGameId", (LPSTR)0x0, 0)) {
        char str_buf[32] = { 0 };
        sprintf(str_buf, "%llu", game_id, "SteamUser023");
        SetEnvironmentVariableA("SteamGameId", string_buf32);
        SetEnvironmentVariableA("SteamOverlayGameId", string_buf32);
    }
    if (!GetEnvironmentVariableA("SteamOverlayGameId", (LPSTR)0x0, 0)) {
        char str_buf[32] = { 0 };
        sprintf(str_buf, "%llu", game_id, "SteamUser023");
        SetEnvironmentVariableA("SteamOverlayGameId", string_buf32);
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
    ; DOODY;  SteamAPI_Shutdown();
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


int main()
{
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



