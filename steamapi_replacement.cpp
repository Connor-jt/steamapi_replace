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
#include <future>

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
static ISteamUser* DAT_ISteamUser_ptr;
static long* DAT_steam_client_interface17; // MARKED FOR REMOVAL!!
static char DAT_is_anon_user;
static HMODULE DAT_steamclient_hmodule;
//static HMODULE DAT_steamclient_ALT_module;
static HSteamPipe DAT_steam_IPC_pipe;
static HSteamPipe DAT_steam_alt_IPC_pipe;
static HSteamUser DAT_steam_user;



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
// 
//int SteamAPI_CheckCallbackRegistered_t_func(int iCallbackNum){
//    char cVar1;
//    int iVar6 = 0;
//    ISteamObjMap* callbacks_root;
//    ISteamObjMap* pIVar3;
//    ISteamObjMap* pIVar5;
//    ISteamObjMap* pIVar7;
//
//    callbacks_root = FUN_ISteam_thread()->map_struct;
//
//    pIVar3 = callbacks_root;
//    pIVar5 = callbacks_root->self_ptr2;
//
//    while (!pIVar5->flag2) {
//        if (pIVar5->cb_index < iCallbackNum) {
//            pIVar7 = pIVar5->next_obj;
//            pIVar5 = pIVar3;
//        }else
//            pIVar7 = pIVar5->prev_obj;
//       
//        pIVar3 = pIVar5;
//        pIVar5 = pIVar7;
//    }
//
//    if ((pIVar3->flag2 == 0) 
//    && ( pIVar3->cb_index <= iCallbackNum)) {
//        while ((pIVar3 != callbacks_root && (pIVar3->cb_index == iCallbackNum))) {
//            pIVar5 = pIVar3->next_obj;
//            iVar6 += 1;
//            if (!pIVar5->flag2) {
//                cVar1 = pIVar5->prev_obj->flag2;
//                pIVar3 = pIVar5;
//                pIVar5 = pIVar5->prev_obj;
//                while (!cVar1) {
//                    cVar1 = pIVar5->prev_obj->flag2;
//                    pIVar3 = pIVar5;
//                    pIVar5 = pIVar5->prev_obj;
//                }
//            }
//            else {
//                cVar1 = pIVar3->self_ptr2->flag2;
//                pIVar7 = pIVar3->self_ptr2;
//                pIVar5 = pIVar3;
//                while ((pIVar3 = pIVar7, !cVar1 && (pIVar5 == pIVar3->next_obj))) {
//                    cVar1 = pIVar3->self_ptr2->flag2;
//                    pIVar7 = pIVar3->self_ptr2;
//                    pIVar5 = pIVar3;
//                }
//            }
//        }
//    }
//    return iVar6;
//}
}



const HKEY HKCR = (HKEY)0xffffffff80000000lu; // HKEY_CLASSES_ROOT
const HKEY HKCU = (HKEY)0xffffffff80000001lu; // HKEY_CURRENT_USER
const HKEY HKLM = (HKEY)0xffffffff80000002lu; // HKEY_LOCAL_MACHINE

// FINISHED
bool SteamAPI_IsSteamRunning(){

    char str_buf[70] = {0}; 
    if (!MultiByteToWideChar(0xfde9, 0, "Software\\Valve\\Steam\\ActiveProcess", -1, (LPWSTR)str_buf, 35))
        return false;

    HKEY proc_key = 0;
    if (RegOpenKeyExW(HKCU, (LPWSTR)str_buf, 0, 0x20219, &proc_key))
        return false;

    memset(str_buf, 0, 70); // clean the buffer
    if (!MultiByteToWideChar(0xfde9, 0, "pid", -1, (LPWSTR)str_buf, 4)){
        RegCloseKey(proc_key);
        return false;}

    DWORD dwProcessId = 0;
    DWORD cbdata = 4;
    DWORD type = 0;
    if (RegQueryValueExW(proc_key, (LPWSTR)str_buf, 0, &type, (LPBYTE)&dwProcessId, &cbdata)) {
        RegCloseKey(proc_key);
        return false;}
    RegCloseKey(proc_key);
    
    HANDLE hProcess = OpenProcess(0x400, 0, dwProcessId);
    if (!hProcess)
        return false;

    DWORD exit_code = 0;
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
    if (!out_buf || (out_buf_size != 0x410)) 
        return false;

    char str_buf[70] = {0};
    if (!MultiByteToWideChar(0xfde9, 0, "Software\\Valve\\Steam\\ActiveProcess", -1, (LPWSTR)str_buf, 35))
        return false;

    HKEY proc_key = 0;
    if (RegOpenKeyExW(HKCU, (LPWSTR)str_buf, 0, 0x20219, &proc_key))
        return false;

    memset(str_buf, 0, 70); // clean the buffer
    if (!MultiByteToWideChar(0xfde9, 0, "SteamClientDll64", -1, (LPWSTR)str_buf, 17)) {
        RegCloseKey(proc_key);
        return false;
    }

    DWORD cbdata = 0x820;
    DWORD type = 0;
    BYTE processPath_wstr[0x822];
    if (RegQueryValueExW(proc_key, (LPWSTR)str_buf, 0, &type, processPath_wstr, &cbdata)) {
        RegCloseKey(proc_key);
        return false;
    }
    RegCloseKey(proc_key);

    // manually terminate wstring
    processPath_wstr[cbdata] = 0;
    processPath_wstr[cbdata+1] = 0;
    if (!WideCharToMultiByte(0xfde9, 0, (LPCWSTR)processPath_wstr, -1, out_buf, 0x410, 0, 0))
        return false;

    // alternative method to get filename if that failed (pretty sure this cant work with our setup)
    if (!out_buf[0]) {
        WCHAR alt_proc_path[0x103];
        alt_proc_path[0] = L'\0';
        if (!GetModuleFileNameW(GetModuleHandleA("steamclient64.dll"), alt_proc_path, 0x104) < 0x104)
            return false;
        if (!WideCharToMultiByte(0xfde9, 0, alt_proc_path, -1, out_buf, 0x410, 0, 0))
            return false;
    }
    return true;
}


/*
0 : success
1 : steam is already running
2 : "Cannot create IPC pipe to Steam client process.  Steam is probably not running."
3 : "ConnectToGlobalUser failed."
4 : interface check failed
5 : failed to load 'SteamUtils010' interface
6 : failed to load 'SteamUser023' interface
7 : "No appID found.  Either launch the game from Steam, or put the file steam_appid.txt containing the correct appID in your game folder."
8 : "[S_API] SteamAPI_Init(): SteamAPI_IsSteamRunning() did not locate a running instance of Steam."
9 : "Could not determine Steam client install directory."
10: couldn't convert path to wide string
11: Failed to load steam client module
12: "Unable to locate interface factory in steamclient64.dll"
13: failed to load 'SteamClient021' interface
*/

// FINISHED
int init_steam_client(HMODULE* resulting_hmodule, ISteamClient** resulting_interface){
    if (!SteamReplace::SteamAPI_IsSteamRunning())
        return 8;

    CHAR steam_install_path[0x410] = {0};
    if (!steam_write_install_path(steam_install_path, 0x410))
        return 9;
    
    // count chars in string (including the null terminator)
    int path_chars = 0;
    while (steam_install_path[path_chars++]);

    LPWSTR steamclient_path_wstr = (LPWSTR)new char[path_chars*2];
    if (!MultiByteToWideChar(0xfde9, 0, steam_install_path, -1, steamclient_path_wstr, path_chars)) {
        delete[] steamclient_path_wstr;
        return 10;}

    HMODULE steamclient_library = LoadLibraryExW(steamclient_path_wstr, 0, 8);
    delete[] steamclient_path_wstr;

    if (!steamclient_library) 
        steamclient_library = LoadLibraryExA(steam_install_path, 0, 8);
    if (!steamclient_library)
        return 11;
    
    CreateInterface create_interface_func = (CreateInterface)GetProcAddress(steamclient_library, "CreateInterface");
    if (!create_interface_func) {
        FreeLibrary(steamclient_library);
        return 12;}

    DAT_steamclient_ReleaseThreadLocalMemory = (ReleaseThreadLocalMemory)GetProcAddress(DAT_steamclient_hmodule, "Steam_ReleaseThreadLocalMemory");

    DAT_steam_client_interface17 = (long*)(*create_interface_func)("SteamClient017", 0);
    *resulting_interface = (ISteamClient*)(*create_interface_func)("SteamClient021", 0);
    *resulting_hmodule = steamclient_library; // not sure why this is set without resulting_interface being true

    if (!*resulting_interface) {
        FreeLibrary(steamclient_library);
        return 13;}

    return 0;
}

// FINISHED
void SteamAPI_Shutdown() {
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

    if (DAT_steamclient_hmodule)
        FreeLibrary(DAT_steamclient_hmodule);
    DAT_steamclient_hmodule = 0;


    DAT_steam_client_interface17 = 0;
}

// FINISHED
int init_steam(const char* pszInternalCheckInterfaceVersions){

    if (DAT_ISteamClient_ptr) return 1;

    int result = init_steam_client(&DAT_steamclient_hmodule, &DAT_ISteamClient_ptr);
    if (!result) return result;

    DAT_steam_IPC_pipe = DAT_ISteamClient_ptr->CreateSteamPipe();
    if (!DAT_steam_IPC_pipe) {
        SteamReplace::SteamAPI_Shutdown();
        return 2;}

    DAT_steam_user = DAT_ISteamClient_ptr->ConnectToGlobalUser(DAT_steam_IPC_pipe);
    if (!DAT_steam_user) {
        SteamReplace::SteamAPI_Shutdown();
        return 3;}

    // verify interface versions
    if (pszInternalCheckInterfaceVersions) {
        Steam_IsKnownInterface interface_check_func = (Steam_IsKnownInterface)GetProcAddress(DAT_steamclient_hmodule, "Steam_IsKnownInterface");
        if (interface_check_func) {
            while (*pszInternalCheckInterfaceVersions) {
                if (!(*interface_check_func)(pszInternalCheckInterfaceVersions)) {
                    SteamReplace::SteamAPI_Shutdown();
                    return 4;}
                // iterate string till we reach the next null terminator
                while (*pszInternalCheckInterfaceVersions++);
            }
        }
    }

    if (!DAT_steamclient_ReleaseThreadLocalMemory) 
        DAT_steam_alt_IPC_pipe = DAT_ISteamClient_ptr->CreateSteamPipe();
    
    ISteamUtils* steam_utils = (ISteamUtils*)DAT_ISteamClient_ptr->GetISteamGenericInterface(0, DAT_steam_IPC_pipe, "SteamUtils010");
    if (!steam_utils) {
        SteamReplace::SteamAPI_Shutdown();
        return 5;}

    DAT_ISteamUser_ptr = DAT_ISteamClient_ptr->GetISteamUser(DAT_steam_IPC_pipe, DAT_steam_user, "SteamUser023");
    if (!DAT_ISteamUser_ptr) {
        SteamReplace::SteamAPI_Shutdown();
        return 6;}

    uint app_id = steam_utils->GetAppID();
    ulonglong game_id = (ulonglong)app_id & 0xffffffff00ffffff; // not sure why this is a thing??
    if (!app_id) {
        SteamReplace::SteamAPI_Shutdown();
        return 7;}

    char str_buf[32];
    if (!GetEnvironmentVariableA("SteamAppId", 0, 0)) {
        memset(str_buf, 0, 32);
        sprintf(str_buf, "%u", app_id); // WARNING: ????
        SetEnvironmentVariableA("SteamAppId", str_buf);
    }
    if (!GetEnvironmentVariableA("SteamGameId", 0, 0)) {
        memset(str_buf, 0, 32);
        sprintf(str_buf, "%llu", game_id);
        SetEnvironmentVariableA("SteamGameId", str_buf);
        SetEnvironmentVariableA("SteamOverlayGameId", str_buf);
    }
    if (!GetEnvironmentVariableA("SteamOverlayGameId", 0, 0)) {
        memset(str_buf, 0, 32);
        sprintf(str_buf, "%llu", game_id);
        SetEnvironmentVariableA("SteamOverlayGameId", str_buf);
    }
    DAT_steam_BGetCallback_func = (Steam_BGetCallback)GetProcAddress(DAT_steamclient_hmodule, "Steam_BGetCallback");
    DAT_steam_FreeLastCallback_func = (Steam_FreeLastCallback)GetProcAddress(DAT_steamclient_hmodule, "Steam_FreeLastCallback");
    DAT_steam_GetAPICallResult_func = (Steam_GetAPICallResult)GetProcAddress(DAT_steamclient_hmodule, "Steam_GetAPICallResult");

    // not sure what our custom function would look like for this, if it even gets used??
    //DAT_ISteamClient_ptr->Set_SteamAPI_CCheckCallbackRegisteredInProcess(Threaded::SteamAPI_CheckCallbackRegistered_t_func);
    
    return 0;
}




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
    //int local_38;

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


                        //remap_cb_position(steam->active_map_struct);
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


void process_alt_callbacks(HSteamPipe ipc_pipe){
    //undefined local_res10[24]; // goes into DAT_steam_BGetCallback_func() supposedly
    CallbackMsg_t cb_output;

    while (true) {
        //Threaded::FUN_ISteam_thread();
        if (!DAT_steam_BGetCallback_func) return;
        if (!(*DAT_steam_BGetCallback_func)(ipc_pipe, &cb_output)) break;

        //Threaded::FUN_ISteam_thread();
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
            DAT_13b445894 = 0;
            //LOCK();
            iVar1 = DAT_13b445890 + 1;
            if (DAT_13b445890 == 0) {
                DAT_13b445890 = iVar1;
                Steam_RunFrames();
                process_callbacks(Threaded::FUN_ISteam_thread(), DAT_steam_IPC_pipe, 0);
                if (DAT_steam_alt_IPC_pipe)
                    process_alt_callbacks(DAT_steam_alt_IPC_pipe);
                    
                bVar2 = true;
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

ISteamUser* SteamUser() {
    return DAT_ISteamUser_ptr;
}

}

static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" "0123456789+/";
std::string base64_encode(unsigned char* bytes_to_encode, unsigned int in_len)
{
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--)
    {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }

    return ret;
}


static std::promise<void> SteamAuthComplete;
static std::string EncodedSteamAuth;

class SteamAuthHelper{
public:
    void OnEncryptedAppTicketResponse(EncryptedAppTicketResponse_t* pEncryptedAppTicketResponse, bool bIOFailure){
        switch (pEncryptedAppTicketResponse->m_eResult)
        {
        case k_EResultOK:
        {
            unsigned char rgubTicket[1024];
            uint32 cubTicket;
            if (SteamUser()->GetEncryptedAppTicket(rgubTicket, sizeof(rgubTicket), &cubTicket)){
                EncodedSteamAuth = base64_encode(rgubTicket, cubTicket);
                std::cout << "Steam App Ticket received" << std::endl;
            }
            else printf("GetEncryptedAppTicket failed.\n");
        }
        break;
        case k_EResultNoConnection:
            printf("Calling RequestEncryptedAppTicket while not connected to steam results in this error.\n"); 
            break;
        case k_EResultDuplicateRequest:
            printf("Calling RequestEncryptedAppTicket while there is already a pending request results in this " "error.\n"); 
            break;
        case k_EResultLimitExceeded:
            printf("Calling RequestEncryptedAppTicket more than once per minute returns this error.\n"); 
            break;
        }

        SteamAuthComplete.set_value();
    }

    CCallResult<SteamAuthHelper, EncryptedAppTicketResponse_t> m_SteamCallResultEncryptedAppTicket;
};

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
    int error_code = SteamReplace::init_steam(pszInternalCheckInterfaceVersions);


    std::atomic<bool> bHaltBackgroundThread{ false };
    // Set up a background thread to run
    std::thread HandlerThread = std::thread([&]() {
        while (!bHaltBackgroundThread){
            //Modio::RunPendingHandlers();
            SteamAPI_RunCallbacks();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
        bHaltBackgroundThread = false;
    });



    SteamAuthHelper* SteamCallbacks = new SteamAuthHelper();
    // Get the Steam Encrypted App Ticket
    char k_unSecretData[] = { 0x39, 0x66, 0x37, 0x61, 0x62, 0x64, 0x36, 0x33, 0x37, 0x35, 0x63, 0x34, 0x61, 0x33, 0x66, 0x64, 0x35, 0x30, 0x61, 0x37, 0x32, 0x62, 0x30, 0x39, 0x31, 0x31, 0x31, 0x35, 0x63, 0x62, 0x32, 0x33, 0x37, 0x32, 0x64, 0x35, 0x65, 0x35, 0x61, 0x63, 0x37, 0x61, 0x37, 0x37, 0x31, 0x39, 0x65, 0x35, 0x34, 0x30, 0x35, 0x33, 0x30, 0x62, 0x32, 0x39, 0x37, 0x65, 0x63, 0x34, 0x62, 0x65, 0x37, 0x39, 0x00 };
    SteamAPICall_t hSteamAPICall = SteamReplace::SteamUser()->RequestEncryptedAppTicket(&k_unSecretData, sizeof(k_unSecretData));
    SteamCallbacks->m_SteamCallResultEncryptedAppTicket.Set(hSteamAPICall, SteamCallbacks, &SteamAuthHelper::OnEncryptedAppTicketResponse);

    SteamAuthComplete.get_future().wait();




}

