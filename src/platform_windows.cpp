// This file is under GNU General Public License 3.0
// see LICENSE.txt

// Windows platform specification

#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#endif
#define _WIN32_WINNT 0x0600

#include <windows.h>
#define _CRT_RAND_S
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <string>
#include <stdexcept>
#include "platform_windows.h"
#include "dynamic_api.h"
#include <fcntl.h>
#include <tchar.h>
#include <sys\stat.h>

#define LOCAL_DB_FILENAME "management.db"
#define SYSTEM_DB_FILENAME "system.db"
#define KEYS_DB "keys.db"
#define USER_FOLDER_PATH pEpUserFolderPath().c_str()
#define SYSTEM_FOLDER_PATH pEpSystemFolderPath().c_str()

#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS      0x00000080  // error for invalid chars
#endif


using namespace std;

static string utf8_string(wstring wstr) {
    string result;

    if (wstr.length()) {
        int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                wstr.c_str(), -1, NULL, 0, NULL, NULL);
        assert(size);
        if (size) {
            char *buf = new char[size];
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wstr.c_str(),
                    -1, buf, size, NULL, NULL);
            result = buf;
            delete[] buf;
        } else
            throw out_of_range("input wstring is not valid"
                    " while converting UTF-16 to UTF-8.");
    }

    return result;
}

static wstring utf16_string(string str) {
    wstring result;

    if (str.length()) {
        int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                str.c_str(), -1, NULL, 0);
        assert(size);
        if (size) {
            wchar_t * buf = new wchar_t[size];
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, str.c_str(), -1,
                    buf, size);
            result = buf;
            delete[] buf;
        } else
            throw out_of_range("input string is not valid"
                    " while converting UTF-8 to UTF-16.");
    }

    return result;
}

static bool readRegistryString(
        HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName, LPTSTR lpResult,
        DWORD dwSize, LPCTSTR lpDefault
    )
{
    assert(lpResult);

	HKEY theKey;
	DWORD type;
	DWORD bytesCopied = dwSize;
	HRESULT result;

	result = RegOpenKeyEx(hKey, lpSubKey, 0, KEY_READ, &theKey);
	if (result != ERROR_SUCCESS) {
		if (lpDefault) {
			wcsncpy_s(lpResult, dwSize, lpDefault, _TRUNCATE);
			return true;
		}
		else
			return false;
	}

	result = RegQueryValueEx(theKey, lpValueName, NULL, &type,
            (LPBYTE) lpResult, &bytesCopied);
    if (result != ERROR_SUCCESS || (type != REG_EXPAND_SZ && type != REG_SZ)) {
		if (lpDefault) {
			wcsncpy_s(lpResult, dwSize, lpDefault, _TRUNCATE);
			RegCloseKey(theKey);
			return true;
		}
		else {
			RegCloseKey(theKey);
			return false;
		}
	}

	RegCloseKey(theKey);
	return true;
}

static const DWORD PATH_BUF_SIZE = 32768;

static inline string managementPath(const char *file_path, const char *file_name)
{
    string path;
    TCHAR tPath[PATH_BUF_SIZE];

    DWORD length = ExpandEnvironmentStringsW(utf16_string(file_path).c_str(),
            tPath, PATH_BUF_SIZE);
	assert(length);
    if (length == 0)
        throw bad_alloc(); // BUG: there are other errors possible beside out of memory

	CreateDirectory(tPath, NULL);
	DWORD error = GetLastError();

	path = utf8_string(tPath);
	path += "\\";
	path += file_name;

	return path;
}

static inline string pEpSystemFolderPath(void)
{
	static TCHAR tPath[PATH_BUF_SIZE];
	string path = PER_MACHINE_DIRECTORY;

	// Get SystemFolder Registry value and use if available
	bool result = readRegistryString(HKEY_CURRENT_USER,
		TEXT("SOFTWARE\\pEp"), TEXT("SystemFolder"), tPath,
		PATH_BUF_SIZE, NULL);

	if (result)
		path = utf8_string(tPath);

	return path;
}

static inline string pEpUserFolderPath(void)
{
	static TCHAR tPath[PATH_BUF_SIZE];
	string path = PER_USER_DIRECTORY;

	// Get UserFolder Registry value and use if available
	bool result = readRegistryString(HKEY_CURRENT_USER,
		TEXT("SOFTWARE\\pEp"), TEXT("UserFolder"), tPath,
		PATH_BUF_SIZE, NULL);

	if (result)
		path = utf8_string(tPath);
	
	return path;
}

extern "C" {

DYNAMIC_API const char *per_user_directory(void)
{
    static string path;
    if (path.length())
        return path.c_str();

    TCHAR tPath[PATH_BUF_SIZE];
    DWORD length = ExpandEnvironmentStringsW(utf16_string(string(PER_USER_DIRECTORY)).c_str(),
            tPath, PATH_BUF_SIZE);
	assert(length);
    if (length == 0)
        throw bad_alloc(); // BUG: there are other errors possible beside out of memory

    path = utf8_string(wstring(tPath));
    return path.c_str();
}

DYNAMIC_API const char *per_machine_directory(void)
{
    static string path;
    if (path.length())
        return path.c_str();

    TCHAR tPath[PATH_BUF_SIZE];
    DWORD length = ExpandEnvironmentStringsW(utf16_string(string(PER_MACHINE_DIRECTORY)).c_str(),
            tPath, PATH_BUF_SIZE);
	assert(length);
    if (length == 0)
        throw bad_alloc(); // BUG: there are other errors possible beside out of memory

    path = utf8_string(wstring(tPath));
    return path.c_str();
}

void *dlopen(const char *filename, int flag) {
	static TCHAR path[PATH_BUF_SIZE];

    assert(filename);
	assert(flag == RTLD_LAZY); // only lazy binding is implemented

	// Look up GnuPG installation in current user scope
	bool result = readRegistryString(HKEY_CURRENT_USER,
		TEXT("SOFTWARE\\GnuPG"), TEXT("Install Directory"), path,
		PATH_BUF_SIZE, NULL);
	// If not found in current user, look up in local machine
	if (!result)
		result = readRegistryString(HKEY_LOCAL_MACHINE,
			TEXT("SOFTWARE\\GnuPG"), TEXT("Install Directory"), path,
			PATH_BUF_SIZE, NULL);
	assert(result);
	if (!result)
		return NULL;

    SetDllDirectory(TEXT(""));
    BOOL _result = SetDllDirectory(path);
    assert(_result != 0);
    if (_result == 0)
        return NULL;

	HMODULE module = LoadLibrary(utf16_string(filename).c_str());

    if (module == NULL) {
        SetDllDirectory(NULL);
                    
		_tcscat_s(path, TEXT("\\bin"));
        
        SetDllDirectory(TEXT(""));
        _result = SetDllDirectory(path);
        assert(_result != 0);
        if (_result == 0)
            return NULL;

    	module = LoadLibrary(utf16_string(filename).c_str());
    }
    
    SetDllDirectory(NULL);
	if (module == NULL)
		return NULL;
	else
		return (void *) module;
}

int dlclose(void *handle) {
	if (FreeLibrary((HMODULE) handle))
		return 0;
	else
		return 1;
}

void *dlsym(void *handle, const char *symbol) {
	return (void *) (intptr_t) GetProcAddress((HMODULE) handle, symbol);
}

const char *windoze_keys_db(void) {
	static string path;
	if (path.length() == 0) {
		path = managementPath(USER_FOLDER_PATH, KEYS_DB);
	}
	return path.c_str();
}

const char *windoze_local_db(void) {
	static string path;
	if (path.length() == 0)
        path = managementPath(PER_USER_DIRECTORY, LOCAL_DB_FILENAME);
    return path.c_str();
}

const char *windoze_system_db(void) {
	static string path;
	if (path.length() == 0)
		path = managementPath(PER_MACHINE_DIRECTORY, SYSTEM_DB_FILENAME);
    return path.c_str();
}

const char *gpg_conf(void)
{
    static string path;
    if (path.length() == 0)
        path = managementPath("%APPDATA%\\gnupg", "gpg.conf");
    return path.c_str();
}

const char *gpg_agent_conf(void)
{
    static string agent_path;
    if (agent_path.length() == 0)
        agent_path = managementPath("%APPDATA%\\gnupg", "gpg-agent.conf");
    return agent_path.c_str();
}


long random(void)
{
    unsigned int r;
    errno_t e;

    assert(sizeof(unsigned int) == sizeof(long)); // this is Windoze

    do {
        e = rand_s(&r);
    } while (e);

    return (long) (r & ((1U<<31)-1));
}

char *strndup(const char *s1, size_t n)
{
    char *str = (char *) calloc(n + 1, 1);
    if (str == NULL)
        return NULL;

    strncpy(str, s1, n);
    return str;
}

char *stpcpy(char *dst, const char *src)
{
    for (;; ++dst, ++src) {
        *dst = *src;
        if (*dst == 0)
            break;
    }
    return dst;
}

size_t strlcpy(char* dst, const	char* src, size_t size) {
    size_t retval = strlen(src);
    size_t size_to_copy = (retval < size ? retval : size - 1);
    
    // strlcpy doc says src and dst not allowed to overlap, as
    // it's undefined. So this is acceptable:
    memcpy((void*)dst, (void*)src, size_to_copy); // no defined error return, but strcpy doesn't either
    dst[size_to_copy] = '\0';
    return retval;
}
size_t strlcat(char* dst, const	char* src, size_t size) {
    size_t start_len = strnlen(dst, size);
    if (start_len == size)
        return size; // no copy, no null termination in size bytes, according to spec
    
    size_t add_len = strlen(src);
    size_t retval = start_len + add_len;
    size_t size_to_copy = (retval < size ? add_len : (size - start_len) - 1);
    
    // strlcat doc says src and dst not allowed to overlap, as
    // it's undefined. So this is acceptable:
    memcpy((void*)(dst + start_len), (void*)src, size_to_copy); // no defined error return, but strcpy doesn't either
    dst[start_len + size_to_copy] = '\0';
    return retval;
}
char *strnstr(const char *big, const char *little, size_t len) {
    if (big == NULL || little == NULL)
        return NULL;
        
    if (*little == '\0')
        return (char*)big;
        
    const char* curr_big = big;
    
    size_t little_len = strlen(little);
    size_t remaining = len;

    const char* retval = NULL;
    
    for (remaining = len; remaining >= little_len && *curr_big != '\0'; remaining--, curr_big++) {
        // find first-char match
        if (*curr_big != *little) {
            continue;
        }
        retval = curr_big;

        const char* inner_big = retval + 1;
        const char* curr_little = little + 1;
        int j;
        for (j = 1; j < little_len; j++, inner_big++, curr_little++) {
            if (*inner_big != *curr_little) {
                retval = NULL;
                break;
            }    
        }
        if (retval)
            break;
    }
    return (char*)retval;
}

int mkstemp(char *templ)
{
    char *pathname = _mktemp(templ);
    if (!pathname)
        return -1;
    return _open(pathname, _O_RDWR | _O_CREAT | _O_EXCL, _S_IREAD | _S_IWRITE);
}

void uuid_generate_random(pEpUUID out)
{
    RPC_STATUS rpc_status = UuidCreate(out);
    assert(rpc_status == RPC_S_OK);
}

int uuid_parse(char *in, pEpUUID uu)
{
    unsigned char *_in = (unsigned char *) in;
    RPC_STATUS rpc_status = UuidFromStringA(_in, uu);
    assert(rpc_status == RPC_S_OK);
    if (rpc_status == RPC_S_INVALID_STRING_UUID)
        return -1;
    return 0;
}

void uuid_unparse_upper(pEpUUID uu, uuid_string_t out)
{
    unsigned char *_out = (unsigned char*)out;
    RPC_CSTR str;
    RPC_STATUS rpc_status = UuidToStringA(uu, &str);
    assert(rpc_status == RPC_S_OK);
    if (rpc_status == RPC_S_OK) {
        memcpy(out, str, 36);
        out[36] = 0;
        RpcStringFreeA(&str);
    }
    else { // if (rpc_status == RPC_S_OUT_OF_MEMORY)
        memset(out, 0, 37);
    }
}

void log_output_debug(const char *title,
                       const char *entity,
                       const char *description,
                       const char *comment)
{
	const size_t size = 256;
	char str[size];
	
	snprintf(str, size, "*** %s %s %s %s\n", title, entity, description, comment);
	OutputDebugStringA(str);
}

time_t timegm(struct tm* tm) {
    return _mkgmtime(tm);
}

} // "C"
