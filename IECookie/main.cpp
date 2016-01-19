#include <windows.h>
#define _CRT_SECURE_NO_WARNINGS 1
#include <stdio.h>

#define SAFE_FREE(x)  { if(x) free(x); x = NULL; }


//字符串转码
void NormalizeDomainA(char *domain)
{
	char *src, *dst;
	if (!domain)
		return;
	src = dst = domain;
	for(; *src=='.'; src++);
	for (;;) {
		if (*src == '/' || *src==NULL)
			break;
		*dst = *src;
		dst++;
		src++;
	}
	*dst = NULL;
}


void ParseIECookieFile(WCHAR *file)
{
	char *session_memory = NULL;
	DWORD session_size;
	HANDLE h_session_file;
	DWORD n_read = 0;
	char *ptr, *name, *value, *host;

	//创建文件
	h_session_file = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (h_session_file == INVALID_HANDLE_VALUE)
		return;

	//获取文件大小
	session_size = GetFileSize(h_session_file, NULL);
	if (session_size == INVALID_FILE_SIZE || session_size == 0) {
		CloseHandle(h_session_file);
		return;
	}
	session_memory = (char *)malloc(session_size + sizeof(WCHAR));
	if (!session_memory) {
		CloseHandle(h_session_file);
		return;
	}
	//读取
	memset(session_memory, 0, session_size + sizeof(WCHAR));
	if (!ReadFile(h_session_file, session_memory, session_size, &n_read, NULL)) {
		CloseHandle(h_session_file);
		SAFE_FREE(session_memory);
		return;
	}
	CloseHandle(h_session_file);
	if (n_read != session_size) {
		SAFE_FREE(session_memory);
		return;
	}

	ptr = session_memory;
	for(;;) {
		name = ptr;
		if (!(ptr = strchr(ptr, '\n')))
			break;
		*ptr = 0;
		ptr++;
		value = ptr;
		if (!(ptr = strchr(ptr, '\n')))
			break;
		*ptr = 0;
		ptr++;
		host = ptr;
		if (!(ptr = strchr(ptr, '\n')))
			break;
		*ptr = 0;
		ptr++;
		if (!(ptr = strstr(ptr, "*\n")))
			break;
		ptr+=2;
		NormalizeDomainA(host);

		if (host && name && value)
			printf("host=%s,\tname=%s,\tvalue=%s\n",host,name,value);

	} 
	SAFE_FREE(session_memory);
}

//获取 IE profile 文件路径
WCHAR *GetIEProfilePath(WCHAR *cookie_path)
{
	static WCHAR FullPath[MAX_PATH];
	WCHAR appPath[MAX_PATH];

	memset(appPath, 0, sizeof(appPath));
	GetEnvironmentVariableW(L"APPDATA", appPath, MAX_PATH);
	_snwprintf_s(FullPath, MAX_PATH, L"%s\\%s", appPath, cookie_path);  
	return FullPath;
}

int DumpIECookies(WCHAR *cookie_path)
{
	WCHAR *ie_dir;
	WIN32_FIND_DATAW find_data;
	WCHAR cookie_search[MAX_PATH];
	HANDLE hFind;

	//获取IP Profile 路径
	ie_dir = GetIEProfilePath(cookie_path);
	_snwprintf_s(cookie_search, MAX_PATH, L"%s\\*", ie_dir);  
	printf("\ncookie_path:\n%S\n",cookie_search);

	//开始cookie文件夹遍历
	hFind = FindFirstFileW(cookie_search, &find_data);
	if (hFind == INVALID_HANDLE_VALUE)
		return 0;
	do {
		if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) 
			continue;
		_snwprintf_s(cookie_search, MAX_PATH, _TRUNCATE, L"%s\\%s", ie_dir, find_data.cFileName); 
		//解析Cookie
		ParseIECookieFile(cookie_search);
	} while (FindNextFileW(hFind, &find_data));
	FindClose(hFind);
	return 1;
}


int main() 
{
	//IE cookie 存放路径
	DumpIECookies(L"Microsoft\\Windows\\Cookies");
	DumpIECookies(L"Microsoft\\Windows\\Cookies\\Low");
	DumpIECookies(L"..\\Local\\Microsoft\\Windows\\InetCookies");
	DumpIECookies(L"..\\Local\\Microsoft\\Windows\\InetCookies\\Low");
	DumpIECookies(L"..\\Local\\Microsoft\\Windows\\INetCache");
	DumpIECookies(L"..\\Local\\Microsoft\\Windows\\INetCache\\Low");
	system("pause");
	return 0;
}

