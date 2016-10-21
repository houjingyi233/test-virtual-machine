// Tencent2016C.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include <shlwapi.h>
#include <tlhelp32.h>
#include "Tencent2016C.h"
#include "TencentAPI2016.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

BOOL CheckVMWare1()
{
	bool rc = true;
	__try
	{
		__asm
		{
			push   edx
			push   ecx
			push   ebx
			mov    eax, 'VMXh'
			mov    ebx, 0  
			mov    ecx, 10 
			mov    edx, 'VX' 
			in     eax, dx 
			cmp    ebx, 'VMXh' 
			setz   [rc] 
			pop    ebx
			pop    ecx
			pop    edx
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)  
	{
		rc = false;
	}
	return rc;
}

BOOL CheckVMWare2()
{
	string mac;
	get_3part_mac(mac);
	if (mac=="00-05-69" || mac=="00-0c-29" || mac=="00-50-56")
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVMWare3()
{
	DWORD ret = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32); 
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 
	if(hProcessSnap == INVALID_HANDLE_VALUE) 
	{ 
		return FALSE; 
	}
	BOOL bMore = Process32First(hProcessSnap, &pe32); 
	while(bMore)
	{
		if (strcmp(pe32.szExeFile, "vmtoolsd.exe")==0)
		{
			return TRUE;
		}

		bMore = Process32Next(hProcessSnap, &pe32); 
	}
	CloseHandle(hProcessSnap); 
	return FALSE;
}

BOOL CheckVMWare4()
{
	__asm
	{
		rdtsc
		xchg ebx, eax
		rdtsc
		sub eax, ebx
		cmp eax, 0xFF
		jg detected
	}
	return FALSE;
	detected:
		return TRUE;
}

BOOL CheckVMWare5()
{
	string table = "Win32_DiskDrive";
	wstring wcol = L"Caption";
	string ret;
	ManageWMIInfo(ret, table, wcol);
	if (ret.find("VMware") != string::npos)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVMWare6()
{
	string table = "Win32_computersystem";
	wstring wcol = L"Model";
	string ret;
	ManageWMIInfo(ret, table, wcol);
	if (ret.find("VMware") != string::npos)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVMWare7()
{
	HKEY hkey;
	if (RegOpenKey(HKEY_CLASSES_ROOT, "\\Applications\\VMwareHostOpen.exe", &hkey) == ERROR_SUCCESS)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVMWare8()
{
	int menu = 0;   
	SC_HANDLE SCMan = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE); 
	if(SCMan == NULL)  
	{
		cout << GetLastError() << endl;
		printf("OpenSCManager Eorror/n");  
		return -1;  
	}  
	LPENUM_SERVICE_STATUSA service_status;   
	DWORD cbBytesNeeded = NULL;   
	DWORD ServicesReturned = NULL;  
	DWORD ResumeHandle = NULL;  
	service_status = (LPENUM_SERVICE_STATUSA)LocalAlloc(LPTR, 1024 * 64);  
	bool ESS = EnumServicesStatusA(SCMan, 
		SERVICE_WIN32,
		SERVICE_STATE_ALL,  
		(LPENUM_SERVICE_STATUSA)service_status,  
		1024 * 64,  
		&cbBytesNeeded, 
		&ServicesReturned, 
		&ResumeHandle); 
	if(ESS == NULL)   
	{  
		printf("EnumServicesStatus Eorror/n");  
		return -1;  
	}  
	for(int i = 0; i < ServicesReturned; i++)  
	{  
		if (strstr(service_status[i].lpDisplayName, "VMware Tools")!=NULL || strstr(service_status[i].lpDisplayName, "VMware 物理磁盘助手服务")!=NULL)
		{
			return TRUE;
		}
	}  
	CloseServiceHandle(SCMan); 
	return FALSE;
}

BOOL CheckVMWare9()
{
	if (PathIsDirectory("C:\\Program Files\\VMware\\VMware Tools\\") == 0)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL CheckVMWare10()
{
	string table = "Win32_BaseBoard";
	wstring wcol = L"SerialNumber";
	string ret;
	ManageWMIInfo(ret, table, wcol);
	if (ret == "None")
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVMWare11()
{
	ULONG xdt = 0 ;
    ULONG InVM = 0;
    __asm
    {
        push edx
        sidt [esp-2]
        pop edx
        nop
        mov xdt , edx
    }
    if (xdt > 0xd0000000)
    {
 
        InVM = 1;
    }
    else
    {
        InVM = 0;
    }
    __asm
    {
        push edx
        sgdt [esp-2]
        pop edx
        nop
        mov xdt , edx
    } 
    if (xdt > 0xd0000000)
    {
        InVM += 1;
    }
	if (InVM == 0)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

BOOL CheckVMWare12()
{
	unsigned char mem[4] = {0};
    __asm str mem;
	if ((mem[0] == 0x00) && (mem[1] == 0x40))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVirtualPC1()
{
	string table = "Win32_computersystem";
	wstring wcol = L"Model";
	string ret;
	ManageWMIInfo(ret, table, wcol);
	if (ret.find("Virtual Machine") != string::npos)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVirtualPC2()
{
	string table = "Win32_DiskDrive";
	wstring wcol = L"Caption";
	string ret;
	ManageWMIInfo(ret, table, wcol);
	if (ret.find("Virtual HD") != string::npos)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVirtualPC3()
{
	__asm
	{
		rdtsc
		xchg ebx, eax
		rdtsc
		sub eax, ebx
		cmp eax, 0xFF
		jg detected
	}
	return FALSE;
detected:
	return TRUE;
}

BOOL CheckVirtualPC4()
{
	int menu = 0;  
	SC_HANDLE SCMan = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE); 
	if(SCMan == NULL)  
	{

		cout << GetLastError() << endl;
		printf("OpenSCManager Eorror/n");  
		return -1;  
	}  
	LPENUM_SERVICE_STATUSA service_status; 
	DWORD cbBytesNeeded = NULL;   
	DWORD ServicesReturned = NULL;  
	DWORD ResumeHandle = NULL;  
	service_status = (LPENUM_SERVICE_STATUSA)LocalAlloc(LPTR, 1024 * 64);
	bool ESS = EnumServicesStatusA(SCMan, 
		SERVICE_WIN32, 
		SERVICE_STATE_ALL,  
		(LPENUM_SERVICE_STATUSA)service_status,  
		1024 * 64,  
		&cbBytesNeeded, 
		&ServicesReturned, 
		&ResumeHandle); 
	if(ESS == NULL)   
	{  
		printf("EnumServicesStatus Eorror/n");  
		return -1;  
	}
	for(int i = 0; i < ServicesReturned; i++)  
	{  
		if (strstr(service_status[i].lpDisplayName, "Virtual Machine")!=NULL)
		{
			return TRUE;
		}
	}  
	CloseServiceHandle(SCMan);
	return FALSE;
}

BOOL CheckVirtualPC5()
{
	bool rc = TRUE;
	__try
	{
		__asm
		{
			push ebx
			mov ebx, 0
			mov eax, 1
			__emit 0fh
			__emit 3fh
			__emit 07h
			__emit 0bh
			test ebx, ebx
			setz[rc]
			pop ebx
		}
	}
	__except(IslnsideVPC_exceptionFilter(GetExceptionInformation()))
	{
		rc = FALSE;
	}
	return rc;
}

BOOL CheckVirtualPC6()
{
	string mac;
	get_3part_mac(mac);
	if (mac=="00-03-ff")
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVirtualBox1()
{
	DWORD ret = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32); 
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 
	if(hProcessSnap == INVALID_HANDLE_VALUE) 
	{ 
		return FALSE; 
	}
	BOOL bMore = Process32First(hProcessSnap, &pe32); 
	while(bMore)
	{
		if (strcmp(pe32.szExeFile, "VBoxService.exe")==0)
		{
			return TRUE;
		}

		bMore = Process32Next(hProcessSnap, &pe32); 
	}
	CloseHandle(hProcessSnap); 
	return FALSE;
}

BOOL CheckVirtualBox2()
{
	string mac;
	get_3part_mac(mac);
	if (mac=="08-00-27")
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVirtualBox3()
{	
	string table = "Win32_computersystem";
	wstring wcol = L"Model";
	string ret;
	ManageWMIInfo(ret, table, wcol);
	if (ret.find("VirtualBox") != string::npos)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVirtualBox4()
{
	string table = "Win32_DiskDrive";
	wstring wcol = L"Caption";
	string ret;
	ManageWMIInfo(ret, table, wcol);
	if (ret.find("VBOX") != string::npos)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVirtualBox5()
{
	int menu = 0;  
	SC_HANDLE SCMan = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE); 
	if(SCMan == NULL)  
	{

		cout << GetLastError() << endl;
		printf("OpenSCManager Eorror/n");  
		return -1;  
	}  
	LPENUM_SERVICE_STATUSA service_status; 
	DWORD cbBytesNeeded = NULL;  
	DWORD ServicesReturned = NULL;  
	DWORD ResumeHandle = NULL;  
	service_status = (LPENUM_SERVICE_STATUSA)LocalAlloc(LPTR, 1024 * 64);
	bool ESS = EnumServicesStatusA(SCMan, 
		SERVICE_WIN32, 
		SERVICE_STATE_ALL,  
		(LPENUM_SERVICE_STATUSA)service_status,  
		1024 * 64,  
		&cbBytesNeeded, 
		&ServicesReturned, 
		&ResumeHandle); 
	if(ESS == NULL)   
	{  
		printf("EnumServicesStatus Eorror/n");  
		return -1;  
	}  
	for(int i = 0; i < ServicesReturned; i++)  
	{  
		if (strstr(service_status[i].lpDisplayName, "VirtualBox Guest")!=NULL)
		{
			return TRUE;
		}
	}  
	CloseServiceHandle(SCMan);
	return FALSE;
}

BOOL CheckVirtualBox6()
{
	HKEY hkey;
	if (RegOpenKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", &hkey) == ERROR_SUCCESS)
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CheckVirtualBox7()
{
	__asm
	{
		rdtsc
		xchg ebx,eax
		rdtsc
		sub eax,ebx
		cmp eax,0xFF
		jg detected
	}
	return FALSE;
detected:
	return TRUE;
}

BOOL CheckVirtualBox8()
{
	if (PathIsDirectory("C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\") == 0)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}