#include "vm.h"


__declspec(dllimport)
BOOLEAN PsGetProcessExitProcessCalled(PEPROCESS process);

__declspec(dllimport)
PCSTR PsGetProcessImageFileName(QWORD process);

__declspec(dllimport)
QWORD PsGetProcessWow64Process(PEPROCESS process);

__declspec(dllimport)
QWORD PsGetProcessPeb(PEPROCESS process);


QWORD GetProcessByName(const char *process_name)
{
	QWORD process;
	QWORD entry;
	
	DWORD gActiveProcessLink = *(DWORD*)((char*)PsGetProcessId + 3) + 8;
	process = (QWORD)PsInitialSystemProcess;

	entry = process;
	do {
		if (PsGetProcessExitProcessCalled((PEPROCESS)entry))
			goto L0;
		
		if (PsGetProcessImageFileName(entry) && strcmp(PsGetProcessImageFileName(entry), process_name) == 0) {
			return entry;
		}
	L0:
		entry = *(QWORD*)(entry + gActiveProcessLink) - gActiveProcessLink;
	} while (entry != process);
	
	return 0;
}

BOOL vm_is_wow64(QWORD target_process)
{
	return PsGetProcessWow64Process((PEPROCESS)target_process) != 0;
}

static void vm_read(QWORD address, PVOID buffer, QWORD length)
{
	

	memcpy(buffer, (const void*)address, length);

	
}

static QWORD vm_read_i64(QWORD address, QWORD length)
{
	QWORD ret = 0;

	memcpy(&ret, (const void*)address, length);

	return ret;
}

QWORD GetModuleByName(QWORD target_process, const wchar_t *module_name)
{
	
	QWORD peb;
	DWORD a0[5];
	QWORD a1, a2, a3[32];

	if (vm_is_wow64(target_process)) {
		peb = (QWORD)PsGetProcessWow64Process((PEPROCESS)target_process);
		a0[0] = 0x04, a0[1] = 0x0C, a0[2] = 0x14, a0[3] = 0x28, a0[4] = 0x10;
	}
	else {
		peb = (QWORD)PsGetProcessPeb((PEPROCESS)target_process);
		a0[0] = 0x08, a0[1] = 0x18, a0[2] = 0x20, a0[3] = 0x50, a0[4] = 0x20;
	}

	if (peb == 0)
		return 0;

	a1 = vm_read_i64(vm_read_i64(peb + a0[1], a0[0]) + a0[2], a0[0]);
	a2 = a2 = vm_read_i64(a1 + a0[0], a0[0]);
	while (a1 != a2) {

		vm_read(vm_read_i64(a1 + a0[3], a0[0]), (char*)a3, (wcslen(module_name) * 2) + 2);

		
		if (wcscmp((const wchar_t *)a3, module_name) == 0) {
			return vm_read_i64(a1 + a0[4], a0[0]);
		}
		a1 = vm_read_i64(a1, a0[0]);
	}
	
	return 0;
}


