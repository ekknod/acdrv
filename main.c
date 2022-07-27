/*
 * ekknod@2021
 *
 * these methods were part of my hobby anti-cheat, and decided to make it public.
 * it's targetted against common kernel drivers.
 * 
 * current methods:
 * - Catch hidden / Unlinked system threads
 * - Catch execution outside of valid module range
 * - Catch KeStackAttachMemory/MmCopyVirtualMemory/ReadProcessMemory
 * - Catch Physical memory reading through PTE (Experimental honey pot)
 */

#include <intrin.h>
#include <ntifs.h>
#include "ia32.h"



#define TARGET_PROCESS "csgo.exe"
#define TARGET_MODULE L"client.dll"
#define TARGET_MODULEADDRESS 0x4DDB8FC // dwEntityList


typedef struct _KPRCB* PKPRCB;

__declspec(dllimport) PKPRCB
KeQueryPrcbAddress(
	__in ULONG Number
);

#ifndef CUSTOMTYPES
#define CUSTOMTYPES
typedef ULONG_PTR QWORD;
typedef ULONG DWORD;
typedef int BOOL;
#endif

__declspec(dllimport)
PCSTR PsGetProcessImageFileName(QWORD process);


PDRIVER_OBJECT gDriverObject;
PVOID thread_object;
HANDLE thread_handle;
BOOLEAN gExitCalled;

__declspec(dllimport)
BOOLEAN PsGetProcessExitProcessCalled(PEPROCESS process);

__declspec(dllimport)
PCSTR PsGetProcessImageFileName(QWORD process);

__declspec(dllimport)
QWORD PsGetProcessWow64Process(PEPROCESS process);

__declspec(dllimport)
QWORD PsGetProcessPeb(PEPROCESS process);


QWORD GetProcessByName(const char* process_name)
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

QWORD GetModuleByName(QWORD target_process, const wchar_t* module_name)
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


		if (wcscmp((const wchar_t*)a3, module_name) == 0) {
			return vm_read_i64(a1 + a0[4], a0[0]);
		}
		a1 = vm_read_i64(a1, a0[0]);
	}

	return 0;
}


// EPROCESS
BOOL IsThreadFoundEPROCESS(QWORD process, QWORD thread)
{
	BOOL contains = 0;

	QWORD address = (QWORD)PsGetThreadExitStatus;
	address += 0xA;
	DWORD RunDownProtectOffset = *(DWORD*)(address + 3);
	ULONG ThreadListEntryOffset = RunDownProtectOffset - 0x10;

	PLIST_ENTRY ThreadListEntry = (PLIST_ENTRY)((QWORD)process + *(UINT32*)((char*)PsGetProcessImageFileName + 3) + 0x38);
	PLIST_ENTRY list = ThreadListEntry;

	while ((list = list->Flink) != ThreadListEntry) {


		QWORD ethread_entry = (QWORD)((char*)list - ThreadListEntryOffset);
		if (ethread_entry == thread) {
			contains = 1;
			break;
		}
	}

	return contains;
}

// KTHREAD
BOOL IsThreadFoundKTHREAD(QWORD process, QWORD thread)
{
	BOOL contains = 0;


	// KTHREAD list
	PLIST_ENTRY list_head = (PLIST_ENTRY)((QWORD)process + 0x30);
	PLIST_ENTRY list_entry = list_head;

	while ((list_entry = list_entry->Flink) != 0 && list_entry != list_head) {
		QWORD entry = (QWORD)((char*)list_entry - 0x2f8);
		if (entry == thread) {
			contains = 1;
			break;
		}
	}

	return contains;
}


void NtSleep(DWORD milliseconds)
{
	QWORD ms = milliseconds;
	ms = (ms * 1000) * 10;
	ms = ms * -1;
#ifdef _KERNEL_MODE
	KeDelayExecutionThread(KernelMode, 0, (PLARGE_INTEGER)&ms);
#else
	NtDelayExecution(0, (PLARGE_INTEGER)&ms);
#endif
}

__declspec(dllimport)
NTSTATUS
PsGetContextThread(
      __in PETHREAD Thread,
      __inout PCONTEXT ThreadContext,
      __in KPROCESSOR_MODE Mode
  );

BOOL IsInValidRange(QWORD address);

void ThreadDetection(QWORD target_game)
{
	/*
	 * I'm not focusing to make clean code, this is just anti-cheat test bench.
	 * 
	 * I have written this in just couple minutes,
	 * that's why it's repeating a lot. who cares :D
	 * 
	 * logic is easy to understand at least.
	 * 
	 * 
	 * Modern Anti-Cheats what doesn't go through KPRCB properly:
	 * ESPORTAL/Vanguard/ESEA/EAC(?)/BE(?)
	 *
	 */

	QWORD current_thread, next_thread;

	for (int i = 0; i < KeNumberProcessors; i++) {
		PKPRCB prcb = KeQueryPrcbAddress(i);


		if (prcb == 0)
			continue;


		current_thread = *(QWORD*)((QWORD)prcb + 0x8);
		if (current_thread != 0) {

			if (current_thread == (QWORD)PsGetCurrentThread())
				goto skip_current;

			if (PsGetThreadExitStatus((PETHREAD)current_thread) != STATUS_PENDING)
				goto skip_current;


			CONTEXT ctx = { 0 };
			ctx.ContextFlags = CONTEXT_ALL;


			// 0x100 + 0x10
			

			

			QWORD cid = (QWORD)PsGetThreadId((PETHREAD)current_thread);
			QWORD host_process = *(QWORD*)(current_thread + 0x220);

			if (host_process == (QWORD)PsGetCurrentProcess() && NT_SUCCESS(PsGetContextThread((PETHREAD)current_thread, &ctx, KernelMode)))
			{
				if (!IsInValidRange(ctx.Rip))
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] Thread is outside of valid module [%ld, %llx] RIP[%llx]\n",
						PsGetProcessImageFileName(host_process),
						cid,
						current_thread,
						ctx.Rip
					);
			}

			BOOL hidden = 0;

			if (!IsThreadFoundKTHREAD(host_process, current_thread) || !IsThreadFoundEPROCESS(host_process, current_thread))
			{
				hidden = 1;

				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Hidden thread found [%s %d], %llx, %d]\n",
					PsGetProcessImageFileName(host_process),

					PsGetProcessId((PEPROCESS)host_process),

					current_thread,
					(DWORD)cid
				);
			}


			// if (thread->ApcState.Process == target_game_process) 
			if (target_game && target_game != host_process && *(QWORD*)(current_thread + 0x98 + 0x20) == target_game) {


				// small filter before proper validating
				BOOL temporary_whitelist = 0;
				if (host_process == (QWORD)PsGetCurrentProcess() && !hidden)
				{
					temporary_whitelist = 1;
				}

				char* target_str;
				if (hidden)
					target_str = "[%s] Hidden Thread (%llx, %ld) is attached to %s\n";
				else
					target_str = "[%s] Thread (%llx, %ld) is attached to %s\n";


				if (!temporary_whitelist)
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, target_str,
					PsGetProcessImageFileName(host_process),
					current_thread,
					(DWORD)cid,
					PsGetProcessImageFileName(*(QWORD*)(current_thread + 0x98 + 0x20))
				);

			}

			

		}
	skip_current:

		next_thread = *(QWORD*)((QWORD)prcb + 0x10);


		if (next_thread) {

			if (next_thread == (QWORD)PsGetCurrentThread())
				continue;

			if (PsGetThreadExitStatus((PETHREAD)next_thread) != STATUS_PENDING)
				continue;



			QWORD cid = (QWORD)PsGetThreadId((PETHREAD)next_thread);
			QWORD host_process = *(QWORD*)(next_thread + 0x220);


			BOOL hidden = 0;

			CONTEXT ctx = { 0 };
			ctx.ContextFlags = CONTEXT_ALL;
			if (host_process == (QWORD)PsGetCurrentProcess() && NT_SUCCESS(PsGetContextThread((PETHREAD)next_thread, &ctx, KernelMode)))
			{
				if (!IsInValidRange(ctx.Rip))
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] Thread is outside of valid module [%ld, %llx] RIP[%llx]\n",
						PsGetProcessImageFileName(host_process),
						cid,
						next_thread,
						ctx.Rip
					);
			}


			if (!IsThreadFoundKTHREAD(host_process, next_thread) || !IsThreadFoundEPROCESS(host_process, next_thread))
			{
				hidden = 1;

				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Hidden thread found [%s %d], %llx, %d]\n",
					PsGetProcessImageFileName(host_process),

					PsGetProcessId((PEPROCESS)host_process),

					next_thread,
					(DWORD)cid
				);
			}

			// if (thread->ApcState.Process == target_game_process) 
			if (target_game && target_game != host_process && *(QWORD*)(next_thread + 0x98 + 0x20) == target_game) {
				// small filter before proper validating
				BOOL temporary_whitelist = 0;
				if (host_process == (QWORD)PsGetCurrentProcess() && !hidden)
				{
					temporary_whitelist = 1;
				}


				char* target_str;
				if (hidden)
					target_str = "[%s] Hidden Thread (%llx, %ld) is attached to %s\n";
				else
					target_str = "[%s] Thread (%llx, %ld) is attached to %s\n";


				if (!temporary_whitelist)
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s] Thread (%llx, %ld) is attached to %s\n",
					PsGetProcessImageFileName(host_process),
					next_thread,
					(DWORD)cid,
					PsGetProcessImageFileName(*(QWORD*)(next_thread + 0x98 + 0x20))
				);

			}

		}


	}
}

#define ABS(a)                          \
  (((a) < 0) ? (-(a)) : (a))

BOOLEAN IsAddressEqual(LONGLONG address0, LONGLONG address2)
{
	LONGLONG res = ABS((LONGLONG)(address2 - address0));

	return res <= 0x1000;
}

// page walking code taken from https://github.com/Deputation/pagewalkr
void PteDetection(QWORD target_process, QWORD target_physicaladdress)
{




	CR3 kernel_cr3;
	kernel_cr3.flags = __readcr3();
	
	PHYSICAL_ADDRESS phys_buffer;
	phys_buffer.QuadPart = kernel_cr3.AddressOfPageDirectory << PAGE_SHIFT;

	PML4E_64* pml4 = (PML4E_64*)(MmGetVirtualForPhysical(phys_buffer));

	if (!MmIsAddressValid(pml4) || !pml4)
		return;

	
	for (int pml4_index = 0; pml4_index < 512; pml4_index++) {

		phys_buffer.QuadPart = pml4[pml4_index].PageFrameNumber << PAGE_SHIFT;
		if (!pml4[pml4_index].Present)
		{
			continue;
		}



		PDPTE_64* pdpt = (PDPTE_64*)(MmGetVirtualForPhysical(phys_buffer));
		if (!MmIsAddressValid(pdpt) || !pdpt)
			continue;

		for (int pdpt_index = 0; pdpt_index < 512; pdpt_index++) {

			phys_buffer.QuadPart = pdpt[pdpt_index].PageFrameNumber << PAGE_SHIFT;
			if (!pdpt[pdpt_index].Present)
			{
				continue;
			}

			PDE_64* pde = (PDE_64*)(MmGetVirtualForPhysical(phys_buffer));
			if (!MmIsAddressValid(pde) || !pde)
				continue;



			for (int pde_index = 0; pde_index < 512; pde_index++) {
				phys_buffer.QuadPart = pde[pde_index].PageFrameNumber << PAGE_SHIFT;

				if (!pde[pde_index].Present)
				{
					continue;
				}

				PTE_64* pte = (PTE_64*)(MmGetVirtualForPhysical(phys_buffer));
				if (!MmIsAddressValid(pte) || !pte)
					continue;

				for (int pte_index = 0; pte_index < 512; pte_index++) {
					phys_buffer.QuadPart = pte[pte_index].PageFrameNumber << PAGE_SHIFT;
					if (!pte[pte_index].Present) {
						continue;
					}





					if (IsAddressEqual(phys_buffer.QuadPart, (LONGLONG)target_physicaladdress))
					{
						DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Physical Memory PTE pointing to %s(%llx, %llx)\n",
							PsGetProcessImageFileName(target_process),
							pml4[pml4_index].PageFrameNumber << PAGE_SHIFT,
							phys_buffer.QuadPart
						);
					}

					
				}

			}
		}
	}
}

VOID
DriverUnload(
	_In_ struct _DRIVER_OBJECT* DriverObject
)
{

	(DriverObject);
	gExitCalled = 1;

	if (thread_object) {
		KeWaitForSingleObject(
			(PVOID)thread_object,
			Executive,
			KernelMode,
			FALSE,
			0
		);

		ObDereferenceObject(thread_object);

		ZwClose(thread_handle);
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Anti-Cheat.sys is closed\n");
}



__declspec(dllimport)
BOOLEAN PsGetProcessExitProcessCalled(PEPROCESS process);

NTSTATUS system_thread(void)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Anti-Cheat.sys is launched\n");


	QWORD target_game = 0;
	QWORD target_physicaladdress = 0;

	while (gExitCalled == 0) {
		NtSleep(1);

		

		if (target_game == 0 || PsGetProcessExitProcessCalled((PEPROCESS)target_game)) {
			target_physicaladdress = 0;
			target_game    = GetProcessByName(TARGET_PROCESS);

			if (target_game == 0)
				goto skip_address;
		}


		if (target_physicaladdress == 0) {
			KAPC_STATE state;
			BOOL was_attached = 0;

			__try {
			
				KeStackAttachProcess((PRKPROCESS)target_game, &state);

				was_attached = 1;

				QWORD client_dll = GetModuleByName(target_game, TARGET_MODULE);

				if (client_dll == 0)
					goto E0;


				QWORD temporary_address = client_dll + TARGET_MODULEADDRESS;
				PHYSICAL_ADDRESS entity_0 = MmGetPhysicalAddress((PVOID)temporary_address);
				target_physicaladdress = entity_0.QuadPart;
			E0:
				KeUnstackDetachProcess(&state);

			
			} __except (1) {

				if (was_attached)
				{
					KeUnstackDetachProcess(&state);
				}

			}

			if (target_physicaladdress) {

				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Anti-Cheat target physical address: %llx\n",
					target_physicaladdress
				);

			}
		}



	skip_address:


		/*
		 * Detect system hidden threads
		 * Detect virtual memory access for our target game
		 */
		ThreadDetection(target_game);

		/*
		 * Detect physical memory access for our target game
		 */
		if (target_game && target_physicaladdress)
			PteDetection(target_game, target_physicaladdress);


	}
	return PsTerminateSystemThread(STATUS_SUCCESS);
}


NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{

	(DriverObject);
	(RegistryPath);

	gDriverObject = DriverObject;
	DriverObject->DriverUnload = DriverUnload;





	CLIENT_ID thread_id;
	PsCreateSystemThread(&thread_handle, STANDARD_RIGHTS_ALL, NULL, NULL, &thread_id, (PKSTART_ROUTINE)system_thread, (PVOID)0);
	ObReferenceObjectByHandle(
		thread_handle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		(PVOID*)&thread_object,
		NULL
	);

	return STATUS_SUCCESS;
}

typedef struct _KLDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        VOID* ExceptionTable;
        UINT32 ExceptionTableSize;
        VOID* GpValue;
        VOID* NonPagedDebugInfo;
        VOID* ImageBase;
        VOID* EntryPoint;
        UINT32 SizeOfImage;
        UNICODE_STRING FullImageName;
        UNICODE_STRING BaseImageName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

BOOL IsInValidRange(QWORD address)
{
	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)gDriverObject->DriverSection;
	for (PLIST_ENTRY pListEntry = ldr->InLoadOrderLinks.Flink; pListEntry != &ldr->InLoadOrderLinks; pListEntry = pListEntry->Flink)
	{
		
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (address >= (QWORD)pEntry->ImageBase && address <= (QWORD)((QWORD)pEntry->ImageBase + pEntry->SizeOfImage))
			return 1;
		
	}
	
	return 0;
}
