/*
 * ekknod@2022
 *
 * Some of these methods were part of my hobby anti-cheat.
 * I used that tool for fixing potential detection vectors.
 * Hopefully you guys find this tool useful (both AC and cheat developers)
 * 
 * It catches a lot of Legit action as well, its nowhere perfect.
 * Also code is written for single file only, it's because it was originally just checking hidden threads.
 *
 * current methods:
 * - Catch hidden / Unlinked system threads                          [Detection]
 * - Catch manual MouseClassServiceCallback call                     [Detection]
 * - Catch execution outside of valid module range                   [Suspicious action]
 * - Check KeStackAttachMemory/MmCopyVirtualMemory/ReadProcessMemory [Suspicious action]
 * 
 */

#include <intrin.h>
#include <ntifs.h>

#define TARGET_PROCESS "csgo.exe"

//
// this project did not actually need NMI interrupts since we can do almost the same at KPRCB,
// but i decided to add since some people might need it for their own purposes.
// 
// changing NMI_INTERRUPT define to something else for example 0 will disable NMI interrupts
// NMI_INTERRUPT_INTERVAL 100ms for test bench, real anti-cheat would probably have interrupts less often.
//

#define NMI_INTERRUPT_INTERVAL 100
#define NMI_INTERRUPT 1

#ifndef CUSTOMTYPES
#define CUSTOMTYPES
typedef ULONG_PTR QWORD;
typedef ULONG DWORD;
typedef int BOOL;
typedef unsigned char BYTE;
typedef unsigned short WORD;
#endif


typedef struct {
	QWORD base, size;
} IMAGE_INFO_TABLE;


typedef struct {
	QWORD thread;
	QWORD address;
	QWORD count;
	QWORD time;
} THREAD_INFO_TABLE;


#define           MAX_THREAD_COUNT 1000
THREAD_INFO_TABLE g_thread_stack_list[MAX_THREAD_COUNT];
int               g_thread_stack_list_count;
void              push_back_stacklist(QWORD thread, QWORD address);
THREAD_INFO_TABLE *get_stacklist_item(QWORD thread);

//
// uefi runtime services, used for whitelisting some non kernel addresses
// this validation is not yet completely working, since some of these HalEfiFunctions are calling relative addresses sub EFI modules
//
#define HAL_EFI_COUNT 9
QWORD            HalEfiFunctions[HAL_EFI_COUNT];
IMAGE_INFO_TABLE HalEfiImages[HAL_EFI_COUNT];
BOOL             HalEfiEnabled = 0;



//
// vmware
//
IMAGE_INFO_TABLE vmusbmouse;



//
// DriverEntry/DriverUnload
//
PDRIVER_OBJECT gDriverObject;
PVOID   gThreadObject;
HANDLE  gThreadHandle;
QWORD   gThreadProcess;
BOOLEAN gExitCalled;

#if NMI_INTERRUPT == 1
DWORD   gCtxOffset;
PVOID   NmiCallbackHandle;
QWORD   gTotalNmiCount;
#endif

//
// IdleThread object
//
QWORD KiIdleThread = 0;

//
// MouseClassServiceCallbackHook
//
#pragma warning(disable : 4201)
typedef struct _MOUSE_INPUT_DATA {
	USHORT UnitId;
	USHORT Flags;
	union {
		ULONG Buttons;
		struct {
			USHORT ButtonFlags;
			USHORT ButtonData;
		};
	};
	ULONG  RawButtons;
	LONG   LastX;
	LONG   LastY;
	ULONG  ExtraInformation;
} MOUSE_INPUT_DATA, * PMOUSE_INPUT_DATA;

typedef VOID
(*MouseClassServiceCallbackFn)(
	PDEVICE_OBJECT DeviceObject,
	PMOUSE_INPUT_DATA InputDataStart,
	PMOUSE_INPUT_DATA InputDataEnd,
	PULONG InputDataConsumed
	);

typedef struct _MOUSE_OBJECT
{
	PDEVICE_OBJECT              mouse_device;
	MouseClassServiceCallbackFn service_callback;
	BOOL                        hook;
	QWORD                       hid;
	QWORD                       hid_length;
} MOUSE_OBJECT, * PMOUSE_OBJECT;

MOUSE_OBJECT gMouseObject;
QWORD _KeAcquireSpinLockAtDpcLevel;
QWORD _KeReleaseSpinLockFromDpcLevel;
QWORD _IofCompleteRequest;
QWORD _IoReleaseRemoveLockEx;
BOOL mouse_hook(void);
void mouse_unhook(void);
QWORD MouseClassServiceCallback(
	PDEVICE_OBJECT DeviceObject,
	PMOUSE_INPUT_DATA InputDataStart,
	PMOUSE_INPUT_DATA InputDataEnd,
	PULONG InputDataConsumed
);



//
// helper functions
//
QWORD GetMilliSeconds();
QWORD GetProcAddressQ(QWORD base, PCSTR name);
QWORD FindPattern(QWORD module, BYTE* bMask, CHAR* szMask, QWORD len);
QWORD FindPatternEx(UINT64 dwAddress, QWORD dwLen, BYTE* bMask, char* szMask);
PVOID ResolveRelativeAddress(
	_In_ PVOID Instruction,
	_In_ ULONG OffsetOffset,
	_In_ ULONG InstructionSize
);
BOOL ResolveHalEfiBase(QWORD address, QWORD* base, QWORD* size);
QWORD GetModuleHandle(PWCH module_name, QWORD* SizeOfImage);
QWORD GetProcessByName(const char* process_name);
BOOL IsThreadFoundEPROCESS(QWORD process, QWORD thread);
void NtSleep(DWORD milliseconds);
__declspec(dllimport) LIST_ENTRY *PsLoadedModuleList;
__declspec(dllimport) PCSTR PsGetProcessImageFileName(QWORD process);
__declspec(dllimport) BOOLEAN PsGetProcessExitProcessCalled(PEPROCESS process);
typedef struct _KPRCB* PKPRCB;
__declspec(dllimport) PKPRCB KeQueryPrcbAddress(__in ULONG Number);
__int64(__fastcall* MiGetPteAddress)(unsigned __int64 a1);

//
// complete functions
//
BOOL IsInValidRange(QWORD address);
BOOL GetThreadStack(QWORD thread, CONTEXT* thread_context);


//
// Anti Cheat checks
//
QWORD MouseClassServiceCallbackHook(
	PDEVICE_OBJECT DeviceObject,
	PMOUSE_INPUT_DATA InputDataStart,
	PMOUSE_INPUT_DATA InputDataEnd,
	PULONG InputDataConsumed
)
{
	if (KiIdleThread != 0 && KiIdleThread != (QWORD)PsGetCurrentThread())
	{
		QWORD thread = (QWORD)PsGetCurrentThread();
		QWORD host_process = *(QWORD*)(thread + 0x220);
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s][%ld] Thread is manipulating mouse [%llx]\n",
			PsGetProcessImageFileName(host_process),
			(DWORD)(QWORD)PsGetThreadId((PETHREAD)thread),
			thread
		);
	}

	QWORD address = (QWORD)_ReturnAddress();
	if (address < (QWORD)gMouseObject.hid || address >(QWORD)((QWORD)gMouseObject.hid + gMouseObject.hid_length))
	{
		// extra check for vmware virtual machine
		if (address < (QWORD)vmusbmouse.base || address >(QWORD)((QWORD)vmusbmouse.base + vmusbmouse.size))
		{
			QWORD thread = (QWORD)PsGetCurrentThread();
			QWORD host_process = *(QWORD*)(thread + 0x220);
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s][%ld] Thread is manipulating mouse [%llx]\n",
				PsGetProcessImageFileName(host_process),
				(DWORD)(QWORD)PsGetThreadId((PETHREAD)thread),
				thread
			);
		}
	}

	// C/C++ -> All Options -> Control Overflow Guard : OFF, otherwise compiler will create CALL instruction and it will BSOD.
	// Sadly inline assembly is not supported by x64 C/C++.
	return ((QWORD(*)(PDEVICE_OBJECT, PMOUSE_INPUT_DATA, PMOUSE_INPUT_DATA, PULONG))((QWORD)MouseClassServiceCallback + 5))(
		DeviceObject,
		InputDataStart,
		InputDataEnd,
		InputDataConsumed
		);


}

BOOL AntiCheatUnlinkDetection(QWORD thread)
{
	BOOL hidden = 0;

	if (thread == 0)
		return 0;

	QWORD host_process = *(QWORD*)(thread + 0x220);



	QWORD lookup_thread;
	if (NT_SUCCESS(PsLookupThreadByThreadId(
		(HANDLE)PsGetThreadId((PETHREAD)thread),
		(PETHREAD*)&lookup_thread
	)))
	{
		if (lookup_thread == thread)
		{
			return 0;
		}
	}

	if (!IsThreadFoundEPROCESS(host_process, thread))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s][%ld] Thread is unlinked [%llx]\n",
			PsGetProcessImageFileName(host_process),
			(DWORD)(QWORD)PsGetThreadId((PETHREAD)thread),
			thread
		);
		hidden = 1;
	}

	return hidden;
}

BOOL AntiCheatAttachProcessDetection(QWORD target_game, QWORD thread)
{
	BOOL attach = 0;

	if (thread == 0)
		return 0;

	if (target_game == 0)
		return 0;

	QWORD host_process = *(QWORD*)(thread + 0x220);
	if (target_game == host_process)
		return 0;

	if (*(QWORD*)(thread + 0x98 + 0x20) == target_game) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%s][%ld] Thread is attached to %s\n",
			PsGetProcessImageFileName(host_process),
			(DWORD)(QWORD)PsGetThreadId((PETHREAD)thread),
			PsGetProcessImageFileName(*(QWORD*)(thread + 0x98 + 0x20))
		);
		attach = 1;
	}
	return attach;
}

#define TRIGGER_DETECTION_MS  100
#define TRIGGER_COUNTER       10000
void AntiCheatInvalidRangeDetection(QWORD thread, CONTEXT ctx, BOOLEAN nmi)
{
	if (thread == 0)
		return;

	if (!PsIsSystemThread((PETHREAD)thread))
	{
		QWORD thread_process = *(QWORD*)(thread + 0x220);
		if (thread_process != (QWORD)gThreadProcess)
		{
			return;
		}
	}

	if (!IsInValidRange(ctx.Rip)) {
		THREAD_INFO_TABLE *table = get_stacklist_item(thread);
		if (table)
		{
			QWORD ms = GetMilliSeconds();
			QWORD previous_ms = table->time;
			BOOL  cnt_triggered = (ms - previous_ms < TRIGGER_DETECTION_MS) + (table->count > TRIGGER_COUNTER);

			if (cnt_triggered || nmi)
			{
				QWORD host_process = *(QWORD*)(thread + 0x220);
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
					"[%s][%ld] Thread outside of valid module RIP[%llx] RSP[%llx]\n",
					PsGetProcessImageFileName(host_process),
					(DWORD)(QWORD)PsGetThreadId((PETHREAD)thread),
					ctx.Rip,
					ctx.Rsp
				);
			}
		}
		push_back_stacklist(thread, ctx.Rip);
	}
}

#if NMI_INTERRUPT == 1

BOOLEAN
NmiCallback(
    _In_opt_ PVOID Context,
    _In_ BOOLEAN Handled
    )
{
	UNREFERENCED_PARAMETER(Context);
	UNREFERENCED_PARAMETER(Handled);
	struct  _CONTEXT *current_context = *(struct  _CONTEXT **)(__readgsqword(0x20) + gCtxOffset);
	AntiCheatInvalidRangeDetection(__readgsqword(0x188), *current_context, 1);
	AntiCheatUnlinkDetection(__readgsqword(0x188));
	gTotalNmiCount = gTotalNmiCount + 1;
	return 1;
}

#endif

void AntiCheat(QWORD target_game)
{
	QWORD current_thread, next_thread;

	for (int i = 0; i < KeNumberProcessors; i++) {
		PKPRCB prcb = KeQueryPrcbAddress(i);


		if (prcb == 0)
			continue;

		current_thread = *(QWORD*)((QWORD)prcb + 0x8);
		next_thread = *(QWORD*)((QWORD)prcb + 0x10);

		if (current_thread != 0 && current_thread != (QWORD)PsGetCurrentThread())
		{
			if (KiIdleThread == 0)
			{
				if (PsGetThreadProcessId((PETHREAD)current_thread) == 0 && PsGetThreadId((PETHREAD)current_thread) == 0)
				{
					KiIdleThread = current_thread;
				}
			}


			AntiCheatAttachProcessDetection(target_game, current_thread);

			CONTEXT ctx;
			ctx.ContextFlags = CONTEXT_ALL;
			if (GetThreadStack(current_thread, &ctx)) {
				AntiCheatInvalidRangeDetection(current_thread, ctx, 0);
			}
		}

		if (next_thread != 0 && next_thread != (QWORD)PsGetCurrentThread())
		{
			AntiCheatUnlinkDetection(next_thread);
			AntiCheatAttachProcessDetection(target_game, next_thread);
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

	mouse_unhook();

	if (gThreadObject) {
		KeWaitForSingleObject(
			(PVOID)gThreadObject,
			Executive,
			KernelMode,
			FALSE,
			0
		);

		ObDereferenceObject(gThreadObject);

		ZwClose(gThreadHandle);
	}

	NtSleep(1000);
#if NMI_INTERRUPT == 1
	if (NmiCallbackHandle)
		KeDeregisterNmiCallback(NmiCallbackHandle);
#endif

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Anti-Cheat.sys is closed\n");
}

__declspec(dllimport) unsigned __int16 __fastcall KeCopyAffinityEx(__int64 a1, __int64 a2);
__declspec(dllimport) void __fastcall HalSendNMI(__int64 a1);
__declspec(dllimport) __int64 __fastcall KeRemoveProcessorAffinityEx(QWORD, QWORD);

void nmi_interurpt(void)
{
	char a0[0x100];

	QWORD KeActiveProcessors = (QWORD)KeQueryGroupAffinity;
	KeActiveProcessors = (QWORD)ResolveRelativeAddress((PVOID)KeActiveProcessors, 3, 7);

	QWORD prcb = __readgsqword(0x20);
	KeCopyAffinityEx((QWORD)a0, KeActiveProcessors);
	KeRemoveProcessorAffinityEx((QWORD)a0, *(DWORD*)(prcb + 0x24));
	HalSendNMI( (QWORD)a0 );
}

NTSTATUS system_thread(void)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Anti-Cheat.sys is launched\n");

	gThreadProcess    = (QWORD)PsGetCurrentProcess();

#if NMI_INTERRUPT == 1
	QWORD nmi_interrupts = 0;
	QWORD previous_ms = GetMilliSeconds();
#endif
	QWORD target_game = 0;

	while (gExitCalled == 0) {

		NtSleep(1);
		if (target_game == 0 || PsGetProcessExitProcessCalled((PEPROCESS)target_game)) {
			target_game = GetProcessByName(TARGET_PROCESS);
		}

		AntiCheat(target_game);
		//
		// This nmi interrupt is going to temporary stop all cores,
		// expect the one you currently executing.
		//

#if NMI_INTERRUPT == 1
		if (GetMilliSeconds() - previous_ms > NMI_INTERRUPT_INTERVAL)
		{
			//
			// we should probably check if there is active NMI interrupt
			// but then again, NMI interrupt handler should be verifying it for us.
			//
			__try {
				nmi_interurpt();
			} __except (1) {
			}

			nmi_interrupts++;
			previous_ms = GetMilliSeconds();
			if (nmi_interrupts > 5)
			{
				DWORD num = KeNumberProcessors - 1;
				num = num * 4;

				if (gTotalNmiCount < num)
				{
					DbgPrintEx(76, 0,
						"[+] Anti-Cheat.sys: NMI blocking detected!!!\n"
					);
				}

				nmi_interrupts = 0;
				gTotalNmiCount = 0;
			}
		}
#endif
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Anti-Cheat.sys thread is closed\n");

	return 0l;
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

	vmusbmouse.base = GetModuleHandle(L"vmusbmouse.sys", &vmusbmouse.size);
	QWORD ntoskrnl = GetModuleHandle(L"ntoskrnl.exe", 0);


#if NMI_INTERRUPT == 1
	QWORD KeBugCheckExPtr = (QWORD)KeBugCheckEx;
	KeBugCheckExPtr = KeBugCheckExPtr + 0x23;
	KeBugCheckExPtr = KeBugCheckExPtr + 0x03;
	gCtxOffset      = *(DWORD*)KeBugCheckExPtr;
#endif


	QWORD MmUnlockPreChargedPagedPool = GetProcAddressQ((QWORD)ntoskrnl, "MmUnlockPreChargedPagedPool");
	if (MmUnlockPreChargedPagedPool == 0)
		return STATUS_DRIVER_ENTRYPOINT_NOT_FOUND;


	*(QWORD*)&MiGetPteAddress = (QWORD)(*(int*)(MmUnlockPreChargedPagedPool + 8) + MmUnlockPreChargedPagedPool + 12);


	QWORD table = 0;
	if (ntoskrnl)
		table = FindPattern((QWORD)ntoskrnl, (BYTE*)"\x48\x83\xEC\x30\x48\x8B\x05\x00\x00\x00\x00\x4D\x8B\xD0", "xxxxxxx????xxx", 15);

	if (!table)
	{
		QWORD hal = GetModuleHandle(L"hal.dll", 0);
		if (hal)
			table = FindPattern((QWORD)hal, (BYTE*)"\x48\x83\xEC\x30\x48\x8B\x05\x00\x00\x00\x00\x4D\x8B\xD0", "xxxxxxx????xxx", 15);
	}

	if (table) {
		table = table + 0x04;
		table = (QWORD)ResolveRelativeAddress((PVOID)table, 3, 7);
		table = *(QWORD*)table;
		HalEfiEnabled = 1;
		for (int i = 0; i < HAL_EFI_COUNT; i++) {
			MM_COPY_ADDRESS address;
			address.VirtualAddress = (PVOID)(table + (i * 8));
			SIZE_T read;
			if (!NT_SUCCESS(MmCopyMemory(&HalEfiFunctions[i], address, 8, MM_COPY_MEMORY_VIRTUAL, &read)))
			{
				HalEfiEnabled = 0;
				break;
			}
		}
	}

	if (HalEfiEnabled && HalEfiFunctions[0] != 0)
	{

		for (int i = 0; i < HAL_EFI_COUNT; i++)
		{

			if (!ResolveHalEfiBase(HalEfiFunctions[i], &HalEfiImages[i].base, &HalEfiImages[i].size))
			{
				HalEfiEnabled = 0;
				break;
			}

			if (HalEfiFunctions[i] && *(unsigned short*)(HalEfiFunctions[i]) == 0x25ff)
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "EFI Runtime service (%d) is most likely manipulated by bytepatch: %llx\n",
					i, *(QWORD*)(HalEfiFunctions[i] + 0x6));
			}

			if (HalEfiEnabled == 0)
				continue;

			if (HalEfiFunctions[i] < HalEfiImages[i].base || HalEfiFunctions[i] > (HalEfiImages[i].base + HalEfiImages[i].size))
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "EFI Runtime service (%d) is not pointing at original Image: %llx\n", i, HalEfiFunctions[i]);
			}
		}
	}

	mouse_hook();

#if NMI_INTERRUPT == 1
	NmiCallbackHandle = KeRegisterNmiCallback(&NmiCallback, 0);
#endif

	CLIENT_ID thread_id;
	PsCreateSystemThread(&gThreadHandle, STANDARD_RIGHTS_ALL, NULL, NULL, &thread_id, (PKSTART_ROUTINE)system_thread, (PVOID)0);
	ObReferenceObjectByHandle(
		gThreadHandle,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		(PVOID*)&gThreadObject,
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
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


BOOL IsInValidRange(QWORD address)
{
	if (HalEfiEnabled)
	{
		for (int i = 0; i < 9; i++)
		{
			if (address >= HalEfiImages[i].base && address <= (QWORD)(HalEfiImages[i].base + HalEfiImages[i].size))
			{
				return 1;
			}
		}
	}

	{
		for (PLIST_ENTRY pListEntry = PsLoadedModuleList->Flink; pListEntry != PsLoadedModuleList; pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (pEntry->ImageBase == 0)
				continue;



			if (address >= (QWORD)pEntry->ImageBase && address <= (QWORD)((QWORD)pEntry->ImageBase + pEntry->SizeOfImage + 0x1000))
			{			
				return 1;
			}

		}
	}

	{
		PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)gDriverObject->DriverSection;
		for (PLIST_ENTRY pListEntry = ldr->InLoadOrderLinks.Flink; pListEntry != &ldr->InLoadOrderLinks; pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (pEntry->ImageBase == 0)
				continue;

			if (address >= (QWORD)pEntry->ImageBase && address <= (QWORD)((QWORD)pEntry->ImageBase + pEntry->SizeOfImage + 0x1000))
			{
				return 1;
			}

		}
	}


	return 0;
}

QWORD GetModuleHandle(PWCH module_name, QWORD* SizeOfImage)
{
	PLDR_DATA_TABLE_ENTRY ldr = (PLDR_DATA_TABLE_ENTRY)gDriverObject->DriverSection;
	for (PLIST_ENTRY pListEntry = ldr->InLoadOrderLinks.Flink; pListEntry != &ldr->InLoadOrderLinks; pListEntry = pListEntry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (pEntry->BaseImageName.Buffer && wcscmp(pEntry->BaseImageName.Buffer, module_name) == 0) {
			if (SizeOfImage) {
				*SizeOfImage = 0;
				*SizeOfImage = pEntry->SizeOfImage;
			}
			return (QWORD)pEntry->ImageBase;
		}

	}
	return 0;
}


// https://github.com/btbd/umap/blob/master/mapper/util.c#L117
BOOLEAN MemCopyWP(PVOID dest, PVOID src, ULONG length) {
	PMDL mdl = IoAllocateMdl(dest, length, FALSE, FALSE, NULL);
	if (!mdl) {
		return FALSE;
	}

	MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

	PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, 0, HighPagePriority);
	if (!mapped) {
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
		return FALSE;
	}

	memcpy(mapped, src, length);

	MmUnmapLockedPages(mapped, mdl);
	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	return TRUE;
}

#define JMP_SIZE 14
// https://github.com/btbd/umap/
VOID* TrampolineHook(VOID* dest, VOID* src, UINT8 original[JMP_SIZE]) {
	if (original) {
		MemCopyWP(original, src, JMP_SIZE);
	}

	unsigned char bytes[] = "\xFF\x25\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	*(QWORD*)(bytes + 6) = (QWORD)dest;

	MemCopyWP(src, bytes, JMP_SIZE);

	return src;
}

VOID TrampolineUnHook(VOID* src, UINT8 original[JMP_SIZE]) {
	MemCopyWP(src, original, JMP_SIZE);
}


unsigned char OriginalMouseClassService[JMP_SIZE];

NTSYSCALLAPI
NTSTATUS
ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID* Object
);

NTSYSCALLAPI
POBJECT_TYPE* IoDriverObjectType;

BOOL mouse_hook(void)
{

	_KeAcquireSpinLockAtDpcLevel = (QWORD)KeAcquireSpinLockAtDpcLevel;
	_KeReleaseSpinLockFromDpcLevel = (QWORD)KeReleaseSpinLockFromDpcLevel;
	_IofCompleteRequest = (QWORD)IofCompleteRequest;
	_IoReleaseRemoveLockEx = (QWORD)IoReleaseRemoveLockEx;

	// https://github.com/nbqofficial/norsefire
	if (gMouseObject.hook == 0) {

		UNICODE_STRING class_string;
		RtlInitUnicodeString(&class_string, L"\\Driver\\MouClass");


		PDRIVER_OBJECT class_driver_object = NULL;
		NTSTATUS status = ObReferenceObjectByName(&class_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&class_driver_object);
		if (!NT_SUCCESS(status)) {
			return 0;
		}

		UNICODE_STRING hid_string;
		RtlInitUnicodeString(&hid_string, L"\\Driver\\MouHID");


		PDRIVER_OBJECT hid_driver_object = NULL;

		status = ObReferenceObjectByName(&hid_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&hid_driver_object);
		if (!NT_SUCCESS(status))
		{
			if (class_driver_object) {
				ObfDereferenceObject(class_driver_object);
			}
			return 0;
		}

		gMouseObject.hid = (QWORD)hid_driver_object->DriverStart;
		gMouseObject.hid_length = (QWORD)hid_driver_object->DriverSize;

		PVOID class_driver_base = NULL;


		PDEVICE_OBJECT hid_device_object = hid_driver_object->DeviceObject;
		while (hid_device_object && !gMouseObject.service_callback)
		{
			PDEVICE_OBJECT class_device_object = class_driver_object->DeviceObject;
			while (class_device_object && !gMouseObject.service_callback)
			{
				if (!class_device_object->NextDevice && !gMouseObject.mouse_device)
				{
					gMouseObject.mouse_device = class_device_object;
				}

				PULONG_PTR device_extension = (PULONG_PTR)hid_device_object->DeviceExtension;
				ULONG_PTR device_ext_size = ((ULONG_PTR)hid_device_object->DeviceObjectExtension - (ULONG_PTR)hid_device_object->DeviceExtension) / 4;
				class_driver_base = class_driver_object->DriverStart;
				for (ULONG_PTR i = 0; i < device_ext_size; i++)
				{
					if (device_extension[i] == (ULONG_PTR)class_device_object && device_extension[i + 1] > (ULONG_PTR)class_driver_object)
					{
						gMouseObject.service_callback = (MouseClassServiceCallbackFn)(device_extension[i + 1]);

						break;
					}
				}
				class_device_object = class_device_object->NextDevice;
			}
			hid_device_object = hid_device_object->AttachedDevice;
		}

		if (!gMouseObject.mouse_device)
		{
			PDEVICE_OBJECT target_device_object = class_driver_object->DeviceObject;
			while (target_device_object)
			{
				if (!target_device_object->NextDevice)
				{
					gMouseObject.mouse_device = target_device_object;
					break;
				}
				target_device_object = target_device_object->NextDevice;
			}
		}

		ObfDereferenceObject(class_driver_object);
		ObfDereferenceObject(hid_driver_object);

		if (gMouseObject.mouse_device && gMouseObject.service_callback) {

			TrampolineHook((void*)MouseClassServiceCallback, (void*)gMouseObject.service_callback, OriginalMouseClassService);

			gMouseObject.hook = 1;

			return 1;

		}
	}
	else {
		return 1;
	}

	return 0;


}

void mouse_unhook(void)
{
	if (gMouseObject.hook) {
		TrampolineUnHook((void*)gMouseObject.service_callback, OriginalMouseClassService);
		gMouseObject.hook = 0;
	}
}

BOOL CopyStackThread(QWORD thread_address, CONTEXT* ctx);
BOOL GetThreadStack(QWORD thread, CONTEXT* thread_context)
{
	BOOL status = 0;

	if (thread == 0)
		return 0;

	status = CopyStackThread(thread, thread_context);

	/*
	
	there is rare cases, where thread has pending APC / or with bad timing goes to guarded region
	it would be better to do manually do APC, doing it with PsGetContextThread is not good,
	because it will then wait forever APC request to complete

	if (status == 0)
	{
		MISC_FLAGS* flags = (MISC_FLAGS*)(thread + 0x74);
		if (flags->ApcQueueable == 1 && *(SHORT*)(thread + 0x1e6) == 0 &&
			NT_SUCCESS(PsGetContextThread((PETHREAD)thread, thread_context, KernelMode)))
		{
			status = 1;
		}
		
	}
	*/

	return status;
}

#pragma warning (disable: 4214)
typedef union _pte
{
	ULONG64 value;
	struct
	{
		ULONG64 present : 1;          // Must be 1, region invalid if 0.
		ULONG64 ReadWrite : 1;        // If 0, writes not allowed.
		ULONG64 user_supervisor : 1;   // If 0, user-mode accesses not allowed.
		ULONG64 PageWriteThrough : 1; // Determines the memory type used to access the memory.
		ULONG64 page_cache : 1; // Determines the memory type used to access the memory.
		ULONG64 accessed : 1;         // If 0, this entry has not been used for translation.
		ULONG64 Dirty : 1;            // If 0, the memory backing this page has not been written to.
		ULONG64 PageAccessType : 1;   // Determines the memory type used to access the memory.
		ULONG64 Global : 1;           // If 1 and the PGE bit of CR4 is set, translations are global.
		ULONG64 Ignored2 : 3;
		ULONG64 pfn : 36; // The page frame number of the backing physical page.
		ULONG64 Reserved : 4;
		ULONG64 Ignored3 : 7;
		ULONG64 ProtectionKey : 4;  // If the PKE bit of CR4 is set, determines the protection key.
		ULONG64 nx : 1; // If 1, instruction fetches not allowed.
	};
} pte_t, * ppte;


#pragma warning (disable: 4996)

BOOL IsAddressValidQ(QWORD address)
{
	if ( (unsigned __int64)address < 0xFFFFF68000000000ui64 || (unsigned __int64)address > 0xFFFFF6FFFFFFFFFFui64 )
	{
		return 1;
	}
	return 0;
}

BOOL CopyStackThread(QWORD thread_address, CONTEXT* ctx)
{
	// portable, could be used standalone as well
	if (thread_address == 0)
		return 0;


	QWORD stack_base = *(QWORD*)(thread_address + 0x38);
	QWORD stack_limit = *(QWORD*)(thread_address + 0x30);
	QWORD kernel_stack = *(QWORD*)(thread_address + 0x58);
	QWORD stack_size = stack_base - kernel_stack;

	if (stack_size < 0x70)
	{
		return 0;
	}


	//
	// stack address is not valid
	//
	if (MmGetPhysicalAddress((PVOID)kernel_stack).QuadPart == 0)
	{
		return 0;
	}


	UCHAR stack_buffer[0x1000];
	memset(stack_buffer, 0, 0x1000);
	if (kernel_stack > stack_limit && kernel_stack < stack_base)
	{
		if (stack_size > sizeof(stack_buffer))
		{
			stack_size = sizeof(stack_buffer);
		}


		MM_COPY_ADDRESS src;
		src.VirtualAddress = (PVOID)kernel_stack;
		if (!NT_SUCCESS(MmCopyMemory((VOID*)stack_buffer, src, stack_size, MM_COPY_MEMORY_VIRTUAL, &stack_size)))
		{
			stack_size = 0;
		}
	}


	//
	// stack copy did fail
	//
	if (stack_size < 0x70)
	{
		return 0;
	}


	QWORD previous_address=0;
	ctx->Rip = 0;

	int stack_index = 0;
	for (int i = 0; i < sizeof(stack_buffer) / 8; i++)
	{
		QWORD address = ((QWORD*)(&stack_buffer[0]))[i];


		if (!IsAddressValidQ(address))
			continue;


		if (address < (QWORD)0xfffff00000000000)
		{
			if (PsGetThreadProcessId((PETHREAD)thread_address) == 0)
				continue;
		}

		if (address >= (QWORD)gDriverObject->DriverStart && address < (QWORD)((QWORD)gDriverObject->DriverStart
			+ gDriverObject->DriverSize
			))
			continue;
		__try {
		if (MmGetPhysicalAddress((PVOID)address).QuadPart != 0)
		{

			ppte pte = (ppte)MiGetPteAddress(address);
			if (pte == 0)
			{
				continue;
			}

			//
			// PTE is invalid
			//
			if (pte->present == 0)
			{
				continue;
			}

			//
			// page is not executable
			//
			if (pte->nx == 1)
			{
				continue;
			}

			//
			// Whenever the processor accesses a page, it automatically sets the A (Accessed) bit in the corresponding PTE = 1
			//
			if (pte->accessed == 0)
			{
				continue;
			}

			if (!IsInValidRange(address))
			{
				ctx->Rip = address;
				ctx->Rsp = (QWORD)kernel_stack + (i * sizeof(QWORD));
			}

			previous_address = address;
			stack_index = i;
		}
		} __except(1) {
			//
			// page fault exception
			//
		}
	}

	if (previous_address == 0)
	{
		return 0;
	}
	
	if (ctx->Rip == 0)
	{
		ctx->Rip = previous_address;
		ctx->Rsp = (QWORD)kernel_stack + (stack_index * sizeof(QWORD));
	}

	return 1;
}

BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{

	for (; *szMask; ++szMask, ++pData, ++bMask)
		if ((*szMask == 1 || *szMask == 'x') && *pData != *bMask)
			return 0;

	return (*szMask) == 0;
}

QWORD FindPatternEx(UINT64 dwAddress, QWORD dwLen, BYTE* bMask, char* szMask)
{

	if (dwLen <= 0)
		return 0;
	for (QWORD i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (QWORD)(dwAddress + i);

	return 0;
}

QWORD GetProcAddressQ(QWORD base, PCSTR name)
{
	QWORD a0;
	DWORD a1[4];


	a0 = base + *(USHORT*)(base + 0x3C);
	a0 = base + *(DWORD*)(a0 + 0x88);
	a1[0] = *(DWORD*)(a0 + 0x18);
	a1[1] = *(DWORD*)(a0 + 0x1C);
	a1[2] = *(DWORD*)(a0 + 0x20);
	a1[3] = *(DWORD*)(a0 + 0x24);
	while (a1[0]--) {

		a0 = base + *(DWORD*)(base + a1[2] + (a1[0] * 4));
		if (strcmp((PCSTR)a0, name) == 0) {
			return (base + *(DWORD*)(base + a1[1] + (*(USHORT*)(base + a1[3] + (a1[0] * 2)) * 4)));
		}

	}
	return 0;
}

#ifdef _KERNEL_MODE
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
	BYTE    Name[8];
	union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;
#endif

QWORD FindPattern(QWORD module, BYTE* bMask, CHAR* szMask, QWORD len)
{

	ULONG_PTR ret = 0;
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((BYTE*)pidh + pidh->e_lfanew);
	PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((BYTE*)pinh + sizeof(IMAGE_NT_HEADERS64));
	for (USHORT sec = 0; sec < pinh->FileHeader.NumberOfSections; sec++)
	{

		if ((pish[sec].Characteristics & 0x00000020))
		{
			QWORD address = FindPatternEx(pish[sec].VirtualAddress + (ULONG_PTR)(module), pish[sec].Misc.VirtualSize - len, bMask, szMask);

			if (address) {
				ret = address;
				break;
			}
		}

	}
	return ret;

}

PVOID ResolveRelativeAddress(
	_In_ PVOID Instruction,
	_In_ ULONG OffsetOffset,
	_In_ ULONG InstructionSize
)
{

	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}

BOOL ResolveHalEfiBase(QWORD address, QWORD* base, QWORD* size)
{
	BOOL result = 0;
	*base = 0;
	if (size)
		*size = 0;

	address = (QWORD)PAGE_ALIGN((QWORD)address);
	while (1)
	{
		address -= 0x1000;
		if (MmGetPhysicalAddress((PVOID)address).QuadPart == 0)
		{
			break;
		}

		if (*(unsigned short*)address == 0x5A4D)
		{
			IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)address;
			IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((char*)dos + dos->e_lfanew);
			if (nt->Signature != 0x00004550)
				continue;

			*base = address;
			if (size)
				*size = nt->OptionalHeader.SizeOfImage;

			result = 1;
			break;
		}
	}
	return result;
}

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

QWORD GetMilliSeconds()
{
#ifdef _KERNEL_MODE
	LARGE_INTEGER start_time;
	KeQueryTickCount(&start_time);
	QWORD start_time_in_msec = (QWORD)(start_time.QuadPart * KeQueryTimeIncrement() / 10000);

	return start_time_in_msec;
#else
	return system_current_time_millis();
#endif
}

THREAD_INFO_TABLE *get_stacklist_item(QWORD thread)
{
	for (int i = 0; i < g_thread_stack_list_count; i++)
	{
		if (thread == g_thread_stack_list[i].thread)
		{
			return &g_thread_stack_list[i];
		}
	}
	return 0;
}

void push_back_stacklist(QWORD thread, QWORD address)
{
	BOOL found = 0;
	for (int i = 0; i < g_thread_stack_list_count; i++)
	{
		if (g_thread_stack_list[i].thread == thread)
		{
			g_thread_stack_list[i].address = address;
			g_thread_stack_list[i].time = GetMilliSeconds();
			g_thread_stack_list[i].count++;
			found = 1;
		}
	}

	if (found == 0 && g_thread_stack_list_count != MAX_THREAD_COUNT)
	{
		g_thread_stack_list[g_thread_stack_list_count].thread = thread;
		g_thread_stack_list[g_thread_stack_list_count].address = address;
		g_thread_stack_list[g_thread_stack_list_count].time = GetMilliSeconds();
		g_thread_stack_list[g_thread_stack_list_count].count++;
		g_thread_stack_list_count++;
	}
}
