#include <ntifs.h>
#include <ntddmou.h>
#include <intrin.h>

//
// detecting MouseClassServiceCallback manipulation (Non HVCI systems).
// 
// e.g.
// https://github.com/nbqofficial/norsefire
// https://github.com/ekknod/MouseClassServiceCallbackTrick
// https://github.com/ekknod/MouseClassServiceCallbackMeme
//
// legal chain should be something like this:
// HidpDistributeInterruptReport->IofCompleteRequest->IopfCompleteRequest->MouHid_ReadComplete->MouseClassServiceCallback->MouseClassRead->win32k.sys:rimInputApc
//

typedef ULONG_PTR QWORD;
typedef unsigned __int32 DWORD;
typedef unsigned __int16 WORD;
typedef unsigned __int8 BYTE;

#define LOG(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[driver.sys] " __VA_ARGS__)

typedef struct
{
	QWORD base,size;
} MODULE_INFO ;

MODULE_INFO ntoskrnl;

extern "C"
{
	//
	// mandatory global variables
	//
	QWORD _KeAcquireSpinLockAtDpcLevel;
	QWORD _KeReleaseSpinLockFromDpcLevel;
	QWORD _IofCompleteRequest;
	QWORD _IoReleaseRemoveLockEx;

	//
	// declarations
	//
	QWORD MouseClassServiceCallback(PDEVICE_OBJECT, PMOUSE_INPUT_DATA, PMOUSE_INPUT_DATA, PULONG);
}

MODULE_INFO get_module_info(PWCH module_name);
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

namespace hooks
{
	BOOLEAN install(void);
	void    uninstall(void);
	
	namespace input
	{
		MODULE_INFO    vmusbmouse;
		PDRIVER_OBJECT mouclass;
		PDRIVER_OBJECT mouhid;
		QWORD          mouclass_routine;
		BOOLEAN        input_sent;
		unsigned char  original_bytes[14];

		NTSTATUS       (*oMouseClassRead)(PDEVICE_OBJECT device, PIRP irp);
		QWORD          MouseClassServiceCallbackHook(PDEVICE_OBJECT DeviceObject, PMOUSE_INPUT_DATA InputDataStart, PMOUSE_INPUT_DATA InputDataEnd, PULONG InputDataConsumed);
		NTSTATUS       MouseClassReadHook(PDEVICE_OBJECT device, PIRP irp);
	}
	
	namespace exception
	{
		QWORD KdpDebugRoutineSelect;
		QWORD PoHiderInProgress;
		void (*oKdTrap)(void);
		void KdTrapHook();
	}

	namespace swap_ctx
	{
		UCHAR (*oHalClearLastBranchRecordStack)(void);
		UCHAR HalClearLastBranchRecordStackHook();
	}
}

extern "C" VOID DriverUnload(
	_In_ struct _DRIVER_OBJECT* DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	hooks::uninstall();

	NtSleep(200);
	LOG("Shutdown\n");
}

extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	ntoskrnl = get_module_info(L"ntoskrnl.exe");
	if (!hooks::install())
	{
		LOG("failed to install hooks\n");
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	LOG("Running\n");

	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}

QWORD hooks::input::MouseClassServiceCallbackHook(
	PDEVICE_OBJECT DeviceObject,
	PMOUSE_INPUT_DATA InputDataStart,
	PMOUSE_INPUT_DATA InputDataEnd,
	PULONG InputDataConsumed
)
{
	QWORD rsp = (QWORD)_AddressOfReturnAddress();

	rsp = rsp + 0x08;  // call MouseClassServiceCallback
	rsp = rsp + 0x08;  // push rbp
	rsp = rsp + 0x08;  // push rbx
	rsp = rsp + 0x08;  // push rsi
	rsp = rsp + 0x08;  // push rdi
	rsp = rsp + 0x08;  // push r12
	rsp = rsp + 0x08;  // push r13
	rsp = rsp + 0x08;  // push r14
	rsp = rsp + 0x08;  // push r15
	rsp = rsp + 0x58;  // sub  rsp,  58h

	QWORD return_address = *(QWORD*)(rsp);

	//
	// extra data
	//  *(UCHAR*)(__readgsqword(0x20) + 0x33BA) == 1 (DpcRoutineActive) 
	//  *(QWORD*)(__readgsqword(0x20) + 0x3320) == Wdf01000.sys:0x6ca0 (void __fastcall imp_VfWdfRequestGetParameters) (CurrentDpcRoutine)
	//
	
	//
	// call should be coming from ntoskrnl.exe IopfCompleteRequest
	//
	if (return_address >= ntoskrnl.base && return_address <= (ntoskrnl.base + ntoskrnl.size))
	{
		input_sent = 1;
	}
	else
	{
		input_sent = 0;
	}
	return MouseClassServiceCallback(DeviceObject, InputDataStart, InputDataEnd, InputDataConsumed);
}

//
// https:://github.com/everdox/hidinput
//
NTSTATUS hooks::input::MouseClassReadHook(PDEVICE_OBJECT device, PIRP irp)
{
	NTSTATUS status = hooks::input::oMouseClassRead(device,irp);
	if (status == 259)
	{
		//
		// did MouseClassServiceCallback get called?
		// only works for real systems. vmware is not supported.
		// 
		if (input_sent == 0 && input::vmusbmouse.base == 0)
		{
			LOG("manual mouse input call detected\n");
		}
		input_sent = 0;
	}
	return status;
}

//
// 24.09.2023 : added this as researching purposes. decided to keep it, since its fine code.
// maybe we can find some use for it later :P
//
extern "C" __declspec(dllimport) PCSTR PsGetProcessImageFileName(QWORD process);
void __fastcall hooks::exception::KdTrapHook(void)
{
	//
	// disable upcoming DPC call
	//
	*(BYTE*)(exception::PoHiderInProgress) = 1;


	QWORD KeBugCheckExPtr = (QWORD)KeBugCheckEx;
	KeBugCheckExPtr       = KeBugCheckExPtr + 0x23;
	KeBugCheckExPtr       = KeBugCheckExPtr + 0x03;
	DWORD ctx_offset      = *(DWORD*)KeBugCheckExPtr;
	struct  _CONTEXT *current_context = *(struct  _CONTEXT **)(__readgsqword(0x20) + ctx_offset);


	//
	// check if exception was caught
	//
	if (current_context == 0 || current_context->Rip == 0)
	{
		return oKdTrap();
	}


	//
	// skipping usermode exceptions
	//
	/*
	if (current_context->Rip <= 0x7FFFFFFFFFFF)
	{
		return oKdTrap();
	}
	*/


	QWORD thread  = __readgsqword(0x188);
	QWORD process = *(QWORD*)(thread + 0xB8);
	QWORD thread_process = *(QWORD*)(thread + 0x98 + 0x20);
		
	
	//
	// exception was caught
	//
	LOG("[%s:%s][%llX][%llX] exception was caught\n",
		PsGetProcessImageFileName(process),
		PsGetProcessImageFileName(thread_process),
		__readcr3(),
		current_context->Rip
		);

	return oKdTrap();
}

BOOLEAN is_unlinked_thread(QWORD process, QWORD thread)
{
	PLIST_ENTRY list_head = (PLIST_ENTRY)((QWORD)process + 0x30);
	PLIST_ENTRY list_entry = list_head;

	QWORD entry = (QWORD)((char*)list_entry - 0x2f8);
	if (entry == thread)
	{
		return 0;
	}

	while ((list_entry = list_entry->Flink) != 0 && list_entry != list_head)
	{
		entry = (QWORD)((char*)list_entry - 0x2f8);
		if (entry == thread)
		{
			return 0;
		}
	}
	return 1;
}

BOOLEAN unlink_thread_detection(QWORD thread)
{
	BOOLEAN hidden = 0;

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

	if (is_unlinked_thread(host_process, thread))
	{
		LOG("[%s][%ld] Thread is unlinked [%llx]\n",
			PsGetProcessImageFileName(host_process),
			(DWORD)(QWORD)PsGetThreadId((PETHREAD)thread),
			thread
		);
		hidden = 1;
	}

	return hidden;
}

UCHAR __fastcall hooks::swap_ctx::HalClearLastBranchRecordStackHook(void)
{
	QWORD current_thread  = __readgsqword(0x188);
	QWORD cr3 = __readcr3();

	if (unlink_thread_detection(current_thread))
	{
		LOG("[%lld] SwapContext: %llx, %llx\n", PsGetCurrentThreadId(), current_thread, cr3);
	}

	return swap_ctx::oHalClearLastBranchRecordStack();
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

extern "C" __declspec(dllimport) LIST_ENTRY *PsLoadedModuleList;
MODULE_INFO get_module_info(PWCH module_name)
{
	PLDR_DATA_TABLE_ENTRY module_entry = CONTAINING_RECORD(PsLoadedModuleList, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	if (!wcscmp(module_entry->BaseImageName.Buffer, module_name))
	{
		return {(QWORD)module_entry->ImageBase, module_entry->SizeOfImage};
	}

	for (PLIST_ENTRY list_entry = PsLoadedModuleList->Flink; list_entry != PsLoadedModuleList; list_entry = list_entry->Flink)
	{
		module_entry = CONTAINING_RECORD(list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (module_entry->ImageBase == 0)
			continue;

		if (module_entry->BaseImageName.Length == 0)
			continue;

		if (!wcscmp(module_entry->BaseImageName.Buffer, module_name))
		{
			return {(QWORD)module_entry->ImageBase, module_entry->SizeOfImage};
		}
	}
	return {};
}

extern "C" NTSYSCALLAPI
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

extern "C" NTSYSCALLAPI POBJECT_TYPE* IoDriverObjectType;

QWORD get_mouse_callback_address(PDRIVER_OBJECT *mouclass, PDRIVER_OBJECT *mouhid)
{
	//
	// https://github.com/nbqofficial/norsefire
	//
	
	UNICODE_STRING class_string;
	RtlInitUnicodeString(&class_string, L"\\Driver\\MouClass");


	PDRIVER_OBJECT class_driver_object = 0;
	NTSTATUS status = ObReferenceObjectByName(&class_string, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&class_driver_object);
	if (!NT_SUCCESS(status)) {
		return 0;
	}
	
	if (mouclass)
		*mouclass = class_driver_object;

	UNICODE_STRING hid_string;
	RtlInitUnicodeString(&hid_string, L"\\Driver\\MouHID");

	PDRIVER_OBJECT hid_driver_object = 0;
	status = ObReferenceObjectByName(&hid_string, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&hid_driver_object);
	if (!NT_SUCCESS(status))
	{
		ObfDereferenceObject(class_driver_object);
		return 0;
	}

	if (mouhid)
		*mouhid = hid_driver_object;

	QWORD result = 0;
	PDEVICE_OBJECT hid_device_object = hid_driver_object->DeviceObject;
	while (hid_device_object)
	{
		PDEVICE_OBJECT class_device_object = class_driver_object->DeviceObject;
		while (class_device_object)
		{
			PULONG_PTR device_extension = (PULONG_PTR)hid_device_object->DeviceExtension;
			ULONG_PTR device_ext_size = ((ULONG_PTR)hid_device_object->DeviceObjectExtension - (ULONG_PTR)hid_device_object->DeviceExtension) / 4;
			for (ULONG_PTR i = 0; i < device_ext_size; i++)
			{
				if (device_extension[i] == (ULONG_PTR)class_device_object && device_extension[i + 1] > (ULONG_PTR)class_driver_object)
				{
					result = (QWORD)(device_extension[i + 1]);
					goto E0;
				}
			}
			class_device_object = class_device_object->NextDevice;
		}
		hid_device_object = hid_device_object->AttachedDevice;
	}
E0:
	ObfDereferenceObject(class_driver_object);
	ObfDereferenceObject(hid_driver_object);
	return result;
}

BOOLEAN MemCopyWP(PVOID dest, PVOID src, ULONG length)
{
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

extern "C" NTSYSCALLAPI NTSTATUS HalPrivateDispatchTable(void);
QWORD FindPattern(QWORD base, unsigned char* pattern, unsigned char* mask);

BOOLEAN hooks::install(void)
{
	//
	// mouse hook
	//
	_KeAcquireSpinLockAtDpcLevel = (QWORD)KeAcquireSpinLockAtDpcLevel;
	_KeReleaseSpinLockFromDpcLevel = (QWORD)KeReleaseSpinLockFromDpcLevel;
	_IofCompleteRequest = (QWORD)IofCompleteRequest;
	_IoReleaseRemoveLockEx = (QWORD)IoReleaseRemoveLockEx;

	input::mouclass_routine = get_mouse_callback_address(&input::mouclass, &input::mouhid);
	if (input::mouclass_routine == 0)
		return 0;

	input::vmusbmouse = get_module_info(L"vmusbmouse.sys");

	unsigned char payload[] = {
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	*(QWORD*)(payload + 0x06) = (QWORD)input::MouseClassServiceCallbackHook;

	memcpy(input::original_bytes, (const void*)input::mouclass_routine, sizeof(input::original_bytes));
	if (!MemCopyWP((PVOID)input::mouclass_routine, &payload, sizeof(payload)))
	{
		return 0;
	}

	input::oMouseClassRead = input::mouclass->MajorFunction[IRP_MJ_READ];
	input::mouclass->MajorFunction[IRP_MJ_READ] = input::MouseClassReadHook;


	//
	// global exception hook
	//
	exception::KdpDebugRoutineSelect = FindPattern(ntoskrnl.base, (BYTE*)"\x83\x3D\x00\x00\x00\x00\x00\x8A\x44", (BYTE*)"xx????xxx");
	if (exception::KdpDebugRoutineSelect == 0)
	{
	E0:
		MemCopyWP((PVOID)input::mouclass_routine, &input::original_bytes, sizeof(input::original_bytes));
		input::mouclass->MajorFunction[IRP_MJ_READ] = input::oMouseClassRead;
		return 0;
	}

	exception::PoHiderInProgress = FindPattern(ntoskrnl.base, (BYTE*)"\xC6\x05\x00\x00\x00\x00\x01\x33\xC9\xE8", (BYTE*)"xx????xxxx");
	if (exception::PoHiderInProgress == 0)
	{
		goto E0;
	}

	exception::KdpDebugRoutineSelect = (exception::KdpDebugRoutineSelect + 7) + *(INT32*)(exception::KdpDebugRoutineSelect + 2);
	exception::PoHiderInProgress = (exception::PoHiderInProgress + 7) + *(INT32*)(exception::PoHiderInProgress + 2);
	*(DWORD*)(exception::KdpDebugRoutineSelect) = 1;


	//
	// HalPrivateDispatchTable + 0x328 = xHalTimerWatchdogStop/xHalTimerWatchdogStart
	//
	*(QWORD*)&exception::oKdTrap = *(QWORD*)((QWORD)HalPrivateDispatchTable + 0x328);
	*(QWORD*)((QWORD)HalPrivateDispatchTable + 0x328) = (QWORD)exception::KdTrapHook;


	//
	// HalPrivateDispatchTable + 0x400 = HalClearLastBranchRecordStack 
	//
	*(QWORD*)&swap_ctx::oHalClearLastBranchRecordStack = *(QWORD*)((QWORD)HalPrivateDispatchTable + 0x400);
	*(QWORD*)((QWORD)HalPrivateDispatchTable + 0x400) = (QWORD)swap_ctx::HalClearLastBranchRecordStackHook;


	//
	// set KiCpuTracingFlags 2
	//
	QWORD KiCpuTracingFlags = (QWORD)KeBugCheckEx;
	while (*(unsigned short*)KiCpuTracingFlags != 0xE800) KiCpuTracingFlags++; KiCpuTracingFlags+=2;
	while (*(unsigned short*)KiCpuTracingFlags != 0xE800) KiCpuTracingFlags++; KiCpuTracingFlags++;
	KiCpuTracingFlags = (KiCpuTracingFlags + 5) + *(int*)(KiCpuTracingFlags + 1);
	while (*(unsigned short*)KiCpuTracingFlags != 0x05F7) KiCpuTracingFlags++;
	KiCpuTracingFlags = (KiCpuTracingFlags + 10) + *(int*)(KiCpuTracingFlags + 2);
	*(BYTE*)(KiCpuTracingFlags) = 2;

	return 1;
}

void hooks::uninstall(void)
{
	//
	// uninstall mouse input hook
	//
	while (!MemCopyWP((PVOID)input::mouclass_routine, &input::original_bytes, sizeof(input::original_bytes)))
		;

	input::mouclass->MajorFunction[IRP_MJ_READ] = input::oMouseClassRead;

	//
	// uninstall exception hook
	//
	*(QWORD*)((QWORD)HalPrivateDispatchTable + 0x328) = (QWORD)exception::oKdTrap;
	*(DWORD*)(exception::KdpDebugRoutineSelect) = 0;
	*(BYTE*)(exception::PoHiderInProgress) = 0;


	//
	// uninstall swap context hook
	//
	*(QWORD*)((QWORD)HalPrivateDispatchTable + 0x400) = *(QWORD*)&swap_ctx::oHalClearLastBranchRecordStack;


	//
	// set KiCpuTracingFlags 0
	//
	QWORD KiCpuTracingFlags = (QWORD)KeBugCheckEx;
	while (*(unsigned short*)KiCpuTracingFlags != 0xE800) KiCpuTracingFlags++; KiCpuTracingFlags+=2;
	while (*(unsigned short*)KiCpuTracingFlags != 0xE800) KiCpuTracingFlags++; KiCpuTracingFlags++;
	KiCpuTracingFlags = (KiCpuTracingFlags + 5) + *(int*)(KiCpuTracingFlags + 1);
	while (*(unsigned short*)KiCpuTracingFlags != 0x05F7) KiCpuTracingFlags++;
	KiCpuTracingFlags = (KiCpuTracingFlags + 10) + *(int*)(KiCpuTracingFlags + 2);
	*(BYTE*)(KiCpuTracingFlags) = 0;
}

static int CheckMask(unsigned char* base, unsigned char* pattern, unsigned char* mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
		if (*mask == 'x' && *base != *pattern)
			return 0;
	return 1;
}

void *FindPatternEx(unsigned char* base, QWORD size, unsigned char* pattern, unsigned char* mask)
{
	size -= strlen((const char *)mask);
	for (QWORD i = 0; i <= size; ++i) {
		void* addr = &base[i];
		if (CheckMask((unsigned char *)addr, pattern, mask))
			return addr;
	}
	return 0;
}

QWORD FindPattern(QWORD base, unsigned char* pattern, unsigned char* mask)
{
	if (base == 0)
	{
		return 0;
	}

	QWORD nt_header = (QWORD)*(DWORD*)(base + 0x03C) + base;
	if (nt_header == base)
	{
		return 0;
	}

	WORD machine = *(WORD*)(nt_header + 0x4);
	QWORD section_header = machine == 0x8664 ?
		nt_header + 0x0108 :
		nt_header + 0x00F8;

	for (WORD i = 0; i < *(WORD*)(nt_header + 0x06); i++) {
		QWORD section = section_header + ((QWORD)i * 40);
		DWORD section_characteristics = *(DWORD*)(section + 0x24);

		if (section_characteristics & 0x00000020 && !(section_characteristics & 0x02000000))
		{
			QWORD virtual_address = base + (QWORD)*(DWORD*)(section + 0x0C);
			DWORD virtual_size = *(DWORD*)(section + 0x08);

			QWORD addr = (QWORD)FindPatternEx( (unsigned char*)virtual_address, virtual_size, pattern, mask);
			if (addr)
			{
				return addr;
			}
		}
	}
	return 0;
}

