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
		BOOLEAN        b_input_sent;
		BOOLEAN        vmware;
		unsigned char  original_bytes[14];

		NTSTATUS       (*oMouseClassRead)(PDEVICE_OBJECT device, PIRP irp);
		QWORD          MouseClassServiceCallbackHook(PDEVICE_OBJECT DeviceObject, PMOUSE_INPUT_DATA InputDataStart, PMOUSE_INPUT_DATA InputDataEnd, PULONG InputDataConsumed);
		NTSTATUS       MouseClassReadHook(PDEVICE_OBJECT device, PIRP irp);
	}
}

extern "C" VOID DriverUnload(
	_In_ struct _DRIVER_OBJECT* DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	hooks::uninstall();

	NtSleep(200);
	DbgPrintEx(77, 0, "[+] driver is successfully closed\n");
}

extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrintEx(77, 0, "[+] driver is successfully started\n");

	ntoskrnl = get_module_info(L"ntoskrnl.exe");
	if (!hooks::install())
	{
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

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
	//  *(UCHAR*)(__readgsqword(0x20) + 0x33BA) == 1 (DpcRoutineActive) 
	//  *(QWORD*)(__readgsqword(0x20) + 0x3320) == Wdf01000.sys:0x6ca0 (void __fastcall imp_VfWdfRequestGetParameters) (CurrentDpcRoutine)
	//
	
	//
	// call should be coming from ntoskrnl.exe IopfCompleteRequest
	//
	if (return_address < ntoskrnl.base || return_address > (ntoskrnl.base + ntoskrnl.size))
	{
		if ((QWORD)_ReturnAddress() < (QWORD)vmusbmouse.base || (QWORD)_ReturnAddress() >(QWORD)((QWORD)vmusbmouse.base + vmusbmouse.size))
		{
			QWORD thread = (QWORD)PsGetCurrentThread();
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%ld] Thread is manipulating mouse [%llx]\n",
				(DWORD)(QWORD)PsGetThreadId((PETHREAD)thread),
				thread
			);
			b_input_sent=0;
			return MouseClassServiceCallback(DeviceObject, InputDataStart, InputDataEnd, InputDataConsumed);
		}
	}
	b_input_sent=1;
	return MouseClassServiceCallback(DeviceObject, InputDataStart, InputDataEnd, InputDataConsumed);
}

//
// https:://github.com/everdox/hidinput
//
NTSTATUS hooks::input::MouseClassReadHook(PDEVICE_OBJECT device, PIRP irp)
{
	//
	// did MouseClassServiceCallback get called?
	//
	if (b_input_sent == 0 && vmware == 0)
	{
		__int64 v4 = *(QWORD *)((QWORD)irp + 184);
		QWORD   en = *(QWORD*)(*(QWORD *)(v4 + 48) + 32i64);
		QWORD   driver_init = (QWORD)mouclass->DriverInit;

		//
		// this code is approax same as original which is found from MouseClassRead
		//
		if (en >= driver_init && (en <= (driver_init + 0x1000)))
		{
			QWORD thread = (QWORD)PsGetCurrentThread();
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[%ld] Thread is manipulating mouse [%llx]\n",
				(DWORD)(QWORD)PsGetThreadId((PETHREAD)thread),
				thread
			);
		}
	}
	NTSTATUS status = hooks::input::oMouseClassRead(device,irp);
	b_input_sent = 0;
	return status;
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

	if (input::vmusbmouse.base != 0)
	{
		input::vmware = 1;
	}
	else
	{
		input::vmware = 0;
	}

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
}

/*
extern "C" __declspec(dllimport) LIST_ENTRY *PsLoadedModuleList;
PCWSTR GetCallerModuleName(QWORD address, QWORD *offset)
{
	PLDR_DATA_TABLE_ENTRY module_entry = CONTAINING_RECORD(PsLoadedModuleList, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	if (address >= (QWORD)module_entry->ImageBase && address <= (QWORD)((QWORD)module_entry->ImageBase + module_entry->SizeOfImage + 0x1000))
	{
			*offset = address - (QWORD)module_entry->ImageBase;
			if (module_entry->BaseImageName.Length == 0)
				return L"unknown_name";
			return (PWCH)module_entry->BaseImageName.Buffer;
	}

	for (PLIST_ENTRY pListEntry = PsLoadedModuleList->Flink; pListEntry != PsLoadedModuleList; pListEntry = pListEntry->Flink)
	{
		module_entry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (module_entry->ImageBase == 0)
			continue;

		if (address >= (QWORD)module_entry->ImageBase && address <= (QWORD)((QWORD)module_entry->ImageBase + module_entry->SizeOfImage + 0x1000))
		{
			*offset = address - (QWORD)module_entry->ImageBase;
			if (module_entry->BaseImageName.Length == 0)
				return L"unknown_name";
			return (PWCH)module_entry->BaseImageName.Buffer;
		}

	}
	return L"unknown";
}
*/
