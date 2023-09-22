#include <ntifs.h>
#include <ntddmou.h>
#include <intrin.h>

//
// detecting MouseClassServiceCallback manipulation (Non HVCI systems).
// 
// e.g.
// https://github.com/nbqofficial/norsefire
// https://github.com/ekknod/MouseClassServiceCallbackTrick
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

namespace hooks
{
	BOOLEAN install(void);
	void    uninstall(void);

	namespace input
	{
		MODULE_INFO   vmusbmouse;
		MODULE_INFO   mouclass;
		MODULE_INFO   mouhid;
		QWORD         mouclass_routine;
		unsigned char original_bytes[14];
		QWORD         MouseClassServiceCallbackHook(PDEVICE_OBJECT DeviceObject, PMOUSE_INPUT_DATA InputDataStart, PMOUSE_INPUT_DATA InputDataEnd, PULONG InputDataConsumed);
	}
}

extern "C" VOID DriverUnload(
	_In_ struct _DRIVER_OBJECT* DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	hooks::uninstall();
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

			return 0;
		}
	}
	return MouseClassServiceCallback(DeviceObject, InputDataStart, InputDataEnd, InputDataConsumed);
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

QWORD get_mouse_callback_address(MODULE_INFO *mouclass, MODULE_INFO *mouhid)
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
	{
		mouclass->base = (QWORD)class_driver_object->DriverStart;
		mouclass->size = (QWORD)class_driver_object->DriverSize;
	}

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
	{
		mouhid->base = (QWORD)hid_driver_object->DriverStart;
		mouhid->size = (QWORD)hid_driver_object->DriverSize;
	}

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

	return 1;
}

void hooks::uninstall(void)
{
	//
	// uninstall mouse input hook
	//
	MemCopyWP((PVOID)input::mouclass_routine, &input::original_bytes, sizeof(input::original_bytes));
}

