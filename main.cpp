#include <ntifs.h>
#include <ntddmou.h>
#include <kbdmou.h>
#include <intrin.h>
#include "img.h"

//
// features:
// - exception hook
// - mouse hook
// - syscall hook (https://github.com/everdox/InfinityHook)
// tested Win11 22H3 + Win10 22H2 HVCI/Core Isolation enabled
//

#define POOLTAG (DWORD)'ACEC'

#define HVCI 1

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
MODULE_INFO vmusbmouse;

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

	namespace efi
	{
		QWORD (*oGetVariable)(char16_t *VariableName, GUID* VendorGuid, DWORD* Attributes, QWORD* DataSize, VOID* Data);
		QWORD (*oSetVariable)(char16_t *VariableName, GUID* VendorGuid, DWORD Attributes, QWORD DataSize, VOID* Data);
	}

	namespace syscall
	{
		QWORD SystemCallEntryPage;
		void __fastcall SyscallStub(unsigned int SyscallIndex, void **SyscallFunction);
		QWORD (*oKeQueryPerformanceCounter)(QWORD rcx);
		QWORD KeQueryPerformanceCounterHook(QWORD rcx);
	}
	
	namespace input
	{
		PDRIVER_OBJECT    mouclass;
		PDRIVER_OBJECT    mouhid;
		QWORD             mouclass_routine;

		MOUSE_INPUT_DATA  mouse_data;
		PMOUSE_INPUT_DATA mouse_irp = 0;

		NTSTATUS          (*rimInputApc)(void *a1, void *a2, void *a3, void *a4, void *a5);
		NTSTATUS          (*oMouseClassRead)(PDEVICE_OBJECT device, PIRP irp);
		NTSTATUS          (*oMouseAddDevice)(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject);

		QWORD             MouseClassServiceCallbackHook(PDEVICE_OBJECT DeviceObject, PMOUSE_INPUT_DATA InputDataStart, PMOUSE_INPUT_DATA InputDataEnd, PULONG InputDataConsumed);
		NTSTATUS          MouseApc(void* a1, void* a2, void* a3, void* a4, void* a5);
		NTSTATUS          MouseClassReadHook(PDEVICE_OBJECT device, PIRP irp);
		NTSTATUS          MouseAddDeviceHook(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT PhysicalDeviceObject);
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

enum class TRACE_OPERATION
{
	TRACE_START,
	TRACE_SYSCALL,
	TRACE_END
};
NTSTATUS ApplyTraceSettings(_In_ TRACE_OPERATION Operation);
QWORD FindPattern(QWORD base, unsigned char* pattern, unsigned char* mask);


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
	UNREFERENCED_PARAMETER(DriverObject);
		
	ntoskrnl = get_module_info(L"ntoskrnl.exe");
	vmusbmouse = get_module_info(L"vmusbmouse.sys");
	if (!hooks::install())
	{
		LOG("failed to install hooks\n");
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	LOG("Running\n");

	//
	// allow driver unload only with vmware
	//
	if (vmusbmouse.base != 0)
	{
		DriverObject->DriverUnload = DriverUnload;
	}
	return STATUS_SUCCESS;
}

NTSTATUS DetourNtCreateFile(
	_Out_ PHANDLE FileHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize,
	_In_ ULONG FileAttributes,
	_In_ ULONG ShareAccess,
	_In_ ULONG CreateDisposition,
	_In_ ULONG CreateOptions,
	_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
	_In_ ULONG EaLength)
{
	//
	// We're going to filter for our "magic" file name.
	//
	if (ObjectAttributes &&
		ObjectAttributes->ObjectName && 
		ObjectAttributes->ObjectName->Buffer)
	{
		//
		// Unicode strings aren't guaranteed to be NULL terminated so
		// we allocate a copy that is.
		//
		PWCHAR ObjectName = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, ObjectAttributes->ObjectName->Length + sizeof(wchar_t), POOLTAG);
		if (ObjectName)
		{
			memset(ObjectName, 0, ObjectAttributes->ObjectName->Length + sizeof(wchar_t));
			memcpy(ObjectName, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length);
		
			//
			// Does it contain our special file name?
			//
			if (wcsstr(ObjectName, L"ifh--"))
			{
				LOG("Denying access to file: %wZ.\n", ObjectAttributes->ObjectName);

				ExFreePoolWithTag(ObjectName, POOLTAG);

				//
				// The demo denies access to said file.
				//
				return STATUS_ACCESS_DENIED;
			}

			ExFreePoolWithTag(ObjectName, POOLTAG);
		}
	}

	//
	// We're uninterested, call the original.
	//
	return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

void __fastcall hooks::syscall::SyscallStub(unsigned int SyscallIndex, void **SyscallFunction)
{
	UNREFERENCED_PARAMETER(SyscallIndex);
	UNREFERENCED_PARAMETER(SyscallFunction);

	if (*SyscallFunction == (void*)NtCreateFile)
	{
		*SyscallFunction = DetourNtCreateFile;
	}

	//
	// to-do / would like to try at some point -->:
	//
	// if (*SyscallFunction == (void*)NtQuerySystemEnvironmentValueEx)
	//	*SyscallFunction = DetourNtQuerySystemEnvironmentValueEx;
	// 
	// DetourNtQuerySystemEnvironmentValueEx:
	//	$status = cpu::emulator(efi::oGetVariable, VariableName, VendorGuid, Attributes, DataSize, Data);
	//
}

QWORD hooks::syscall::KeQueryPerformanceCounterHook(QWORD rcx)
{
	if (ExGetPreviousMode() == KernelMode)
	{
		return oKeQueryPerformanceCounter(rcx);
	}

	QWORD current_thread = (QWORD)PsGetCurrentThread();
	DWORD syscall_index = *(DWORD*)(current_thread + 0x80);
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return oKeQueryPerformanceCounter(rcx);
	}

	PVOID* StackMax = (PVOID*)__readgsqword(0x1A8);
	PVOID* StackFrame = (PVOID*)_AddressOfReturnAddress();
	for (PVOID* StackCurrent = StackMax;
		StackCurrent > StackFrame;
		--StackCurrent)
	{
		PULONG AsUlong = (PULONG)StackCurrent;
		if (*AsUlong != ((ULONG)0x501802))
		{
			continue;
		}
		// 
		// If the first magic is set, check for the second magic.
		//
		--StackCurrent;
		PUSHORT AsShort = (PUSHORT)StackCurrent;
		if (*AsShort != ((USHORT)0xF33))
		{
			continue;
		}

		//
		// Now we reverse the direction of the stack walk.
		//
		int index = 0;
		for (;
			StackCurrent < StackMax;
			++StackCurrent)
		{
			PULONGLONG AsUlonglong = (PULONGLONG)StackCurrent;
			index++;
			if (index > 8)
			{
				break;
			}
			if (!(PAGE_ALIGN(*AsUlonglong) >= (PVOID)syscall::SystemCallEntryPage &&
				PAGE_ALIGN(*AsUlonglong) < (PVOID)((uintptr_t)syscall::SystemCallEntryPage + (PAGE_SIZE * 2))))
			{
				continue;
			}
			void** syscall = &StackCurrent[9];
			SyscallStub(syscall_index, syscall);
			break;
		}
		break;
	}
	return oKeQueryPerformanceCounter(rcx);
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
		mouse_data = *InputDataStart;
	}
	else
	{
		memset(&mouse_data, 0, sizeof(mouse_data));
	}
	//
	// HidpDistributeInterruptReport->IofCompleteRequest->IopfCompleteRequest->MouHid_ReadComplete->MouseClassServiceCallback->MouseClassRead->win32k.sys:rimInputApc
	//
	return ((QWORD(*)(PDEVICE_OBJECT, PMOUSE_INPUT_DATA, PMOUSE_INPUT_DATA, PULONG))(mouclass_routine))(
		DeviceObject,
		InputDataStart,
		InputDataEnd,
		InputDataConsumed
		);
}

//
// https:://github.com/everdox/hidinput
//
NTSTATUS hooks::input::MouseApc(void* a1, void* a2, void* a3, void* a4, void* a5)
{
	for (int i = sizeof(MOUSE_INPUT_DATA); i--;)
	{
		if (((unsigned char*)mouse_irp)[i] != ((unsigned char*)&mouse_data)[i])
		{
			DbgPrintEx(77, 0, "invalid mouse packet detected\n");
			break;
		}
	}
	return rimInputApc(a1, a2, a3, a4, a5);
}

//
// https:://github.com/everdox/hidinput
//
NTSTATUS hooks::input::MouseClassReadHook(PDEVICE_OBJECT device, PIRP irp)
{
	//
	// do not allow mouse hook with vmware
	//
	if (vmusbmouse.base == 0)
	{
		QWORD *routine;
		routine=(QWORD*)irp;
		routine+=0xb;
		if (rimInputApc == 0)
		{
			*(QWORD*)&rimInputApc = *routine;
		}
		*routine=(ULONGLONG)MouseApc;
		mouse_irp = (struct _MOUSE_INPUT_DATA*)irp->UserBuffer;
	}
	return hooks::input::oMouseClassRead(device,irp);
}

void update_mouse_devices(QWORD callback, QWORD original_callback, PDRIVER_OBJECT mouclass, PDRIVER_OBJECT mouhid);
NTSTATUS hooks::input::MouseAddDeviceHook(IN PDRIVER_OBJECT DriverObject, IN PDEVICE_OBJECT PhysicalDeviceObject)
{
	NTSTATUS status = oMouseAddDevice(DriverObject, PhysicalDeviceObject);
	if (status == 0)
	{
		update_mouse_devices((QWORD)mouclass_routine, (QWORD)MouseClassServiceCallbackHook, mouclass, mouhid);
	}
	return status;
}

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

	/*
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
		);*/

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

extern "C" __declspec(dllimport) LIST_ENTRY *PsLoadedModuleList;
PCWSTR GetCallerModuleName(QWORD address, QWORD *offset)
{
	PLDR_DATA_TABLE_ENTRY module_entry = CONTAINING_RECORD(PsLoadedModuleList, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	if (address >= (QWORD)module_entry->ImageBase && address <= (QWORD)((QWORD)module_entry->ImageBase + module_entry->SizeOfImage + 0x1000))
	{
		if (offset)
			*offset = address - (QWORD)module_entry->ImageBase;
		if (module_entry->BaseImageName.Length == 0)
			return L"unknown";
		return (PWCH)module_entry->BaseImageName.Buffer;
	}

	for (PLIST_ENTRY pListEntry = PsLoadedModuleList->Flink; pListEntry != PsLoadedModuleList; pListEntry = pListEntry->Flink)
	{
		module_entry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (module_entry->ImageBase == 0)
			continue;

		if (address >= (QWORD)module_entry->ImageBase && address <= (QWORD)((QWORD)module_entry->ImageBase + module_entry->SizeOfImage + 0x1000))
		{
			if (offset)
				*offset = address - (QWORD)module_entry->ImageBase;
			if (module_entry->BaseImageName.Length == 0)
				return L"unknown";
			return (PWCH)module_entry->BaseImageName.Buffer;
		}

	}
	return L"unknown";
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

void update_mouse_devices(QWORD current_callback, QWORD callback, PDRIVER_OBJECT mouclass, PDRIVER_OBJECT mouhid)
{
	PDEVICE_OBJECT hid_device_object = mouhid->DeviceObject;
	while (hid_device_object)
	{
		PDEVICE_OBJECT class_device_object = mouclass->DeviceObject;
		while (class_device_object)
		{
			PULONG_PTR device_extension = (PULONG_PTR)hid_device_object->DeviceExtension;
			ULONG_PTR device_ext_size =
				((ULONG_PTR)hid_device_object->DeviceObjectExtension - (ULONG_PTR)hid_device_object->DeviceExtension) / 4;

			for (ULONG_PTR i = 0; i < device_ext_size; i++)
			{
				if (device_extension[i] == current_callback)
				{
					device_extension[i] = callback;
				}
			}
			class_device_object = class_device_object->NextDevice;
		}
		hid_device_object = hid_device_object->AttachedDevice;
	}
}

extern "C" NTSYSCALLAPI NTSTATUS HalPrivateDispatchTable(void);
extern "C" NTSYSCALLAPI NTSTATUS HalEnumerateEnvironmentVariablesEx(void);

extern "C" NTSYSCALLAPI NTSTATUS 
ZwSetSystemInformation (
    ULONG SystemInformationClass, 
    PVOID SystemInformation, 
    ULONG SystemInformationLength);

extern "C" NTSYSCALLAPI NTSTATUS
ZwQuerySystemInformation(
    ULONG                    SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
);

BOOLEAN hooks::install(void)
{
	//
	// syscall hook
	//
	if (!NT_SUCCESS(ApplyTraceSettings(TRACE_OPERATION::TRACE_SYSCALL)))
	{
		if (!NT_SUCCESS(ApplyTraceSettings(TRACE_OPERATION::TRACE_START)))
		{
			return 0;
		}
		ApplyTraceSettings(TRACE_OPERATION::TRACE_SYSCALL);
	}


	QWORD temp = (QWORD)KeQueryPerformanceCounter + 0x05;
	while (*(WORD*)temp != 0x8948) temp++;
	temp = temp + 0x08;
	temp = (temp + 7) + *(int*)(temp + 3);
	temp = *(QWORD*)temp;


	*(QWORD*)&syscall::oKeQueryPerformanceCounter = *(QWORD*)(temp + 0x70);
	*(QWORD*)(temp + 0x70) = (QWORD)syscall::KeQueryPerformanceCounterHook;
	syscall::SystemCallEntryPage = (QWORD)ImgGetSyscallEntry((PVOID)ntoskrnl.base);


	//
	// mouse hook
	//
	input::mouclass_routine = get_mouse_callback_address(&input::mouclass, &input::mouhid);
	if (input::mouclass_routine == 0)
		return 0;

	update_mouse_devices(input::mouclass_routine, (QWORD)input::MouseClassServiceCallbackHook, input::mouclass, input::mouhid);

	
	input::oMouseClassRead = input::mouclass->MajorFunction[IRP_MJ_READ];
	input::mouclass->MajorFunction[IRP_MJ_READ] = input::MouseClassReadHook;

	input::oMouseAddDevice = input::mouclass->DriverExtension->AddDevice;
	input::mouclass->DriverExtension->AddDevice = input::MouseAddDeviceHook;


	//
	// global exception hook
	//
	exception::KdpDebugRoutineSelect = FindPattern(ntoskrnl.base, (BYTE*)"\x83\x3D\x00\x00\x00\x00\x00\x8A\x44", (BYTE*)"xx????xxx");
	if (exception::KdpDebugRoutineSelect == 0)
	{
	E0:
		update_mouse_devices((QWORD)input::MouseClassServiceCallbackHook, input::mouclass_routine, input::mouclass, input::mouhid);
		input::mouclass->MajorFunction[IRP_MJ_READ] = input::oMouseClassRead;
		input::mouclass->DriverExtension->AddDevice = input::oMouseAddDevice;
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


	QWORD HalEfiRuntimeServicesBlock = (QWORD)HalEnumerateEnvironmentVariablesEx + 0xC;

	HalEfiRuntimeServicesBlock =
		*(INT*)(HalEfiRuntimeServicesBlock + 1) + HalEfiRuntimeServicesBlock + 5;

	HalEfiRuntimeServicesBlock = HalEfiRuntimeServicesBlock + 0x69;

	HalEfiRuntimeServicesBlock =
		*(INT*)(HalEfiRuntimeServicesBlock + 3) + HalEfiRuntimeServicesBlock + 7;

	HalEfiRuntimeServicesBlock = *(QWORD*)(HalEfiRuntimeServicesBlock);

	*(QWORD*)&efi::oGetVariable = *(QWORD*)(HalEfiRuntimeServicesBlock + 0x18);
	*(QWORD*)&efi::oSetVariable = *(QWORD*)(HalEfiRuntimeServicesBlock + 0x28);

	return 1;
}

void hooks::uninstall(void)
{
	//
	// unhook syscalls
	//
	ApplyTraceSettings(TRACE_OPERATION::TRACE_END);
	QWORD temp = (QWORD)KeQueryPerformanceCounter + 0x05;
	while (*(WORD*)temp != 0x8948) temp++;
	temp = temp + 0x08;
	temp = (temp + 7) + *(int*)(temp + 3);
	temp = *(QWORD*)temp;
	*(QWORD*)(temp + 0x70) = (QWORD)syscall::oKeQueryPerformanceCounter;


	//
	// unhook mouse
	//
	update_mouse_devices((QWORD)input::MouseClassServiceCallbackHook, input::mouclass_routine, input::mouclass, input::mouhid);

	input::mouclass->MajorFunction[IRP_MJ_READ] = input::oMouseClassRead;
	input::mouclass->DriverExtension->AddDevice = input::oMouseAddDevice;

	//
	// unhook exceptions
	//
	*(QWORD*)((QWORD)HalPrivateDispatchTable + 0x328) = (QWORD)exception::oKdTrap;
	*(DWORD*)(exception::KdpDebugRoutineSelect) = 0;
	*(BYTE*)(exception::PoHiderInProgress) = 0;


	//
	// unhook SwapContext
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

EXTERN_C
NTSYSCALLAPI 
NTSTATUS
NTAPI
ZwTraceControl (
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	 _Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
);
#define EVENT_TRACE_BUFFERING_MODE  0x00000400  // Buffering mode only
#define EtwpStartTrace		    1
#define EtwpStopTrace		    2
#define EtwpQueryTrace		    3
#define EtwpUpdateTrace		    4
#define EtwpFlushTrace		    5
#define EVENT_TRACE_FLAG_SYSTEMCALL 0x00000080  // system calls
#define WNODE_FLAG_TRACED_GUID      0x00020000  // denotes a trace

#pragma warning (disable: 4201)
typedef struct _WNODE_HEADER
{
	ULONG BufferSize;        // Size of entire buffer inclusive of this ULONG
	ULONG ProviderId;    // Provider Id of driver returning this buffer
	union
	{
		ULONG64 HistoricalContext;  // Logger use
		struct
		{
			ULONG Version;           // Reserved
			ULONG Linkage;           // Linkage field reserved for WMI
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	union
	{
		ULONG CountLost;         // Reserved
		HANDLE KernelHandle;     // Kernel handle for data block
		LARGE_INTEGER TimeStamp; // Timestamp as returned in units of 100ns
								 // since 1/1/1601
	} DUMMYUNIONNAME2;
	GUID Guid;                  // Guid for data block returned with results
	ULONG ClientContext;
	ULONG Flags;             // Flags, see below
} WNODE_HEADER, *PWNODE_HEADER;

typedef struct _EVENT_TRACE_PROPERTIES {
	WNODE_HEADER	Wnode;
	ULONG			BufferSize;
	ULONG			MinimumBuffers;
	ULONG			MaximumBuffers;
	ULONG			MaximumFileSize;
	ULONG			LogFileMode;
	ULONG			FlushTimer;
	ULONG			EnableFlags;
	LONG			AgeLimit;
	ULONG			NumberOfBuffers;
	ULONG			FreeBuffers;
	ULONG			EventsLost;
	ULONG			BuffersWritten;
	ULONG			LogBuffersLost;
	ULONG			RealTimeBuffersLost;
	HANDLE			LoggerThreadId;
	ULONG			LogFileNameOffset;
	ULONG			LoggerNameOffset;
} EVENT_TRACE_PROPERTIES, *PEVENT_TRACE_PROPERTIES;

typedef struct _CKCL_TRACE_PROPERIES: EVENT_TRACE_PROPERTIES
{
	ULONG64				Unknown[3];
	UNICODE_STRING			ProviderName;
} CKCL_TRACE_PROPERTIES, *PCKCL_TRACE_PROPERTIES;

const GUID session_guid = { 0x9E814AAD, 0x3204, 0x11D2, { 0x9A, 0x82, 0x0, 0x60, 0x8, 0xA8, 0x69, 0x39 }  };

//
// https://github.com/everdox/InfinityHook / https://revers.engineering/fun-with-pg-compliant-hook/
//
NTSTATUS ApplyTraceSettings(_In_ TRACE_OPERATION Operation)
{
	PCKCL_TRACE_PROPERTIES Property = (PCKCL_TRACE_PROPERTIES)ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, POOLTAG);
	if (!Property)
	{
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	memset(Property, 0, PAGE_SIZE);

	Property->Wnode.BufferSize = PAGE_SIZE;
	Property->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	Property->ProviderName = RTL_CONSTANT_STRING(L"NT Kernel Logger");
	Property->Wnode.Guid = session_guid;
	Property->Wnode.ClientContext = 1;
	Property->BufferSize = sizeof(ULONG);
	Property->MinimumBuffers = Property->MaximumBuffers = 2;
	Property->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

	NTSTATUS Status = STATUS_ACCESS_DENIED;
	ULONG ReturnLength = 0;

	switch (Operation)
	{
		case TRACE_OPERATION::TRACE_START:
		{
			Status = ZwTraceControl(EtwpStartTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
			break;
		}
		case TRACE_OPERATION::TRACE_END:
		{
			Status = ZwTraceControl(EtwpStopTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
			break;
		}
		case TRACE_OPERATION::TRACE_SYSCALL:
		{
			//
			// Add more flags here to trap on more events!
			//
			Property->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;

			Status = ZwTraceControl(EtwpUpdateTrace, Property, PAGE_SIZE, Property, PAGE_SIZE, &ReturnLength);
			break;
		}
	}

	ExFreePoolWithTag(Property, POOLTAG);

	return Status;
}

