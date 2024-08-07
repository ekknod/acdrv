#include <ntifs.h>
#include <ntddmou.h>
#include <kbdmou.h>
#include <intrin.h>
#include "img.h"

extern "C"
{
	int _fltused;
}

//
// features:
// - exception hook
// - mouse hook
// - syscall hook (https://github.com/everdox/InfinityHook)
// - SwapContext hook
// tested Win11 22H3 + Win10 22H2 HVCI/Core Isolation enabled
//

#define POOLTAG (DWORD)'ACEC'

typedef ULONG_PTR QWORD;
typedef unsigned __int32 DWORD;
typedef unsigned __int16 WORD;
typedef unsigned __int8 BYTE;

#define LOG(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[driver.sys] " __VA_ARGS__)

typedef struct
{
	QWORD base, size;
} MODULE_INFO;

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

namespace globals
{
	MODULE_INFO ntoskrnl;
	MODULE_INFO vmusbmouse;
	DWORD       exit = 0;
}

namespace hooks
{
	BOOLEAN install(void);
	void    uninstall(void);

	namespace efi
	{
		QWORD(*oGetVariable)(PCWCH VariableName, GUID* VendorGuid, DWORD* Attributes, QWORD* DataSize, VOID* Data);
		QWORD(*oSetVariable)(PCWCH VariableName, GUID* VendorGuid, DWORD Attributes, QWORD DataSize, VOID* Data);

		QWORD NtSetSystemEnvironmentValueEx;
		QWORD NtQuerySystemEnvironmentValueEx;

		NTSTATUS NTAPI NtQuerySystemEnvironmentValueExHook(
			PUNICODE_STRING VariableName,
			LPGUID VendorGuid,
			PVOID Value,
			PULONG ValueLength,
			PULONG Attributes
		);

		NTSTATUS NTAPI NtSetSystemEnvironmentValueExHook(
			PUNICODE_STRING VariableName,
			LPGUID VendorGuid,
			PVOID Value,
			ULONG ValueLength,
			ULONG Attributes
		);
	}

	namespace syscall
	{
		QWORD SystemCallEntryPage;
		void __fastcall SyscallStub(unsigned int SyscallIndex, void** SyscallFunction);
		QWORD(*oKeQueryPerformanceCounter)(QWORD rcx);
		QWORD KeQueryPerformanceCounterHook(QWORD rcx);
	}

	namespace input
	{
		PDRIVER_OBJECT    mouclass;
		PDRIVER_OBJECT    mouhid;
		PDEVICE_OBJECT    mouse_device;
		PMOUSE_INPUT_DATA mouse_irp;
		NTSTATUS          mouse_apc(void* a1, void* a2, void* a3, void* a4, void* a5);

		NTSTATUS          (*rimInputApc)(void* a1, void* a2, void* a3, void* a4, void* a5);

		NTSTATUS          (*oMouseClassRead)(PDEVICE_OBJECT device, PIRP irp);
		NTSTATUS          MouseClassReadHook(PDEVICE_OBJECT device, PIRP irp);
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
		UCHAR(*oHalClearLastBranchRecordStack)(void);
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

	globals::exit = 1;
	while (globals::exit != 2)
	{
		NtSleep(100);
		LOG("Please move mouse in order to unload the driver\n");
	}

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

	globals::ntoskrnl = get_module_info(0);
	globals::vmusbmouse = get_module_info(L"vmusbmouse.sys");
	if (!hooks::install())
	{
		LOG("failed to install hooks\n");
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	LOG("Running\n");
	DriverObject->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI hooks::efi::NtQuerySystemEnvironmentValueExHook(
	PUNICODE_STRING VariableName,
	LPGUID VendorGuid,
	PVOID Value,
	PULONG ValueLength,
	PULONG Attributes
)
{
	if (VariableName == 0 || VendorGuid == 0)
	{
		return STATUS_INVALID_PARAMETER_1;
	}
	//
	// if someone has x86-x64 emulator with basic x86/x64 instruction set, feel free to commit
	// 
	// cpu::emulator(efi::oGetVariable, VariableName, VendorGuid, Attributes, DataSize, Data);
	//
	QWORD status = oGetVariable(VariableName->Buffer, VendorGuid, (DWORD*)Attributes, (QWORD*)ValueLength, Value);
	if (status != 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI hooks::efi::NtSetSystemEnvironmentValueExHook(
    PUNICODE_STRING VariableName,
    LPGUID VendorGuid,
    PVOID Value,
    ULONG ValueLength,
    ULONG Attributes
    )
{
	if (VariableName == 0 || VendorGuid == 0)
	{
		return STATUS_INVALID_PARAMETER_1;
	}
	//
	// if someone has x86-x64 emulator with basic x86/x64 instruction set, feel free to commit
	// 
	// cpu::emulator(efi::oSetVariable, VariableName, VendorGuid, Attributes, DataSize, Data);
	//
	QWORD status = oSetVariable(VariableName->Buffer, VendorGuid, Attributes, ValueLength, Value);
	if (status != 0)
	{
		return STATUS_INVALID_PARAMETER;
	}

	return STATUS_SUCCESS;
}

void __fastcall hooks::syscall::SyscallStub(unsigned int SyscallIndex, void** SyscallFunction)
{
	UNREFERENCED_PARAMETER(SyscallIndex);
	UNREFERENCED_PARAMETER(SyscallFunction);

	if (*SyscallFunction == (void*)efi::NtQuerySystemEnvironmentValueEx)
	{
		*SyscallFunction = efi::NtQuerySystemEnvironmentValueExHook;
	}

	else if (*SyscallFunction == (void*)efi::NtSetSystemEnvironmentValueEx)
	{
		*SyscallFunction = efi::NtSetSystemEnvironmentValueExHook;
	}
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

typedef struct {
	QWORD device_object;
	QWORD timestamp;
} DEVICE_INFO;
QWORD SDL_GetTicksNS(void);

double ns_to_herz(double ns) { return 1.0 / (ns / 1e9);  }

//
// https:://github.com/everdox/hidinput
//
NTSTATUS hooks::input::mouse_apc(void* a1, void* a2, void* a3, void* a4, void* a5)
{
	QWORD          extension = (QWORD)mouse_device->DeviceExtension;
	PDEVICE_OBJECT hid       = *(PDEVICE_OBJECT*)(extension + 0x10);
	QWORD          phid      = (QWORD)hid->DeviceExtension;

	//
	// third party driver (razer,steelseries) filtering
	//
	BOOLEAN msdrv=1;
	if (hid->DriverObject != mouhid)
	{
		hid = hid->DeviceObjectExtension->AttachedTo;

		if (hid == 0 || hid->DriverObject != mouhid)
		{
			return rimInputApc(a1, a2, a3, a4, a5);
		}

		phid = (QWORD)hid->DeviceExtension;

		msdrv = 0;
	}

	//
	// check if there is invalid packets in queue
	//
	for (int i = sizeof(MOUSE_INPUT_DATA); i--;)
	{
		if (((unsigned char*)phid + 0x160)[i] != ((unsigned char*)mouse_irp)[i])
		{
			DbgPrintEx(77, 0, "invalid mouse packet detected\n");
			memset(mouse_irp, 0, sizeof(MOUSE_INPUT_DATA));
			return rimInputApc(a1, a2, a3, a4, a5);
		}
	}

	//
	// did someone inject empty :D
	//
	// steelseries mouse driver can cause false positive
	//
	/*
	BOOLEAN empty = 1;
	for (int i = 4; i < sizeof(MOUSE_INPUT_DATA); i++)
	{
		if (((BYTE*)mouse_irp)[i] != 0)
		{
			empty = 0;
			break;
		}
	}

	if (empty)
	{
		DbgPrintEx(77, 0, "empty mouse packet detected\n");
	}
	*/

	//
	// do not ever write code like this. should be good enough for demo
	//
	// ---------------------------------------------------------------------------------
	static DEVICE_INFO dev{};
	if (dev.device_object == 0 || dev.device_object != (QWORD)hid)
	{
		dev.device_object = (QWORD)hid;
		dev.timestamp     = SDL_GetTicksNS();
		return rimInputApc(a1, a2, a3, a4, a5);
	}

	QWORD timestamp = SDL_GetTicksNS();
	if (timestamp - dev.timestamp < 117647) // if latency is less than 117647  ns (8500 Hz)
	{
		//
		// https://www.unitjuggler.com/convert-frequency-from-Hz-to-ns(p).html?val=8500
		//
		LOG("Device: 0x%llx, timestamp: %lld, hz: [%lld]\n",
			(QWORD)hid, timestamp, (QWORD)ns_to_herz( (double)(timestamp - dev.timestamp) ));
	}

	dev.timestamp = timestamp;
	//
	// ---------------------------------------------------------------------------------
	//

	return rimInputApc(a1, a2, a3, a4, a5);
}

//
// https:://github.com/everdox/hidinput
//
NTSTATUS hooks::input::MouseClassReadHook(PDEVICE_OBJECT device, PIRP irp)
{
	QWORD* routine;
	routine = (QWORD*)irp;
	routine += 0xb;
	if (rimInputApc == 0)
	{
		*(QWORD*)&rimInputApc = *routine;
	}

	if (globals::exit == 0)
	{
		*routine = (ULONGLONG)mouse_apc;
	}
	else
	{
		// safe to close signal
		globals::exit = 2;
	}

	mouse_irp    = (struct _MOUSE_INPUT_DATA*)irp->UserBuffer;
	mouse_device = device;

	return hooks::input::oMouseClassRead(device, irp);
}

extern "C" __declspec(dllimport) PCSTR PsGetProcessImageFileName(QWORD process);
void __fastcall hooks::exception::KdTrapHook(void)
{
	//
	// disable upcoming DPC call
	//
	*(BYTE*)(exception::PoHiderInProgress) = 1;


	QWORD KeBugCheckExPtr = (QWORD)KeBugCheckEx;
	KeBugCheckExPtr = KeBugCheckExPtr + 0x23;
	KeBugCheckExPtr = KeBugCheckExPtr + 0x03;
	DWORD ctx_offset = *(DWORD*)KeBugCheckExPtr;
	struct  _CONTEXT* current_context = *(struct  _CONTEXT**)(__readgsqword(0x20) + ctx_offset);


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
	if (thread == 0)
		return 0;

	QWORD host_process = *(QWORD*)(thread + 0x220);

	QWORD lookup_thread;
	if (NT_SUCCESS(PsLookupThreadByThreadId(
		(HANDLE)PsGetThreadId((PETHREAD)thread),
		(PETHREAD*)&lookup_thread
	)))
	{
		ObfDereferenceObject((PVOID)lookup_thread);
		if (lookup_thread == thread)
		{
			return 0;
		}
	}
	return is_unlinked_thread(host_process, thread);
}

UCHAR __fastcall hooks::swap_ctx::HalClearLastBranchRecordStackHook(void)
{
	QWORD current_thread = __readgsqword(0x188);
	QWORD cr3 = __readcr3();

	if (unlink_thread_detection(current_thread))
	{
		LOG("Unlinked thread found [%lld] [%llX] [%llX]\n", (QWORD)PsGetCurrentThreadId(), current_thread, cr3);
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

extern "C" __declspec(dllimport) LIST_ENTRY * PsLoadedModuleList;
MODULE_INFO get_module_info(PWCH module_name)
{
	PLDR_DATA_TABLE_ENTRY module_entry = CONTAINING_RECORD(PsLoadedModuleList, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
	if (module_name == 0)
	{
		return { (QWORD)module_entry->ImageBase, module_entry->SizeOfImage };
	}

	for (PLIST_ENTRY list_entry = PsLoadedModuleList->Flink; list_entry != PsLoadedModuleList; list_entry = list_entry->Flink)
	{
		module_entry = CONTAINING_RECORD(list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (module_entry->ImageBase == 0)
			continue;

		if (module_entry->BaseImageName.Length == 0)
			continue;

		if (module_entry->BaseImageName.Buffer && !wcscmp(module_entry->BaseImageName.Buffer, module_name))
		{
			return { (QWORD)module_entry->ImageBase, module_entry->SizeOfImage };
		}
	}
	return {};
}

extern "C" __declspec(dllimport) LIST_ENTRY * PsLoadedModuleList;
PCWSTR GetCallerModuleName(QWORD address, QWORD* offset)
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
	__out PVOID * Object
);

extern "C" NTSYSCALLAPI POBJECT_TYPE * IoDriverObjectType;
void get_mouse_class_address(PDRIVER_OBJECT* mouclass, PDRIVER_OBJECT* mouhid)
{
	UNICODE_STRING class_string;
	RtlInitUnicodeString(&class_string, L"\\Driver\\MouClass");

	PDRIVER_OBJECT driver_object = 0;
	ObReferenceObjectByName(&class_string, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&driver_object);

	if (mouclass)
		*mouclass = driver_object;

	ObfDereferenceObject(driver_object);

	RtlInitUnicodeString(&class_string, L"\\Driver\\MouHid");
	ObReferenceObjectByName(&class_string, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&driver_object);

	if (mouhid)
		*mouhid = driver_object;

	ObfDereferenceObject(driver_object);
}

extern "C" NTSYSCALLAPI NTSTATUS HalPrivateDispatchTable(void);
extern "C" NTSYSCALLAPI NTSTATUS HalEnumerateEnvironmentVariablesEx(void);


QWORD GetExportByName(QWORD base, const char* export_name)
{
	QWORD a0;
	DWORD a1[4];

	a0 = base + *(unsigned short*)(base + 0x3C);
	if (a0 == base)
	{
		return 0;
	}


	WORD machine = *(WORD*)(a0 + 0x4);

	a0 = machine == 0x8664 ? base + *(DWORD*)(a0 + 0x88) : base + *(DWORD*)(a0 + 0x78);

	if (a0 == base)
	{
		return 0;
	}


	a1[0] = *(DWORD*)(a0 + 0x18);
	a1[1] = *(DWORD*)(a0 + 0x1C);
	a1[2] = *(DWORD*)(a0 + 0x20);
	a1[3] = *(DWORD*)(a0 + 0x24);
	while (a1[0]--) {
		a0 = base + *(DWORD*)(base + a1[2] + (a1[0] * 4));
		if (strcmp((const char*)a0, export_name) == 0)
		{
			return (base + *(DWORD*)(base + a1[1] + (*(unsigned short*)(base + a1[3] + (a1[0] * 2)) * 4)));
		}
	}
	return 0;
}

QWORD GetAddressByRef(QWORD ref, BOOLEAN inc)
{
	QWORD val = ref;

	while (1)
	{
		if (*(unsigned char*)val == 0xE8)
		{
			if ((val + 5) + *(int*)(val + 1) == ref)
				break;
		}
		if (inc) val++; else val--;
	}

	while (*(unsigned char*)val != 0xCC)
		val--;

	return val + 1;
}

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
	syscall::SystemCallEntryPage = (QWORD)ImgGetSyscallEntry((PVOID)globals::ntoskrnl.base);


	//
	// mouse hook
	//
	get_mouse_class_address(&input::mouclass, &input::mouhid);
	input::oMouseClassRead = input::mouclass->MajorFunction[IRP_MJ_READ];
	input::mouclass->MajorFunction[IRP_MJ_READ] = input::MouseClassReadHook;


	//
	// global exception hook
	//
	exception::KdpDebugRoutineSelect = FindPattern(globals::ntoskrnl.base, (BYTE*)"\x83\x3D\x00\x00\x00\x00\x00\x8A\x44", (BYTE*)"xx????xxx");
	if (exception::KdpDebugRoutineSelect == 0)
	{
	E0:
		input::mouclass->MajorFunction[IRP_MJ_READ] = input::oMouseClassRead;
		return 0;
	}

	exception::PoHiderInProgress = FindPattern(globals::ntoskrnl.base, (BYTE*)"\xC6\x05\x00\x00\x00\x00\x01\x33\xC9\xE8", (BYTE*)"xx????xxxx");
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
	while (*(unsigned short*)KiCpuTracingFlags != 0xE800) KiCpuTracingFlags++; KiCpuTracingFlags += 2;
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

	efi::NtSetSystemEnvironmentValueEx =
		GetAddressByRef((QWORD)GetExportByName(globals::ntoskrnl.base, "ExSetFirmwareEnvironmentVariable"), 1);

	efi::NtQuerySystemEnvironmentValueEx =
		GetAddressByRef((QWORD)GetExportByName(globals::ntoskrnl.base, "ExGetFirmwareEnvironmentVariable"), 0);

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
	input::mouclass->MajorFunction[IRP_MJ_READ] = input::oMouseClassRead;

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
	while (*(unsigned short*)KiCpuTracingFlags != 0xE800) KiCpuTracingFlags++; KiCpuTracingFlags += 2;
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

void* FindPatternEx(unsigned char* base, QWORD size, unsigned char* pattern, unsigned char* mask)
{
	size -= strlen((const char*)mask);
	for (QWORD i = 0; i <= size; ++i) {
		void* addr = &base[i];
		if (CheckMask((unsigned char*)addr, pattern, mask))
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

	QWORD nt_header = (QWORD) * (DWORD*)(base + 0x03C) + base;
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
			QWORD virtual_address = base + (QWORD) * (DWORD*)(section + 0x0C);
			DWORD virtual_size = *(DWORD*)(section + 0x08);

			QWORD addr = (QWORD)FindPatternEx((unsigned char*)virtual_address, virtual_size, pattern, mask);
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
ZwTraceControl(
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
} WNODE_HEADER, * PWNODE_HEADER;

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
} EVENT_TRACE_PROPERTIES, * PEVENT_TRACE_PROPERTIES;

typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
	ULONG64				Unknown[3];
	UNICODE_STRING			ProviderName;
} CKCL_TRACE_PROPERTIES, * PCKCL_TRACE_PROPERTIES;

const GUID session_guid = { 0x9E814AAD, 0x3204, 0x11D2, { 0x9A, 0x82, 0x0, 0x60, 0x8, 0xA8, 0x69, 0x39 } };

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

QWORD SDL_GetPerformanceCounter(void)
{
	LARGE_INTEGER counter;
	return KeQueryPerformanceCounter(&counter).QuadPart;
}


QWORD SDL_GetPerformanceFrequency(void)
{
	LARGE_INTEGER frequency;
	KeQueryPerformanceCounter(&frequency);
	return frequency.QuadPart;
}

DWORD CalculateGCD(DWORD a, DWORD b)
{
	if (b == 0) {
		return a;
	}
	return CalculateGCD(b, (a % b));
}

QWORD SDL_GetTicksNS(void)
{
	QWORD starting_value, value;

	static QWORD tick_start = SDL_GetPerformanceCounter();
	static QWORD tick_freq = SDL_GetPerformanceFrequency();
	static DWORD gcd = CalculateGCD(1000000000LL, (DWORD)tick_freq);
	static QWORD tick_numerator_ns = (1000000000LL / gcd);
	static DWORD tick_denominator_ns = (DWORD)(tick_freq / gcd);

	starting_value = (SDL_GetPerformanceCounter() - tick_start);
	value = (starting_value * tick_numerator_ns);
	value /= tick_denominator_ns;
	return value;
}

