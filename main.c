#include <ntddk.h>

/*
 * ekknod@2021
 * 
 * this method was part of my hobby anti-cheat, and decided to make it public.
 * It should catch all hidden threads, doesn't matter where you unlink it.
 *
 */

typedef struct _KPRCB* PKPRCB;

extern PKPRCB
KeQueryPrcbAddress(
	__in ULONG Number
);

typedef ULONG_PTR QWORD;
typedef ULONG DWORD;
typedef int BOOL;

extern PCSTR
PsGetProcessImageFileName(QWORD process);

PVOID thread_object;
HANDLE thread_handle;
BOOLEAN gExitCalled;

BOOL IsThreadFound(QWORD process, QWORD thread)
{
	BOOL contains = 0;

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
}

NTSTATUS system_thread(void)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Anti-Cheat.sys -> catch hidden threads\n");




	while (gExitCalled == 0) {
		NtSleep(1);


		for (int i = 0; i < KeNumberProcessors; i++) {
			PKPRCB prcb = KeQueryPrcbAddress(i);


			if (prcb == 0)
				continue;


			QWORD current_thread = *(QWORD*)((QWORD)prcb + 0x8);
			if (current_thread == 0)
				continue;

			// ohhohhoho, don't go manipulate ETHREAD ExitStatus, it can be anyway verified.
			if (PsGetThreadExitStatus((PETHREAD)current_thread) != STATUS_PENDING)
				continue;

			QWORD cid = (QWORD)PsGetThreadId((PETHREAD)current_thread);
			QWORD host_process = *(QWORD*)(current_thread + 0x220);



			if (!IsThreadFound(host_process, current_thread))
			{
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Hidden thread found [%s %d], %llx, %d]\n",
					PsGetProcessImageFileName(host_process),

					PsGetProcessId((PEPROCESS)host_process),

					current_thread,
					(DWORD)cid
				);
			}

			QWORD next_thread = *(QWORD*)((QWORD)prcb + 0x10);


			if (next_thread) {

				// ohhohhoho, don't go manipulate ETHREAD ExitStatus, it can be anyway verified.
				if (PsGetThreadExitStatus((PETHREAD)next_thread) != STATUS_PENDING)
					continue;

				cid = (QWORD)PsGetThreadId((PETHREAD)next_thread);
				host_process = *(QWORD*)(next_thread + 0x220);

				if (!IsThreadFound(host_process, next_thread))
				{
					DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Hidden thread found [%s %d], %llx, %d]\n",
						PsGetProcessImageFileName(host_process),

						PsGetProcessId((PEPROCESS)host_process),

						current_thread,
						(DWORD)cid
					);
				}

			}


		}
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
