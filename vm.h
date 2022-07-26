#ifndef VM_H
#define VM_H


#include <ntddk.h>

#ifndef CUSTOMTYPES
#define CUSTOMTYPES
typedef ULONG_PTR QWORD;
typedef ULONG DWORD;
typedef int BOOL;
#endif

QWORD GetProcessByName(const char* process_name);
QWORD GetModuleByName(QWORD target_process, const wchar_t* module_name);

#endif

