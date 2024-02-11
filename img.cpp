/*
*	Module Name:
*		img.cpp
*
*	Abstract:
*		Helper routines for extracting useful information from the PE
*		file specification.
*
*	Authors:
*		Nick Peterson <everdox@gmail.com> | http://everdox.net/
*
*	Special thanks to Nemanja (Nemi) Mulasmajic <nm@triplefault.io>
*	for his help with the POC.
*
*/


#include "img.h"
#include "hde/hde64.h"
#include <intrin.h>

#define OPCODE_JMP_NEAR 0xE9

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG		VirtualAddress;
	ULONG		Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_SECTION_HEADER {
	UCHAR		Name[8];
	union {
		ULONG	PhysicalAddress;
		ULONG	VirtualSize;
	} Misc;
	ULONG   VirtualAddress;
	ULONG   SizeOfRawData;
	ULONG   PointerToRawData;
	ULONG   PointerToRelocations;
	ULONG   PointerToLinenumbers;
	USHORT  NumberOfRelocations;
	USHORT  NumberOfLinenumbers;
	ULONG   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	USHORT      Magic;
	UCHAR       MajorLinkerVersion;
	UCHAR       MinorLinkerVersion;
	ULONG       SizeOfCode;
	ULONG       SizeOfInitializedData;
	ULONG       SizeOfUninitializedData;
	ULONG       AddressOfEntryPoint;
	ULONG       BaseOfCode;
	ULONGLONG   ImageBase;
	ULONG       SectionAlignment;
	ULONG       FileAlignment;
	USHORT      MajorOperatingSystemVersion;
	USHORT      MinorOperatingSystemVersion;
	USHORT      MajorImageVersion;
	USHORT      MinorImageVersion;
	USHORT      MajorSubsystemVersion;
	USHORT      MinorSubsystemVersion;
	ULONG       Win32VersionValue;
	ULONG       SizeOfImage;
	ULONG       SizeOfHeaders;
	ULONG       CheckSum;
	USHORT      Subsystem;
	USHORT      DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	ULONG       LoaderFlags;
	ULONG       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_FILE_HEADER {
	USHORT		Machine;
	USHORT		NumberOfSections;
	ULONG		TimeDateStamp;
	ULONG		PointerToSymbolTable;
	ULONG		NumberOfSymbols;
	USHORT		SizeOfOptionalHeader;
	USHORT		Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64 {
	ULONG                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;


EXTERN_C
NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
	_In_ PVOID ModuleAddress
);


#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS64, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))


/*
*	Retrieves the start of a PE section and its size within an
*	image.
*/
PVOID ImgGetImageSection(
	_In_ PVOID ImageBase,
	_In_ const char* SectionName,
	_Out_opt_ PULONG SizeOfSection)
{
	//
	// Get the IMAGE_NT_HEADERS.
	//
	PIMAGE_NT_HEADERS64 NtHeaders = RtlImageNtHeader(ImageBase);
	if (!NtHeaders)
	{
		return NULL;
	}

	//
	// Walk the PE sections, looking for our target section.
	//
	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);
	for (USHORT i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i, ++SectionHeader)
	{
		if (!_strnicmp((const char*)SectionHeader->Name, SectionName, 8))
		{
			if (SizeOfSection)
			{
				*SizeOfSection = SectionHeader->SizeOfRawData;
			}

			return (PVOID)((uintptr_t)ImageBase + SectionHeader->VirtualAddress);
		}
	}

	return NULL;
}

/*
*	Retrieves the address of the non-KVA shadow system call entry.
*/
PVOID ImgGetSyscallEntry(PVOID ntoskrnl_base)
{
	//
	// Get the base address of the kernel.
	//
	PVOID NtBaseAddress = (PVOID)ntoskrnl_base;
	if (!NtBaseAddress)
	{
		return NULL;
	}

	//
	// Get the LSTAR MSR. This should be KiSystemCall64 if KVA shadowing
	// is not enabled.
	//
	PVOID SyscallEntry = (PVOID)__readmsr(0xC0000082);

	//
	// Get the PE section for KVASCODE. If one doesn't exit, KVA 
	// shadowing doesn't exist. This can be queried using 
	// NtQuerySystemInformation alternatively.
	//
	ULONG SizeOfSection;
	PVOID SectionBase = ImgGetImageSection(NtBaseAddress, "KVASCODE", &SizeOfSection);
	if (!SectionBase)
	{
		return SyscallEntry;
	}

	//
	// Is the value within this KVA shadow region? If not, we're done.
	//
	if (!(SyscallEntry >= SectionBase && SyscallEntry < (PVOID)((uintptr_t)SectionBase + SizeOfSection)))
	{
		return SyscallEntry;
	}

	//
	// This is KiSystemCall64Shadow.
	//
	hde64s HDE;
	for (PCHAR KiSystemServiceUser = (PCHAR)SyscallEntry; /* */; KiSystemServiceUser += HDE.len)
	{
		//
		// Disassemble every instruction till the first near jmp (E9).
		//
		if (!hde64_disasm(KiSystemServiceUser, &HDE))
		{
			break;
		}

		if (HDE.opcode != OPCODE_JMP_NEAR)
		{
			continue;
		}

		//
		// Ignore jmps within the KVA shadow region.
		//
		PVOID PossibleSyscallEntry = (PVOID)((intptr_t)KiSystemServiceUser + (int)HDE.len + (int)HDE.imm.imm32);
		if (PossibleSyscallEntry >= SectionBase && PossibleSyscallEntry < (PVOID)((uintptr_t)SectionBase + SizeOfSection))
		{
			continue;
		}

		//
		// Found KiSystemServiceUser.
		//
		SyscallEntry = PossibleSyscallEntry;
		break;
	}

	return SyscallEntry;
}

