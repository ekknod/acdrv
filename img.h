/*
*	Module Name:
*		img.h
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

#pragma once

#include <ntifs.h>

///
/// Forward declarations.
///

PVOID ImgGetSyscallEntry(PVOID ntoskrnl_base);

