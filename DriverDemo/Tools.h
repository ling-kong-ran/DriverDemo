#include "NtDef.h"

PDRIVER_OBJECT GetDriverObjectByName(__in PCWSTR name);


PRTL_PROCESS_MODULE_INFORMATION GetSystemModuleByName(__in PUCHAR moduleName, __out PULONG pModuleSize);