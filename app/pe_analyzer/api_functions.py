"""Shared Windows API names and categories for import, string, and hash analysis.

SUSPICIOUS_APIS drives import flagging. ADDITIONAL_HASHED_APIS expands hash
and string matching without flagging every additional name as an import.
API_NAME_CATEGORIES combines both collections, preferring suspicious categories.
This module owns the registries and shared token matching; hashes are generated
by the hashes module.
"""

import re
from collections.abc import Iterator

SUSPICIOUS_APIS: dict[str, set[str]] = {
    "Download & Network Retrieval": {
        "URLDownloadToCacheFileA",
        "URLDownloadToCacheFileW",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "InternetOpenUrlA",
        "InternetOpenUrlW",
        "HttpOpenRequestA",
        "HttpOpenRequestW",
        "HttpSendRequestA",
        "HttpSendRequestW",
    },
    "Memory Allocation & Protection": {
        "VirtualAlloc",
        "VirtualFree",
        "VirtualProtect",
        "NtAllocateVirtualMemory",
        "ZwAllocateVirtualMemory",
        "NtFreeVirtualMemory",
        "ZwFreeVirtualMemory",
        "NtProtectVirtualMemory",
        "ZwProtectVirtualMemory",
    },
    "Process Injection & Hollowing": {
        "OpenProcess",
        "VirtualAllocEx",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "QueueUserAPC",
        "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection",
        "SetThreadContext",
        "GetThreadContext",
        "ResumeThread",
        "NtMapViewOfSection",
        "ZwMapViewOfSection",
    },
    "Dynamic API Resolution": {
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "GetProcAddress",
        "LdrLoadDll",
        "LdrGetProcedureAddress",
    },
    "Anti-Debugging & Evasion": {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess",
        "ZwQueryInformationProcess",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "SetUnhandledExceptionFilter",
    },
    "Persistence & Execution": {
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "RegSetValueExA",
        "RegSetValueExW",
        "CreateServiceA",
        "CreateServiceW",
        "StartServiceA",
        "StartServiceW",
        "WinExec",
        "ShellExecuteA",
        "ShellExecuteW",
        "CreateProcessA",
        "CreateProcessW",
    },
    "Credential Access & Hooking": {
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "GetAsyncKeyState",
        "GetForegroundWindow",
        "CryptEncrypt",
        "CryptDecrypt",
        "CryptAcquireContextA",
        "CryptAcquireContextW",
        "LsaRetrievePrivateData",
    },
    "Network Communication": {
        "InternetOpenA",
        "InternetOpenW",
        "InternetConnectA",
        "InternetConnectW",
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpOpenRequest",
        "WinHttpSendRequest",
        "WSAStartup",
        "socket",
        "connect",
        "send",
        "recv",
        "getaddrinfo",
        "DnsQuery_A",
        "DnsQuery_W",
    },
    "File Operations": {
        "CreateFileA",
        "CreateFileW",
        "WriteFile",
        "DeleteFileA",
        "DeleteFileW",
        "MoveFileA",
        "MoveFileW",
        "CopyFileA",
        "CopyFileW",
        "FindFirstFileA",
        "FindFirstFileW",
        "FindNextFileA",
        "FindNextFileW",
    },
    "Discovery": {
        "CreateToolhelp32Snapshot",
        "Module32First",
        "Module32Next",
        "GetUserNameA",
        "GetUserNameW",
        "GetComputerNameA",
        "GetComputerNameW",
        "GlobalMemoryStatusEx",
        "GetSystemInfo",
    },
    "Privilege & Token Manipulation": {
        "OpenProcessToken",
        "OpenThreadToken",
        "LookupPrivilegeValueA",
        "LookupPrivilegeValueW",
        "AdjustTokenPrivileges",
        "DuplicateTokenEx",
        "ImpersonateLoggedOnUser",
        "CreateProcessWithTokenW",
        "CreateProcessAsUserW",
    },
    "Screen & Clipboard Collection": {
        "BitBlt",
        "GetDC",
        "CreateCompatibleBitmap",
        "OpenClipboard",
        "GetClipboardData",
        "SetClipboardData",
    },
    "Anti-Analysis & Timing": {
        "Sleep",
        "SleepEx",
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "EnumProcesses",
        "Process32First",
        "Process32Next",
        "NtSetInformationThread",
    },
    "Service & Task Persistence": {
        "OpenSCManagerA",
        "OpenSCManagerW",
        "ChangeServiceConfigA",
        "ChangeServiceConfigW",
        "ControlService",
        "DeleteService",
        "CoCreateInstance",
        "TaskScheduler",
    },
    "Cryptography & Encoding": {
        "CryptProtectData",
        "CryptUnprotectData",
        "BCryptEncrypt",
        "BCryptDecrypt",
        "BCryptGenerateSymmetricKey",
        "CryptStringToBinaryA",
        "CryptStringToBinaryW",
    },
    "Driver & Native Execution": {
        "NtLoadDriver",
        "ZwLoadDriver",
        "DeviceIoControl",
        "NtCreateSection",
        "ZwCreateSection",
        "NtWriteVirtualMemory",
        "ZwWriteVirtualMemory",
    },
}

ADDITIONAL_HASHED_APIS: dict[str, set[str]] = {
    "Process and memory": {
        "CreateThread", "CreateRemoteThreadEx", "OpenThread", "SuspendThread",
        "TerminateProcess", "TerminateThread", "VirtualAllocExNuma",
        "VirtualQuery", "VirtualQueryEx", "NtReadVirtualMemory",
        "NtOpenProcess", "NtOpenThread", "NtResumeThread", "NtSuspendThread",
        "NtQueueApcThread", "NtCreateProcessEx",
        "NtCreateUserProcess", "RtlMoveMemory",
        "MapViewOfFile", "MapViewOfFileEx",
        "CreateFileMappingA", "CreateFileMappingW", "CreateFileMapping2",
        "UnmapViewOfFile", "FlushInstructionCache",
        "Wow64GetThreadContext", "Wow64SetThreadContext",
    },
    "Dynamic loading and resolution": {
        "FreeLibrary", "GetModuleHandleA",
        "GetModuleHandleW", "GetModuleHandleExA", "GetModuleHandleExW",
        "LdrGetDllHandle",
        "RtlGetVersion",
    },
    "Credentials and tokens": {
        "LogonUserA", "LogonUserW", "DuplicateToken",
        "GetTokenInformation", "SetTokenInformation",
        "ImpersonateNamedPipeClient",
        "RevertToSelf", "CredReadA", "CredReadW", "CredEnumerateA",
        "CredEnumerateW", "LsaEnumerateLogonSessions",
        "LsaGetLogonSessionData", "MiniDumpWriteDump", "PssCaptureSnapshot",
    },
    "Network and transfer": {
        "WinHttpReadData", "WinHttpWriteData", "WinHttpReceiveResponse",
        "WinHttpQueryHeaders", "InternetReadFile", "InternetWriteFile",
        "InternetCrackUrlA", "InternetCrackUrlW", "WSAConnect", "WSASend",
        "WSARecv", "sendto", "recvfrom", "gethostbyname",
    },
    "Persistence and system changes": {
        "RegOpenKeyExA", "RegOpenKeyExW", "RegDeleteKeyA", "RegDeleteKeyW",
        "RegDeleteValueA", "RegDeleteValueW", "RegQueryValueExA",
        "RegQueryValueExW",
        "OpenServiceA", "OpenServiceW",
        "ChangeServiceConfig2A",
        "ChangeServiceConfig2W", "MoveFileExA", "MoveFileExW",
        "SetFileAttributesA", "SetFileAttributesW",
    },
    "Discovery and evasion": {
        "EnumWindows", "EnumDesktopWindows", "EnumProcessModules",
        "EnumProcessModulesEx", "GetModuleFileNameA", "GetModuleFileNameW",
        "GetSystemDirectoryA", "GetSystemDirectoryW", "GetWindowsDirectoryA",
        "GetWindowsDirectoryW", "GetAdaptersAddresses", "GetIfTable",
        "NtQuerySystemInformation",
        "GetKeyState",
    },
}

API_NAME_CATEGORIES: dict[str, str] = {
    name: category
    for category, names in (*ADDITIONAL_HASHED_APIS.items(), *SUSPICIOUS_APIS.items())
    for name in names
}

_API_NAMES_BY_LOWER = {name.lower(): name for name in API_NAME_CATEGORIES}
_API_NAME_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def iter_api_name_matches(text: str) -> Iterator[tuple[str, int]]:
    """Yield canonical API names and their character offsets in encounter order."""
    for match in _API_NAME_TOKEN.finditer(text):
        canonical_name = _API_NAMES_BY_LOWER.get(match.group().lower())
        if canonical_name is not None:
            yield canonical_name, match.start()
