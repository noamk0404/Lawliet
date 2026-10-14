"""Shared detection definitions and bounded-inspection limits."""

import re

from .api_functions import API_NAME_CATEGORIES, SUSPICIOUS_APIS

HASH_CHUNK_SIZE = 1024 * 1024
YARA_SCAN_TIMEOUT_SECONDS = 30
MINIMUM_STRING_LENGTH = 5
MAX_STRING_INDICATORS = 500
MAX_RESOURCES = 500
MAX_TLS_CALLBACKS = 64
MAX_EVIDENCE_ITEMS = 15
MAX_INDICATOR_LENGTH = 512
HIGH_ENTROPY_RESOURCE_THRESHOLD = 7.0

# Per-file and per-item budgets for untrusted content. Truncation is reported.
MAX_RESOURCE_BYTES = 2 * 1024 * 1024
MAX_RESOURCE_TOTAL_BYTES = 16 * 1024 * 1024
MAX_RESOURCE_NODES = 4096
MAX_DECODE_BYTES = 1024 * 1024
MAX_DECODE_DEPTH = 3
MAX_DECODE_RESULTS = 8
MAX_ENCODING_CANDIDATES = 32
MAX_XOR_BYTES = 256 * 1024
MAX_EXTRACTED_STRINGS = 10000
MAX_STRING_LENGTH = 8192
MAX_STRING_SCAN_BYTES = 32 * 1024 * 1024
MAX_STRING_DECODE_ATTEMPTS = 2048
MAX_BINARY_HASH_MATCHES = 256
MAX_EXECUTABLE_CODE_SCAN_BYTES = 16 * 1024 * 1024

CONTENT_SIGNATURES = (
    ("PNG image", b"\x89PNG\r\n\x1a\n", "image asset"),
    ("JPEG image", b"\xff\xd8\xff", "image asset"),
    ("GIF image", b"GIF87a", "image asset"),
    ("GIF image", b"GIF89a", "image asset"),
    ("BMP image", b"BM", "image asset"),
    ("ICO image", b"\0\0\x01\0", "icon asset"),
    ("CUR image", b"\0\0\x02\0", "cursor asset"),
    ("TIFF image", b"II\x2a\0", "image asset"),
    ("TIFF image", b"MM\0\x2a", "image asset"),
    ("PDF document", b"%PDF-", "embedded document"),
    ("ZIP archive", b"PK\x03\x04", "embedded archive"),
    ("7-Zip archive", b"7z\xbc\xaf\x27\x1c", "embedded archive"),
    ("RAR archive", b"Rar!\x1a\x07", "embedded archive"),
    ("CAB archive", b"MSCF", "embedded archive"),
)
RESOURCE_ROLES = {
    "RT_MANIFEST": "application manifest",
    "RT_VERSION": "version metadata",
    "RT_STRING": "localized strings",
    "RT_MENU": "menu definition",
    "RT_DIALOG": "dialog definition",
    "RT_ACCELERATOR": "keyboard shortcuts",
    "RT_GROUP_ICON": "icon directory",
    "RT_GROUP_CURSOR": "cursor directory",
}
# These are byte-signature heuristics, not disassembly. Require both groups.
SHELLCODE_PEB_PATTERNS = (
    b"\x64\xa1\x30\0\0\0",
    b"\x64\x8b\x52\x30",
    b"\x65\x48\x8b\x52\x60",
    b"\x65\x48\x8b\x04\x25\x60\0\0\0",
)
SHELLCODE_RESOLVER_PATTERNS = (b"\xc1\xcf\x0d", b"\xc1\xc9\x0d")
# Narrow x86/x64 PEB access and BeingDebugged checks. These are byte heuristics,
# not a general disassembler or proof that the branch is reached.
PEB_DEBUG_READ_PATTERNS = {
    0x014C: b"\x64\xa1\x30\x00\x00\x00",  # mov eax, fs:[0x30]
    0x8664: b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00",  # mov rax, gs:[0x60]
}
PEB_DEBUG_FLAG_PATTERNS = (
    b"\x80\x78\x02\x00",  # cmp byte ptr [*ax+2], 0
    b"\xf6\x40\x02\x01",  # test byte ptr [*ax+2], 1
    b"\x0f\xb6\x40\x02",  # movzx *, byte ptr [*ax+2]
)
ENCODING_PATTERNS = (
    ("hex", re.compile(r"(?<![\w])[0-9a-fA-F]{4,}(?![\w])")),
    ("hex-escape", re.compile(r"(?:\\x[0-9a-fA-F]{2}){2,}")),
    ("unicode-escape", re.compile(r"(?:\\u[0-9a-fA-F]{4}){2,}")),
    (
        "percent",
        re.compile(r"(?:[A-Za-z0-9_./:?-]*%[0-9a-fA-F]{2})+[A-Za-z0-9_./:?-]*"),
    ),
    ("base32", re.compile(r"(?<![\w])[A-Z2-7]{8,}={0,6}(?![\w=])")),
    ("base64", re.compile(r"(?<![\w+/=-])[A-Za-z0-9+/_-]{2,}={0,2}(?![\w+/=-])")),
)

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

MACHINE_NAMES = {
    0x014C: "x86",
    0x01C0: "ARM",
    0x8664: "x64",
    0xAA64: "ARM64",
}

SUBSYSTEM_NAMES = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console",
    5: "OS/2 Console",
    7: "POSIX Console",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    14: "Xbox",
    16: "Windows Boot Application",
}

DLL_CHARACTERISTICS = {
    "high_entropy_va": 0x0020,
    "aslr": 0x0040,
    "force_integrity": 0x0080,
    "dep": 0x0100,
    "no_seh": 0x0400,
    "control_flow_guard": 0x4000,
}

FILE_SIGNATURES = (
    ("PE executable", b"MZ"),
    ("ZIP archive", b"PK\x03\x04"),
    ("7-Zip archive", b"7z\xbc\xaf\x27\x1c"),
    ("RAR archive", b"Rar!\x1a\x07"),
    ("CAB archive", b"MSCF"),
    ("PDF document", b"%PDF-"),
    ("gzip stream", b"\x1f\x8b\x08"),
)

IGNORED_URL_PREFIXES = (
    "http://schemas.microsoft.com/",
    "https://schemas.microsoft.com/",
    "http://www.w3.org/",
    "https://www.w3.org/",
)

IOC_PATTERNS = (
    ("url", re.compile(r"(?i)\b(?:https?|ftp)://[^\s\"'<>]{4,}")),
    ("ipv4", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")),
    (
        "registry_persistence",
        re.compile(
            r"(?i)(?:software\\microsoft\\windows\\currentversion\\(?:runonceex|runonce|run)(?![a-z0-9])|"
            r"software\\microsoft\\windows\\currentversion\\policies\\explorer\\run(?![a-z0-9])|"
            r"system\\currentcontrolset\\services|"
            r"windows nt\\currentversion\\winlogon|"
            r"image file execution options)"
        ),
    ),
    (
        "startup_folder",
        re.compile(r"(?i)microsoft\\windows\\start menu\\programs\\startup(?![a-z0-9])"),
    ),
    (
        "scheduled_task_creation",
        re.compile(r"(?i)\bschtasks(?:\.exe)?\s+/create\b"),
    ),
    (
        "service_creation_command",
        re.compile(r"(?i)\bsc(?:\.exe)?\s+create\s+[^\s\"']+"),
    ),
    (
        "debugger_query",
        re.compile(r"(?i)\b(?:ProcessDebugPort|ProcessDebugFlags|ProcessDebugObjectHandle)\b"),
    ),
    (
        "suspicious_command",
        re.compile(
            r"(?i)\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|rundll32(?:\.exe)?|"
            r"regsvr32(?:\.exe)?|mshta(?:\.exe)?|certutil(?:\.exe)?|"
            r"wscript(?:\.exe)?|cscript(?:\.exe)?|schtasks(?:\.exe)?|"
            r"wmic(?:\.exe)?)\b"
        ),
    ),
    (
        "anti_analysis",
        re.compile(
            r"(?i)\b(?:wireshark|procmon|processhacker|ollydbg|x64dbg|"
            r"idaq?64?|ida|ghidra|fiddler|vboxservice|vmtoolsd|sandboxie)\b"
        ),
    ),
    ("named_pipe", re.compile(r"(?i)\\\\\.\\pipe\\[^\s\"']+")),
    (
        "base64_blob",
        re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{48,}={0,2}(?![A-Za-z0-9+/])"),
    ),
    ("hex_blob", re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{64,}(?![0-9a-f])")),
)

INDICATOR_FINDING_CONFIG = {
    "flagged_api_name": (
        "Suspicious API names embedded as strings",
        "API Resolution",
        "low",
        6,
        0.62,
    ),
    "registry_persistence": (
        "Persistence-related registry strings",
        "Persistence",
        "medium",
        10,
        0.72,
    ),
    "startup_folder": ("Startup-folder path strings", "Persistence", "low", 5, 0.60),
    "scheduled_task_creation": (
        "Scheduled-task creation command strings", "Persistence", "medium", 8, 0.72,
    ),
    "service_creation_command": (
        "Service-creation command strings", "Persistence", "medium", 8, 0.72,
    ),
    "debugger_query": (
        "Debugger-query constants as strings", "Anti-Analysis", "low", 4, 0.58,
    ),
    "anti_analysis": (
        "Analysis-tool or virtual-machine strings",
        "Anti-Analysis",
        "medium",
        8,
        0.68,
    ),
    "suspicious_command": (
        "Command interpreter or LOLBin strings",
        "Execution",
        "low",
        6,
        0.62,
    ),
    "url": ("Network URL strings", "Network", "low", 4, 0.55),
    "named_pipe": ("Named-pipe strings", "IPC", "low", 4, 0.55),
    "base64_blob": ("Long Base64-like strings", "Obfuscation", "low", 3, 0.50),
    "hex_blob": ("Long hexadecimal strings", "Obfuscation", "low", 3, 0.50),
}

REGISTRY_WRITE_APIS = {
    "regsetvalueexa",
    "regsetvalueexw",
    "regcreatekeyexa",
    "regcreatekeyexw",
}

SERVICE_CREATE_APIS = {"createservicea", "createservicew", "changeserviceconfiga", "changeserviceconfigw"}
STARTUP_FILE_APIS = {"copyfilea", "copyfilew", "movefilea", "movefilew", "movefileexa", "movefileexw"}
DIRECT_DEBUGGER_APIS = {"isdebuggerpresent", "checkremotedebuggerpresent"}
DEBUG_QUERY_APIS = {"ntqueryinformationprocess", "zwqueryinformationprocess"}

PROCESS_LAUNCH_APIS = {
    "createprocessa",
    "createprocessw",
    "winexec",
    "shellexecutea",
    "shellexecutew",
}

NETWORK_ENDPOINT_APIS = {
    "urldownloadtofilea",
    "urldownloadtofilew",
    "internetopenurla",
    "internetopenurlw",
    "winhttpsendrequest",
    "httpsendrequesta",
    "httpsendrequestw",
    "connect",
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "informational": 3}
PACKING_RULES = {
    "single_packing_indicator",
    "probable_packing",
    "sparse_imports_packed",
    "high_entropy_overlay",
    "local_entropy",
    "identified_packer",
}



# Common packer/protector section names. A name match is evidence, not a verdict.
PACKER_SECTION_NAMES = {
    "upx0",
    "upx1",
    "upx2",
    ".aspack",
    ".adata",
    "aspack",
    ".packed",
    ".pack",
    "petite",
    ".petite",
    ".mpress1",
    ".mpress2",
    "mpress1",
    "mpress2",
    ".themida",
    "themida",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    "vmp0",
    "vmp1",
    "vmp2",
    ".enigma1",
    ".enigma2",
    "pec1",
    "pec2",
}


# Ordered steps are not required here: imports only prove availability, not call order.
BEHAVIOR_CHAINS = {
    "process_injection": {
        "title": "Remote process injection capability",
        "category": "Process Injection",
        "severity": "high",
        "score": 30,
        "confidence": 0.82,
        "required": [
            {"OpenProcess"},
            {"VirtualAllocEx", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory"},
            {"WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory"},
            {
                "CreateRemoteThread",
                "NtCreateThreadEx",
                "RtlCreateUserThread",
                "QueueUserAPC",
            },
        ],
    },
    "process_hollowing": {
        "title": "Process hollowing capability",
        "category": "Process Injection",
        "severity": "high",
        "score": 35,
        "confidence": 0.88,
        "required": [
            {"CreateProcessA", "CreateProcessW"},
            {"NtUnmapViewOfSection", "ZwUnmapViewOfSection"},
            {"WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory"},
            {"SetThreadContext"},
            {"ResumeThread"},
        ],
    },
    "download_and_execute": {
        "title": "Download and execute capability",
        "category": "Payload Delivery",
        "severity": "high",
        "score": 25,
        "confidence": 0.78,
        "required": [
            {
                "URLDownloadToFileA",
                "URLDownloadToFileW",
                "URLDownloadToCacheFileA",
                "URLDownloadToCacheFileW",
                "InternetOpenUrlA",
                "InternetOpenUrlW",
                "WinHttpSendRequest",
            },
            {
                "CreateProcessA",
                "CreateProcessW",
                "WinExec",
                "ShellExecuteA",
                "ShellExecuteW",
            },
        ],
    },
    "privilege_adjustment": {
        "title": "Privilege adjustment capability",
        "category": "Privilege Escalation",
        "severity": "medium",
        "score": 12,
        "confidence": 0.72,
        "required": [
            {"OpenProcessToken", "OpenThreadToken"},
            {"LookupPrivilegeValueA", "LookupPrivilegeValueW"},
            {"AdjustTokenPrivileges"},
        ],
    },
    "dynamic_payload_loading": {
        "title": "Dynamic payload loading capability",
        "category": "Evasion",
        "severity": "medium",
        "score": 10,
        "confidence": 0.60,
        "required": [
            {
                "LoadLibraryA",
                "LoadLibraryW",
                "LoadLibraryExA",
                "LoadLibraryExW",
                "LdrLoadDll",
            },
            {"GetProcAddress", "LdrGetProcedureAddress"},
            {
                "VirtualAlloc",
                "VirtualProtect",
                "NtAllocateVirtualMemory",
                "NtProtectVirtualMemory",
            },
        ],
    },
}


# Language detection hints based on imported DLLs
LANGUAGE_HINTS: dict[str, list[str]] = {
    ".NET": ["mscoree.dll", "mscorwks.dll", "clr.dll"],
    "C++": ["msvcp", "vcruntime", "libstdc++"],
    "Python": ["python", "python3"],
    "Delphi": ["sysutils.dcu", "system.dcu"],
    # Go binaries are normally identified from build/runtime strings, not DLLs.
    "Go": [],
    "Rust": ["rust_std", "rustc"],
    "Java": ["java.dll", "jvm.dll"],
}


# Language detection strings found in binary data/resources
LANGUAGE_STRINGS: dict[str, list[str]] = {
    ".NET": [
        ".net framework",
        "assembly version",
        "publickeytoken",
        "mscorlib",
        "system.private.corelib",
        ".net core",
    ],
    "C++": [
        "microsoft visual c++",
        "runtime error",
        "pure virtual function call",
        "__vfptr",
        "std::",
        "basic_string",
    ],
    "Python": [
        "python",
        "sys.executable",
        "importlib",
        "site-packages",
        "python3",
    ],
    "Go": [
        "go version",
        "runtime.main",
        "golang.org",
        "gopkg",
    ],
    "Rust": [
        "rust_panic",
        "rustc version",
        "cargo",
        "std::panicking",
    ],
    "Delphi": [
        "borland",
        "delphi",
        "fastmm",
        "sharemem",
    ],
    "Java": [
        "java version",
        "javac",
        "jvm",
        "javax.",
        "java.lang",
    ],
}


# Extended inspection and optional-engine limits.
ENTROPY_SCAN_BYTES = 32 * 1024 * 1024
MAX_ENTROPY_REGIONS = 128
REGION_SCAN_BYTES = 16 * 1024 * 1024
MAX_REGION_BYTES = 2 * 1024 * 1024
MAX_REGIONS = 128
MAX_CHILD_PES = 32
MAX_CHILD_CANDIDATES = 256
MAX_METADATA_ITEMS = 512
MAX_METADATA_BYTES = 1024 * 1024
MAX_TOOL_OUTPUT = 16 * 1024 * 1024
MAX_TOOL_ITEMS = 1000
