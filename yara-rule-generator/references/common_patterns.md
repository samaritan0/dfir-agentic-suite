# Common YARA Detection Patterns Reference

## Encryption Constants

### AES S-box (first 16 bytes)
```
{ 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
```

### AES inverse S-box (first 16 bytes)
```
{ 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }
```

### RSA public key header (PKCS#1)
```
{ 30 82 [2] 30 0D 06 09 2A 86 48 86 F7 0D 01 01 }
```

### RC4 key scheduling (init loop pattern)
```
{ 8A 04 ?? 88 04 ?? 8A 04 ?? 88 04 ?? }
```

### ChaCha20 constant "expand 32-byte k"
```
{ 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
```

## Process Injection Patterns

### Classic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
API sequence: three imports from kernel32.dll typically used together.

### NtCreateSection injection (syscall-based)
```
$ntcreate = "NtCreateSection"
$ntmap    = "NtMapViewOfSection"
$ntunmap  = "NtUnmapViewOfSection"
```

### APC injection
```
$queueapc = "QueueUserAPC"
$ntqueue  = "NtQueueApcThread"
```

## Anti-Analysis

### CPUID VM detection
```
{ 0F A2 }  // CPUID instruction, often followed by comparison against VM strings
```

### Common VM detection strings
```
$vm1 = "VMwareVMware" wide ascii
$vm2 = "VBoxGuest" wide ascii
$vm3 = "QEMU" wide ascii
$vm4 = "Xen" wide ascii
$vm5 = "SbieDll.dll" wide ascii  // Sandboxie
```

### Sleep-based evasion
```
$sleep1 = "kernel32.dll" wide ascii
$sleep2 = "Sleep" wide ascii
// Combined with large sleep values detected in condition
```

## Ransomware Patterns

### Common ransom note filenames
```
$note1 = "README" nocase wide
$note2 = "DECRYPT" nocase wide
$note3 = "RECOVER" nocase wide
$note4 = "RESTORE" nocase wide
$note5 = "HOW_TO" nocase wide
$note6 = "HELP_DECRYPT" nocase wide
```

### Bitcoin address patterns
```
$btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii wide
$btc2 = /bc1[a-zA-HJ-NP-Z0-9]{25,90}/ ascii
```

### Tor .onion addresses
```
$onion = /[a-z2-7]{16,56}\.onion/ nocase
```

## Persistence Mechanisms

### Registry Run keys
```
$run1 = "\\CurrentVersion\\Run" nocase wide
$run2 = "\\CurrentVersion\\RunOnce" nocase wide
$run3 = "\\Winlogon\\Shell" nocase wide
$run4 = "\\Explorer\\Shell Folders" nocase wide
```

### WMI event subscription
```
$wmi1 = "__EventFilter" wide
$wmi2 = "ActiveScriptEventConsumer" wide
$wmi3 = "__FilterToConsumerBinding" wide
```

## File Type Magic Bytes

### PE (MZ header)
```
condition: uint16(0) == 0x5A4D
```

### ELF
```
condition: uint32(0) == 0x464C457F
```

### Mach-O (both endianness + universal)
```
condition: uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xBEBAFECA
```

### Office OLE (DOC, XLS, PPT)
```
condition: uint32(0) == 0xE011CFD0
```

### Office OOXML (DOCX, XLSX, PPTX) — ZIP-based
```
condition: uint32(0) == 0x04034B50
```

### PDF
```
condition: uint32(0) == 0x46445025  // %PDF
```
