---
layout: post
title: "EDR as a rootkit (OpenEDR)"
categories: research
tags: ikerl research pwn openedr
date: 2024-02-22 8:00:00 +0100
author: ikerl
---

## Introduction

Over the past few months, I have been working with a very interesting open source EDR called [OpenEDR](https://www.openedr.com/). As a Red Team operator, I have spent a significant amount of time evading EDRs over the past few years, so this project caught my interest. OpenEDR is developed and maintained by [Xcytium](https://www.xcitium.com/) (formerly known as COMODO) and is an open source EDR fully equipped with advanced modules such as minidrivers (for network and registry monitoring), DLL injection technology for hooking Windows API calls from the kernel and support for behavioral rules. Personally, the published source code has proven to be incredibly valuable in helping me understand and learn in depth how commercial and professional EDRs work. The project is designed for ease of compilation, allowing developers to modify and customize it to their preferences.


## Vulnerabilities found

After spending several days reviewing the source code and learning new concepts, I discovered some security flaws in the DLL injector module of the EDR driver. This module is responsible for loading a hooking DLL, from kerneland, into all monitored processes to intercept interesting Windows API calls and collect this information. To accomplish this, the driver uses kernel callbacks to receive notifications when a new process is created and, at that time, initiate DLL injection process.


During testing of the precompiled version of OpenEDR available on GitHub and the commercial version accessible on the [cloud platform](https://openedr.platform.xcitium.com), I noticed that the driver does not verify the signature of the DLL used during the driver's hook injection phase. This means that an attacker could exploit this vulnerability to replace the original DLL with a malicious one and force the OpenEDR driver to use it to execute malicious code in any monitored process, compromising the integrity and confidentiality of the entire computer.


OpenEDR incorporates some anti-tampering technologies to mitigate attacks against the EDR. For example, EDR protects the installation path against tampering while the EDR service is running. 
However, EDR first looks for the DLL it uses to inject into processes in the System32 folder and this DLL is not properly protected against modification and replacement. Unfortunately, it is still possible to rename the original injecting DLL in the System32 folder and replace it with a malicious one. Consequently, with each subsequent process creation, the EDR driver would inject the malicious DLL in place of the originally renamed DLL each time a new process is monitored. The affected DLLs are `edrpm64.dll` and `edrpm32.dll` located in the `System32` and `SysWOW64` folders.

Therefore, these would be the two vulnerabilities I have identified:

1. **Unsigned DLL Loading in the Injector Module**: The EDR's injector driver loads specific DLLs into monitored processees to hook certain Windows APIs. However, the driver does not check the loaded DLLs' signatures at all. This allows an attacker with high integrity privileges to use this legitimate driver, signed by Comodo, to load a malicious DLLs and perform userland hooking.
2. **DLL Hijacking in the Injector Module**: The injector driver searches for DLLs to inject into the monitored processes in a predefined list of paths in priority order. The issue stems from the fact that, even though the second of these paths is properly protected, the first is not. This allows a user with high integrity privileges to drop a malicious DLL into this path, or overwrite a legitimate DLL in such path.

These vulnerabilities were reported to the manufacturer on 06/29/2023 and to date no response has been received. Therefore, this disclosure is made after the expiration of the embargo period. It is important to mention that the exploitation of these vulnerabilities requires prior administrator privileges to be able to modify the affected DLLs. They are not a way to escalate privileges in the system but they completely compromise the confidentiality of the information of the monitored processes.


## Code review

This EDR supports two different injection techniques:

1. **IAT hooking**: This technique involves intercepting calls to imported functions in the Import Address Table (IAT).
2. **APC injection**: This technique allows for the injection of malicious code via asynchronous procedure calls.

Upon closer examination, we note that only the IAT hooking technique uses the implemented `isDllVerified()` function, which verifies the signature level of the injectable DLL. In contrast, the APC injector lacks any signature level verification process. This point is important because the latest versions of the tool use this second injector.

In the following code snippet, you can see the DLL verification function for the IAT injector:

```c
NTSTATUS IatInjector::addNewImportedDlls(ULONG ProcessId)
{
	ProcObjectPtr processObject;
	IFERR_RET_NOLOG(PsLookupProcessByProcessId(UlongToHandle(ProcessId), &processObject));

	if (!isAllowDllInjection(processObject, ProcessId))
		return LOGERROR(STATUS_CONTENT_BLOCKED, "Disallow DLLs injection into process <%d>\r\n", ProcessId);

	bool dllSignedProperly = false;
	IFERR_RET(Injector::isDllVerified(dllSignedProperly));

	if (!dllSignedProperly)
		return LOGERROR(STATUS_CONTENT_BLOCKED, "Can't inject DLLs into process <%d>, invalid required signing level\r\n", ProcessId);

	AttachToProcess attach(processObject);
	IFERR_RET_NOLOG(addNewImportedDlls(ZwCurrentProcess(), PsGetProcessSectionBaseAddress(processObject)));

	return STATUS_SUCCESS;
}
```

The function `isDllVerified()` then calls `getModuleSignatureLevel()`, which ultimately utilizes the functions `ntSetCachedSigningLevel()` and `seGetCachedSigningLevel()` to verify the signature level of the injectable DLL and determine whether it can be used, based on the minimum signature level configured during the driver compilation.

At this point, I considered developing a security patch by simply copying the `isDllVerified()` call from the IAT injector and incorporating it into the APC injector. In this way, the injector would verify the integrity and legitimacy of the injectable DLL in new versions of OpenEDR that use the APC technique.

I set up the lab to compile and debug the driver to check the functionality of the injectors and validate my patch. Unfortunately, I noticed that the `isDllVerified()` function does not work correctly on either Windows 10 or Windows 7. I suspect that this is the reason why this validation is not performed in APC injection mode, and consequently has been removed in newer versions using this hooking technique. The Windows documentation also does not help much to understand why `ntSetCachedSigningLevel()` and `seGetCachedSigningLevel()` aren't behaving as expected. Consequently, I had to give up on the patch.

Finally, I am not sure why this DLL verification function is still present in the code when it does not seem to be used in any case. I have received no response from Xcititum so it will remain a mystery.

## Mitigations

These are some of the recommendations for the manufacturer to mitigate the identified vulnerabilities and improve the security of its product:

- The EDR's injector module should only load signed and trusted DLLs. The function that verifies the legitimacy of the DLL to be injected should be reprogrammed to work correctly in current versions of Windows.
- Change the order of the DLL search paths, so that the first one to be searched (`C:\Program Files\COMODOEdrAgentV2`) is the one that is properly protected, and only use the unprotected path (`C:\Windows\System32`) as an alternative.

## Conclusions

Here are the conclusions of this research:

- It is crucial to be cautious with tools that inject monitoring DLLs into other processes. If the injected DLLs are not adequately protected, and their signature levels are not verified during loading, an adversary could manipulate them to achieve persistence in the system, inject into sensitive processes, or evade security systems.
- Unlike OpenEDR, it has been observed that the evaluated AV and EDR solutions (Bitdefender, Avast, AVG, Panda EDR, and Trend Micro EDR) correctly protect the DLLs used for injection into processes.
- It is concluded that OpenEDR lacks any functional verification of the signature level of the DLL it uses for injection.
- During the study, other programs and functionalities were identified that allow the use of this technique for a driver to inject malicious DLLs into monitored processes. For example, Lakeside Software's tool used for measuring user experience, Microsoft's AppInit functionality, and Vmware's vmtools (which inject `vm3dum64.dll` and `vm3dum64_10.dll`).


Finally, we would like to thank Xcitium for their commitment to open source software and for publishing this interesting tool. 