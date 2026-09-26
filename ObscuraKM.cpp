#include "ObscuraKM.h"
#include <ntimage.h>

namespace obscura {

namespace registry {

    namespace {
        NTSTATUS WriteDword(HANDLE keyHandle, const wchar_t* valueName, ULONG data) {
            UNICODE_STRING unicodeName{};
            RtlInitUnicodeString(&unicodeName, valueName);
            return ZwSetValueKey(keyHandle, &unicodeName, 0, REG_DWORD, &data, sizeof(data));
        }

        HANDLE OpenOrCreateKey(const wchar_t* keyPath) {
            UNICODE_STRING unicodePath{};
            RtlInitUnicodeString(&unicodePath, keyPath);

            OBJECT_ATTRIBUTES attributes{};
            InitializeObjectAttributes(&attributes, &unicodePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

            HANDLE keyHandle{ nullptr };
            NTSTATUS status = ZwOpenKey(&keyHandle, KEY_SET_VALUE, &attributes);
            if (!NT_SUCCESS(status)) {
                ULONG disposition{ 0 };
                status = ZwCreateKey(&keyHandle, KEY_SET_VALUE, &attributes, 0, nullptr, REG_OPTION_NON_VOLATILE, &disposition);
            }

            return NT_SUCCESS(status) ? keyHandle : nullptr;
        }
    }

    NTSTATUS Initialize() {
        const HANDLE stateKey = OpenOrCreateKey(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
        if (!stateKey) {
            return STATUS_UNSUCCESSFUL;
        }

        (void)WriteDword(stateKey, L"UEFISecureBootEnabled", 1);
        (void)WriteDword(stateKey, L"SecureBootCapable", 1);
        ZwClose(stateKey);

        const HANDLE servicingKey = OpenOrCreateKey(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\Servicing");
        if (servicingKey) {
            (void)WriteDword(servicingKey, L"DeviceAttributes", 1);
            ZwClose(servicingKey);
        }

        return STATUS_SUCCESS;
    }

    void Cleanup() {}

} 

namespace firmware {

    namespace {
        constexpr GUID EfiGlobalGuid = {
            0x8BE4DF61, 0x93CA, 0x11D2,
            { 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C }
        };

        constexpr GUID EfiSecureBootEnableGuid = {
            0xF0A30BC7, 0xAF08, 0x4556,
            { 0x99, 0xC4, 0x00, 0x10, 0x09, 0xC9, 0x3A, 0x44 }
        };

        struct VariableOverride {
            const wchar_t* Name;
            const GUID* VendorGuid;
            UCHAR SpoofedValue;
        };

        constexpr VariableOverride VariableOverrides[] = {
            { L"SecureBoot",       &EfiGlobalGuid,           1 },
            { L"SetupMode",        &EfiGlobalGuid,           0 },
            { L"AuditMode",        &EfiGlobalGuid,           0 },
            { L"DeployedMode",     &EfiGlobalGuid,           1 },
            { L"SecureBootEnable", &EfiSecureBootEnableGuid, 1 },
        };

        using FnQueryFirmwareEnvironmentVariable = NTSTATUS(NTAPI*)(
            PUNICODE_STRING VariableName,
            LPGUID VendorGuid,
            PVOID Value,
            PULONG ValueLength,
            PULONG Attributes
        );

        FnQueryFirmwareEnvironmentVariable OriginalQueryRoutine{ nullptr };
        PMDL MdlInstance{ nullptr };
        UCHAR OriginalPreambleBytes[12]{};

        NTSTATUS NTAPI QueryFirmwareHook(
            PUNICODE_STRING VariableName,
            LPGUID VendorGuid,
            PVOID Value,
            PULONG ValueLength,
            PULONG Attributes
        ) {
            if (VariableName && VendorGuid && Value && ValueLength) {
                for (const auto& overrideEntry : VariableOverrides) {
                    if (RtlCompareMemory(VendorGuid, overrideEntry.VendorGuid, sizeof(GUID)) != sizeof(GUID)) {
                        continue;
                    }

                    UNICODE_STRING targetName{};
                    RtlInitUnicodeString(&targetName, overrideEntry.Name);

                    if (!RtlEqualUnicodeString(VariableName, &targetName, TRUE)) {
                        continue;
                    }

                    if (*ValueLength < 1) {
                        break;
                    }

                    *static_cast<PUCHAR>(Value) = overrideEntry.SpoofedValue;
                    *ValueLength = 1;

                    if (Attributes) {
                        *Attributes = 0x6;
                    }

                    return STATUS_SUCCESS;
                }
            }

            return OriginalQueryRoutine(VariableName, VendorGuid, Value, ValueLength, Attributes);
        }

        PVOID FindPattern(PUCHAR baseAddress, ULONG regionSize, const UCHAR* patternBytes, ULONG patternLength) {
            for (ULONG i = 0; i + patternLength <= regionSize; ++i) {
                bool matchFound = true;

                for (ULONG j = 0; j < patternLength; ++j) {
                    if (patternBytes[j] != 0x00 && baseAddress[i + j] != patternBytes[j]) {
                        matchFound = false;
                        break;
                    }
                }

                if (matchFound) {
                    return baseAddress + i;
                }
            }

            return nullptr;
        }

        PVOID LocateKernelBase(PVOID systemRoutineAddress) {
            const auto target = static_cast<PUCHAR>(systemRoutineAddress);
            auto currentAddress = reinterpret_cast<PUCHAR>(reinterpret_cast<ULONG_PTR>(systemRoutineAddress) & ~static_cast<ULONG_PTR>(0xFFF));

            for (int i = 0; i < 0x10000; ++i, currentAddress -= 0x1000) {
                if (!MmIsAddressValid(currentAddress)) {
                    continue;
                }

                if (*reinterpret_cast<PUSHORT>(currentAddress) != 0x5A4D) {
                    continue;
                }

                const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(currentAddress);
                if (dosHeader->e_lfanew <= 0 || dosHeader->e_lfanew >= 0x1000) {
                    continue;
                }

                if (!MmIsAddressValid(currentAddress + dosHeader->e_lfanew)) {
                    continue;
                }

                if (*reinterpret_cast<PULONG>(currentAddress + dosHeader->e_lfanew) != 0x00004550) {
                    continue;
                }

                const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(currentAddress + dosHeader->e_lfanew);
                if (target >= currentAddress && target < currentAddress + ntHeaders->OptionalHeader.SizeOfImage) {
                    return currentAddress;
                }
            }

            return nullptr;
        }

        NTSTATUS ApplyKernelGlobalPatch(PVOID kernelBaseAddress) {
            if (!kernelBaseAddress) {
                return STATUS_NOT_FOUND;
            }

            const auto dosHeader = static_cast<PIMAGE_DOS_HEADER>(kernelBaseAddress);
            const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(static_cast<PUCHAR>(kernelBaseAddress) + dosHeader->e_lfanew);
            const ULONG imageSize = ntHeaders->OptionalHeader.SizeOfImage;

            static constexpr UCHAR Signature[] = {
                0x8A, 0x05, 0x00, 0x00, 0x00, 0x00,
                0x24, 0x01, 0x88, 0x02,
                0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
                0xC1, 0xE8, 0x03, 0x24, 0x01, 0x88, 0x42, 0x01
            };

            const auto matchAddress = static_cast<PUCHAR>(FindPattern(static_cast<PUCHAR>(kernelBaseAddress), imageSize, Signature, sizeof(Signature)));
            if (!matchAddress) {
                return STATUS_NOT_FOUND;
            }

            const INT32 relativeDisplacement = *reinterpret_cast<INT32*>(matchAddress + 2);
            const auto flagsPointer = reinterpret_cast<PULONG>(matchAddress + 6 + relativeDisplacement);

            if (!MmIsAddressValid(flagsPointer)) {
                return STATUS_UNSUCCESSFUL;
            }

            *flagsPointer |= 0x09;
            return STATUS_SUCCESS;
        }

        PVOID LocateTargetQueryRoutine(PVOID kernelBaseAddress) {
            if (!kernelBaseAddress) {
                return nullptr;
            }

            const auto dosHeader = static_cast<PIMAGE_DOS_HEADER>(kernelBaseAddress);
            const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(static_cast<PUCHAR>(kernelBaseAddress) + dosHeader->e_lfanew);
            const ULONG imageSize = ntHeaders->OptionalHeader.SizeOfImage;

            static constexpr UCHAR Signature[] = {
                0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
                0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00,
                0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00,
                0x48, 0x33, 0xC4,
                0x48, 0x89, 0x44, 0x24, 0x78,
                0x4D, 0x8B, 0xE1,
                0x4D, 0x8B, 0xF8,
                0x4C, 0x8B, 0xF2,
                0x48, 0x8B, 0xF9
            };

            return FindPattern(static_cast<PUCHAR>(kernelBaseAddress), imageSize, Signature, sizeof(Signature));
        }
    }

    NTSTATUS Initialize() {
        UNICODE_STRING routineName{};
        RtlInitUnicodeString(&routineName, L"ExAllocatePool2");
        PVOID systemRoutine = MmGetSystemRoutineAddress(&routineName);

        PVOID kernelBase = LocateKernelBase(systemRoutine);
        NTSTATUS patchStatus = ApplyKernelGlobalPatch(kernelBase);

        SharedUserData->DbgSecureBootEnabled = 1;

        PVOID targetFunction = LocateTargetQueryRoutine(kernelBase);
        if (!targetFunction) {
            return NT_SUCCESS(patchStatus) ? STATUS_SUCCESS : patchStatus;
        }

        if (*reinterpret_cast<PUSHORT>(targetFunction) == 0xB848) {
            return NT_SUCCESS(patchStatus) ? STATUS_SUCCESS : patchStatus;
        }

        const auto trampolinePool = static_cast<PUCHAR>(ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, 24, 'FWsb'));
        if (!trampolinePool) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(OriginalPreambleBytes, targetFunction, 12);
        RtlCopyMemory(trampolinePool, OriginalPreambleBytes, 12);

        PUCHAR jumpBlock = trampolinePool + 12;
        jumpBlock[0] = 0x48;
        jumpBlock[1] = 0xB8;
        *reinterpret_cast<PVOID*>(jumpBlock + 2) = static_cast<PUCHAR>(targetFunction) + 12;
        jumpBlock[10] = 0xFF;
        jumpBlock[11] = 0xE0;

        OriginalQueryRoutine = reinterpret_cast<FnQueryFirmwareEnvironmentVariable>(trampolinePool);

        MdlInstance = IoAllocateMdl(targetFunction, 12, FALSE, FALSE, nullptr);
        if (!MdlInstance) {
            ExFreePool(trampolinePool);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        MmBuildMdlForNonPagedPool(MdlInstance);
        PVOID writableAddress = MmMapLockedPagesSpecifyCache(
            MdlInstance, KernelMode, MmNonCached, nullptr, FALSE,
            NormalPagePriority | MdlMappingNoExecute
        );

        if (!writableAddress) {
            IoFreeMdl(MdlInstance);
            MdlInstance = nullptr;
            ExFreePool(trampolinePool);
            return STATUS_UNSUCCESSFUL;
        }

        UCHAR detourBuffer[12] = { 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0 };
        *reinterpret_cast<PVOID*>(detourBuffer + 2) = reinterpret_cast<PVOID>(QueryFirmwareHook);

        RtlCopyMemory(writableAddress, detourBuffer, 12);
        MmUnmapLockedPages(writableAddress, MdlInstance);

        return STATUS_SUCCESS;
    }

    void Cleanup() {
        if (!MdlInstance || !OriginalQueryRoutine) {
            return;
        }

        PVOID writableAddress = MmMapLockedPagesSpecifyCache(
            MdlInstance, KernelMode, MmNonCached, nullptr, FALSE,
            NormalPagePriority | MdlMappingNoExecute
        );

        if (writableAddress) {
            RtlCopyMemory(writableAddress, OriginalPreambleBytes, 12);
            MmUnmapLockedPages(writableAddress, MdlInstance);
        }

        IoFreeMdl(MdlInstance);
        MdlInstance = nullptr;
    }

} 

} 

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING) {
    (void)obscura::registry::Initialize();
    (void)obscura::firmware::Initialize();
    return STATUS_SUCCESS;
}
