#pragma once

#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdlib.h>
#include <wdf.h>
#include "Enums.h"

#define CB_PROCESS_TERMINATE 0x0001
#define CB_PROCESS_CREATE_PROCESS 0x0080
#define CB_PROCESS_DUP_HANDLE 0x0040

#define CB_THREAD_TERMINATE  0x0001

#define PROCESS_NAME_SIZE 200
#define IOCTL_STOP_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800 + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_START_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800 + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SEND_MESSAGE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800 + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PROCESS_SYSTEM_INFORMATION 5
#define POOL_TAG 'enoN'
#define START_PROTECTION_TAG "966139b8-8216-4034-872e-7268a92a18ef"
#define STOP_PROTECTION_TAG "f4ac987a-b8a3-4df1-a4c9-da9c2f0a5730"

#define PIPE_NAME L"\\\\.\\MyServicePipeTest"

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

PVOID ProcessRegistrationHandle;
NTSTATUS ProcCreateCloseCallback(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status = STATUS_SUCCESS, ULONG_PTR info = 0);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS RegisterCallbacks(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT DeviceObject);
OB_PREOP_CALLBACK_STATUS PreProcessHandleCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
VOID PsCreateProcessNotifyCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
NTSTATUS CheckProcessMatch(_In_ PCUNICODE_STRING pustrCommand, _In_ PEPROCESS Process, _In_ HANDLE ProcessId);
NTSTATUS HandleIoctl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS StopProtection(PDEVICE_OBJECT DeviceObject);
NTSTATUS StartProtection(PDEVICE_OBJECT DeviceObject);
NTSTATUS HandleCustomCommand(PDEVICE_OBJECT DeviceObject);
NTSTATUS GetProcessIdByName(PUNICODE_STRING ProcessName, HANDLE* ProcessId);
NTSTATUS GetProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);
NTSTATUS CheckIrpData(_In_ PIO_STACK_LOCATION irpStack, _In_ PIRP Irp, _In_ ProtectionEnum operationType);
NTSTATUS SendMessageToPipe();

extern "C"
NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

extern "C"
NTSTATUS PsLookupProcessByProcessId(_In_  HANDLE    ProcessId, _Out_ PEPROCESS* Process);