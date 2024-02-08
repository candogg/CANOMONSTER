#pragma once

#include <ntddk.h>

#define CB_PROCESS_TERMINATE 0x0001
#define CB_PROCESS_CREATE_PROCESS 0x0080
#define CB_THREAD_TERMINATE  0x0001
#define PROCESS_NAME_SIZE 200
#define IOCTL_CUSTOM_COMMAND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x222000, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_STOP_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x222003, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
NTSTATUS HandleCustomCommand(PDEVICE_OBJECT DeviceObject);