#include "Driver.h"
#include "Enums.h"

/// <summary>
/// Author: Can DOGU
/// A simple kernel driver for protecting user mode security endpoint applications
/// </summary>

WCHAR ProtectedProcessName[PROCESS_NAME_SIZE + 1] = { 0 };
PVOID ProtectedProcess = NULL;
HANDLE ProtectedProcessId = { 0 };
BOOLEAN IsProtected;

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = 0;

	DbgPrintEx(0, 0, "CANOMONSTER driver calismaya basladi :)\n");

	HANDLE processId;
	PEPROCESS process = nullptr;
	UNICODE_STRING processName;
	RtlInitUnicodeString(&processName, L"ElevationTest.exe");

	status = GetProcessIdByName(&processName, &processId);

	if (NT_SUCCESS(status))
	{
		uintptr_t handleValue = reinterpret_cast<uintptr_t>(processId);
		int intValue = static_cast<int>(handleValue);

		DbgPrintEx(0, 0, "Process PID: %d bulundu\n", intValue);

		status = GetProcessByProcessId(processId, &process);

		if (NT_SUCCESS(status))
		{
			ProtectedProcess = process;
			ProtectedProcessId = processId;
		}
	}

	wcscpy(ProtectedProcessName, L"ElevationTest");
	IsProtected = FALSE;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = ProcCreateCloseCallback;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = ProcCreateCloseCallback;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleIoctl;

	UNICODE_STRING name;
	RtlInitUnicodeString(&name, L"\\Device\\CANOMONSTER");
	PDEVICE_OBJECT DeviceObject;

	status = IoCreateDevice(DriverObject, 0, &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "Device olusturulamadi\n");
		return status;
	}

	DriverObject->DeviceObject = DeviceObject;
	DeviceObject->Flags |= DO_DIRECT_IO;

	UNICODE_STRING symlink;
	RtlInitUnicodeString(&symlink, L"\\??\\CANOMONSTER");

	status = IoCreateSymbolicLink(&symlink, &name);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "Device olusturulamadi\n");
		IoDeleteDevice(DeviceObject);
		return status;
	}

	status = PsSetCreateProcessNotifyRoutineEx(PsCreateProcessNotifyCallback, FALSE);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "PsSetCreateProcessNotifyRoutineEx callback kaydedilemedi\n");
		return status;
	}

	status = RegisterCallbacks(DriverObject, DeviceObject);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "ObRegisterCallbacks callback kaydedilemedi\n");
		return status;
	}

	SendMessageToPipe();

	return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	ObUnRegisterCallbacks(ProcessRegistrationHandle);

	PsSetCreateProcessNotifyRoutineEx(PsCreateProcessNotifyCallback, TRUE);

	UNICODE_STRING symlink;
	RtlInitUnicodeString(&symlink, L"\\??\\CANOMONSTER");
	IoDeleteSymbolicLink(&symlink);
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrintEx(0, 0, "CANOMONSTER driver sonlandi :(\n");
}

NTSTATUS CompleteRequest(PIRP Irp, NTSTATUS status, ULONG_PTR info)
{
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = info;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS ProcCreateCloseCallback(PDEVICE_OBJECT, PIRP Irp)
{
	DbgPrintEx(0, 0, "Create/Close istegi geldi\n");

	return CompleteRequest(Irp);
}

NTSTATUS HandleIoctl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

	DbgPrintEx(0, 0, "IOCTL istegi geldi\n");

	DbgPrintEx(0, 0, "IOCTL Code: 0x%x\n", irpStack->Parameters.DeviceIoControl.IoControlCode);

	switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_STOP_PROTECTION:
	{
		if (NT_SUCCESS(CheckIrpData(irpStack, Irp, UNPROTECT)))
		{
			DbgPrintEx(0, 0, "StopProtection request valid\n");

			status = StopProtection(DeviceObject);
		}
		else
		{
			DbgPrintEx(0, 0, "StopProtection request invalid\n");
		}

		break;
	}
	case IOCTL_START_PROTECTION:
	{
		if (NT_SUCCESS(CheckIrpData(irpStack, Irp, PROTECT)))
		{
			DbgPrintEx(0, 0, "StartProtection request valid\n");

			status = StartProtection(DeviceObject);
		}
		else
		{
			DbgPrintEx(0, 0, "StartProtection request invalid\n");
		}

		break;
	}
	default:
	{
		DbgPrintEx(0, 0, "Default\n");

		status = STATUS_INVALID_DEVICE_REQUEST;

		break;
	}
	}

	CompleteRequest(Irp, status, 0);

	return status;
}

NTSTATUS CheckIrpData(_In_ PIO_STACK_LOCATION irpStack, _In_ PIRP Irp, _In_ ProtectionEnum operationType)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

	UCHAR* inputData = (UCHAR*)Irp->AssociatedIrp.SystemBuffer;
	ULONG inputDataLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;

	if (!inputData || inputDataLength == 0)
	{
		return status;
	}

	inputData[inputDataLength] = '\0';

	while (*inputData && isspace(*inputData))
	{
		++inputData;
		--inputDataLength;
	}

	UCHAR* endPtr = inputData + inputDataLength - 1;
	while (endPtr >= inputData && isspace(*endPtr))
	{
		*endPtr-- = '\0';
		--inputDataLength;
	}

	DbgPrintEx(0, 0, "Gelen data: %s\n", inputData);

	switch (operationType)
	{
	case PROTECT:
	{
		if (strcmp((const char*)inputData, START_PROTECTION_TAG) == 0)
		{
			status = STATUS_SUCCESS;
		}

		break;
	}
	case UNPROTECT:
	{
		if (strcmp((const char*)inputData, STOP_PROTECTION_TAG) == 0)
		{
			status = STATUS_SUCCESS;
		}

		break;
	}
	}

	return status;
}

NTSTATUS StopProtection(PDEVICE_OBJECT DeviceObject)
{
	DeviceObject->DriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}

NTSTATUS StartProtection(PDEVICE_OBJECT DeviceObject)
{
	DeviceObject->DriverObject->DriverUnload = NULL;

	return STATUS_SUCCESS;
}

NTSTATUS HandleCustomCommand(PDEVICE_OBJECT DeviceObject)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	DbgPrintEx(0, 0, "IOCTL HancleCustomCommand metoduna iletildi\n");

	return STATUS_SUCCESS;
}

NTSTATUS RegisterCallbacks(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT DeviceObject)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(DriverObject);

	OB_CALLBACK_REGISTRATION CallbackRegistration{};
	OB_OPERATION_REGISTRATION OperationRegistrations[2]{};
	OperationRegistrations[0].ObjectType = PsProcessType;
	OperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
	OperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	OperationRegistrations[0].PreOperation = PreProcessHandleCallback;
	OperationRegistrations[0].PostOperation = PostProcessHandleCallback;

	OperationRegistrations[1].ObjectType = PsThreadType;
	OperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
	OperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
	OperationRegistrations[1].PreOperation = PreProcessHandleCallback;
	OperationRegistrations[1].PostOperation = PostProcessHandleCallback;

	UNICODE_STRING Altitude;
	RtlInitUnicodeString(&Altitude, L"1000");

	CallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
	CallbackRegistration.OperationRegistrationCount = 2;
	CallbackRegistration.Altitude = Altitude;
	CallbackRegistration.RegistrationContext = NULL;
	CallbackRegistration.OperationRegistration = OperationRegistrations;

	NTSTATUS status = ObRegisterCallbacks(&CallbackRegistration, &ProcessRegistrationHandle);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "ObRegisterCallbacks callback kaydedilemedi\n");
		return status;
	}

	return status;
}

VOID PostProcessHandleCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION PostOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(PostOperationInformation);

	DbgPrint("Post operation request.");
}

OB_PREOP_CALLBACK_STATUS PreProcessHandleCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	PACCESS_MASK DesiredAccess = NULL;
	ACCESS_MASK AccessBitsToClear = 0;
	ACCESS_MASK AccessBitsToSet = 0;
	ACCESS_MASK InitialDesiredAccess = 0;
	ACCESS_MASK OriginalDesiredAccess = 0;

	LPCWSTR ObjectTypeName = NULL;
	LPCWSTR OperationName = NULL;

	UNICODE_STRING commandLine;
	RtlInitEmptyUnicodeString(&commandLine, NULL, 0);

	if (OperationInformation->ObjectType == *PsProcessType)
	{
		PEPROCESS openedProcess = (PEPROCESS)OperationInformation->Object;
		HANDLE targetPID = PsGetProcessId(openedProcess);

		if (ProtectedProcess == NULL || targetPID != (HANDLE)ProtectedProcessId || targetPID == PsGetCurrentProcessId())
		{
			goto Exit;
		}

		if (!IsProtected)
		{
			uintptr_t handleValue = reinterpret_cast<uintptr_t>(ProtectedProcessId);
			int intValue = static_cast<int>(handleValue);

			DbgPrintEx(0, 0, "PID: %d, ProcessName: %ls korumaya aliniyor\n", intValue, ProtectedProcessName);
		}

		AccessBitsToClear = CB_PROCESS_TERMINATE | CB_PROCESS_CREATE_PROCESS | CB_PROCESS_DUP_HANDLE;
		ObjectTypeName = L"PsProcessType";

		switch (OperationInformation->Operation) {
		case OB_OPERATION_HANDLE_CREATE:
			DesiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
			OriginalDesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
			OperationName = L"OB_OPERATION_HANDLE_CREATE";
			IsProtected = TRUE;
			break;
		case OB_OPERATION_HANDLE_DUPLICATE:
			DesiredAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
			OriginalDesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
			OperationName = L"OB_OPERATION_HANDLE_DUPLICATE";
			IsProtected = TRUE;
			break;
		default:
			goto Exit;
		}
	}
	else if (OperationInformation->ObjectType == *PsThreadType)
	{
		HANDLE targetPID = PsGetThreadProcessId((PETHREAD)OperationInformation->Object);

		if (ProtectedProcess == NULL || targetPID != (HANDLE)ProtectedProcessId || targetPID == PsGetCurrentProcessId())
		{
			goto Exit;
		}

		AccessBitsToClear = CB_THREAD_TERMINATE ;
		ObjectTypeName = L"PsThreadType";

		switch (OperationInformation->Operation) {
		case OB_OPERATION_HANDLE_CREATE:
			DesiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
			OriginalDesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
			OperationName = L"OB_OPERATION_HANDLE_CREATE";
			IsProtected = TRUE;
			break;
		case OB_OPERATION_HANDLE_DUPLICATE:
			DesiredAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
			OriginalDesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
			OperationName = L"OB_OPERATION_HANDLE_DUPLICATE";
			IsProtected = TRUE;
			break;
		default:
			goto Exit;
		}
	}
	else
	{
		goto Exit;
	}

	AccessBitsToSet = 0;

	InitialDesiredAccess = *DesiredAccess;

	if (OperationInformation->KernelHandle != 1 && DesiredAccess != NULL)
	{
		*DesiredAccess &= ~AccessBitsToClear;
		*DesiredAccess |= AccessBitsToSet;
	}

	/*if (DesiredAccess != NULL)
	{
		*DesiredAccess &= ~AccessBitsToClear;
		*DesiredAccess |= AccessBitsToSet;

		DbgPrintEx(0, 0,
			"ObCallbackTest: CBTdPreOperationCallback\n"
			"    Client Id:    %p:%p\n"
			"    Object:       %p\n"
			"    Type:         %ls\n"
			"    Operation:    %ls (KernelHandle=%d)\n"
			"    OriginalDesiredAccess: 0x%x\n"
			"    DesiredAccess (in):    0x%x\n"
			"    DesiredAccess (out):   0x%x\n",
			PsGetCurrentProcessId(),
			PsGetCurrentThreadId(),
			OperationInformation->Object,
			ObjectTypeName,
			OperationName,
			OperationInformation->KernelHandle,
			OriginalDesiredAccess,
			InitialDesiredAccess,
			*DesiredAccess
		);
	}*/
Exit:
	return OB_PREOP_SUCCESS;
}

VOID PsCreateProcessNotifyCallback(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId, _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo && CreateInfo->CommandLine != NULL)
	{
		NTSTATUS processMatchStatus = CheckProcessMatch(CreateInfo->CommandLine, Process, ProcessId);

		if (processMatchStatus == STATUS_SUCCESS)
		{
			uintptr_t handleValue = reinterpret_cast<uintptr_t>(ProcessId);
			int intValue = static_cast<int>(handleValue);

			DbgPrintEx(0, 0, "PROCESS UYUMLU! PID: %d, KAYNAK: %wZ / HEDEF: %ls\n", intValue, CreateInfo->ImageFileName, ProtectedProcessName);
		}
	}
}

NTSTATUS CheckProcessMatch(_In_ PCUNICODE_STRING pustrCommand, _In_ PEPROCESS Process, _In_ HANDLE ProcessId)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	WCHAR   CommandLineBuffer[PROCESS_NAME_SIZE + 1] = { 0 };
	USHORT  CommandLineBytes = 0;

	if (!pustrCommand || !pustrCommand->Buffer)
	{
		Status = FALSE;
		goto Exit;
	}

	if (pustrCommand->Length < (PROCESS_NAME_SIZE * sizeof(WCHAR)))
	{
		CommandLineBytes = pustrCommand->Length;
	}
	else
	{
		CommandLineBytes = PROCESS_NAME_SIZE * sizeof(WCHAR);
	}

	if (CommandLineBytes)
	{
		memcpy(CommandLineBuffer, pustrCommand->Buffer, CommandLineBytes);

		if (NULL != wcsstr(CommandLineBuffer, ProtectedProcessName))
		{
			ProtectedProcess = Process;
			ProtectedProcessId = ProcessId;

			Status = STATUS_SUCCESS;
		}
	}
	else
	{
		Status = FALSE;
	}
Exit:
	return Status;
}

NTSTATUS GetProcessIdByName(PUNICODE_STRING ProcessName, HANDLE* ProcessId)
{
	NTSTATUS status;
	PSYSTEM_PROCESS_INFORMATION processInfo, nextProcessInfo;
	ULONG bufferSize = 0;

	status = ZwQuerySystemInformation(PROCESS_SYSTEM_INFORMATION, NULL, 0, &bufferSize);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
	{
		return status;
	}

	if (bufferSize)
	{
		PVOID memory = ExAllocatePool2(POOL_FLAG_PAGED, bufferSize, POOL_TAG);

		if (!memory)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		status = ZwQuerySystemInformation(PROCESS_SYSTEM_INFORMATION, memory, bufferSize, &bufferSize);

		if (!NT_SUCCESS(status))
		{
			ExFreePoolWithTag(memory, POOL_TAG);
			return status;
		}

		processInfo = (PSYSTEM_PROCESS_INFORMATION)memory;

		while (processInfo->NextEntryOffset != 0)
		{
			if (RtlEqualUnicodeString(&processInfo->ImageName, ProcessName, TRUE))
			{
				*ProcessId = processInfo->ProcessId;
				ExFreePoolWithTag(memory, POOL_TAG);
				return STATUS_SUCCESS;
			}

			nextProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
			processInfo = nextProcessInfo;
		}

		ExFreePoolWithTag(memory, POOL_TAG);
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS GetProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process)
{
	NTSTATUS status = PsLookupProcessByProcessId(ProcessId, Process);

	return status;
}

NTSTATUS SendMessageToPipe()
{
	UNICODE_STRING pipeName;
	RtlInitUnicodeString(&pipeName, PIPE_NAME);

	IO_STATUS_BLOCK ioStatus;
	OBJECT_ATTRIBUTES objectAttributes{};
	InitializeObjectAttributes(&objectAttributes, &pipeName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	HANDLE pipeHandle;
	NTSTATUS status = ZwCreateFile(&pipeHandle, SYNCHRONIZE | FILE_WRITE_DATA, &objectAttributes, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, 0, NULL, 0);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "Pipe acilamadi\n");
		return status;
	}

	WCHAR message[] = L"Hello from kernel mode!";
	ULONG messageLength = sizeof(message);

	status = ZwWriteFile(pipeHandle, NULL, NULL, NULL, &ioStatus, message, messageLength, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "Pipe mesaj gonderilemedi\n");
	}

	ZwClose(pipeHandle);

	return status;
}