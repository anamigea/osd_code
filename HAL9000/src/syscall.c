#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "mmu.h"
#include "process_internal.h"
#include "dmp_cpu.h"
#include "thread.h"
#include "iomu.h"

extern void SyscallEntry();

#define SYSCALL_IF_VERSION_KM       SYSCALL_IMPLEMENTED_IF_VERSION

void
SyscallHandler(
	INOUT   COMPLETE_PROCESSOR_STATE* CompleteProcessorState
)
{
	SYSCALL_ID sysCallId;
	PQWORD pSyscallParameters;
	PQWORD pParameters;
	STATUS status;
	REGISTER_AREA* usermodeProcessorState;

	ASSERT(CompleteProcessorState != NULL);

	// It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
	// The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
	// that stack. This is why we only enable interrupts here.
	ASSERT(CpuIntrGetState() == INTR_OFF);
	CpuIntrSetState(INTR_ON);

	LOG_TRACE_USERMODE("The syscall handler has been called!\n");

	status = STATUS_SUCCESS;
	pSyscallParameters = NULL;
	pParameters = NULL;
	usermodeProcessorState = &CompleteProcessorState->RegisterArea;

	__try
	{
		if (LogIsComponentTraced(LogComponentUserMode))
		{
			DumpProcessorState(CompleteProcessorState);
		}

		// Check if indeed the shadow stack is valid (the shadow stack is mandatory)
		pParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp];
		status = MmuIsBufferValid(pParameters, SHADOW_STACK_SIZE, PAGE_RIGHTS_READ, GetCurrentProcess());
		if (!SUCCEEDED(status))
		{
			LOG_FUNC_ERROR("MmuIsBufferValid", status);
			__leave;
		}

		sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

		LOG_TRACE_USERMODE("System call ID is %u\n", sysCallId);

		// The first parameter is the system call ID, we don't care about it => +1
		pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

		// Dispatch syscalls
		switch (sysCallId)
		{
		case SyscallIdIdentifyVersion:
			status = SyscallValidateInterface((SYSCALL_IF_VERSION)*pSyscallParameters);
			break;
			// STUDENT TODO: implement the rest of the syscalls
		case SyscallIdThreadExit:
			status = SyscallThreadExit(
				(STATUS)pSyscallParameters[0]
			);
			break;
		case SyscallIdFileWrite:
			status = SyscallFileWrite(
				(UM_HANDLE)pSyscallParameters[0],
				(PVOID)pSyscallParameters[1],
				(QWORD)pSyscallParameters[2],
				(QWORD*)pSyscallParameters[3]
			);
			break;
		case SyscallIdProcessExit:
			status = SyscallProcessExit(
				(STATUS)pSyscallParameters[0]
			);
			break;
		case SyscallIdProcessCreate:
			status = SyscallProcessCreate(
				(char*)pSyscallParameters[0],
				(QWORD)pSyscallParameters[1],
				(char*)pSyscallParameters[2],
				(QWORD)pSyscallParameters[3],
				(UM_HANDLE*)pSyscallParameters[4]
			);
			break;
		case SyscallIdProcessCloseHandle:
			status = SyscallProcessCloseHandle(
				(UM_HANDLE)pSyscallParameters[0]
			);
			break;
		case SyscallIdProcessGetPid:
			status = SyscallProcessGetPid(
				(UM_HANDLE)pSyscallParameters[0],
				(PID*)pSyscallParameters[1]
			);
			break;
		case SyscallIdProcessWaitForTermination:
			status = SyscallProcessWaitForTermination(
				(UM_HANDLE)pSyscallParameters[0],
				(STATUS*)pSyscallParameters[1]
			);
			break;
		case SyscallIdFileCreate:
			status = SyscallFileCreate(
				(char*)pSyscallParameters[0],
				(QWORD)pSyscallParameters[1],
				(BOOLEAN)pSyscallParameters[2],
				(BOOLEAN)pSyscallParameters[3],
				(UM_HANDLE*)pSyscallParameters[4]
			);
			break;
		case SyscallIdFileRead:
			status = SyscallFileRead(
				(UM_HANDLE)pSyscallParameters[0],
				(PVOID)pSyscallParameters[1],
				(QWORD)pSyscallParameters[2],
				(QWORD*)pSyscallParameters[3]
			);
			break;
		case SyscallIdFileClose:
			status = SyscallFileClose(
				(UM_HANDLE)pSyscallParameters[0]
			);
			break;
		default:
			LOG_ERROR("Unimplemented syscall called from User-space!\n");
			status = STATUS_UNSUPPORTED;
			break;
		}

	}
	__finally
	{
		LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

		usermodeProcessorState->RegisterValues[RegisterRax] = status;

		CpuIntrSetState(INTR_OFF);
	}
}

void
SyscallPreinitSystem(
	void
)
{

}

STATUS
SyscallInitSystem(
	void
)
{
	return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
	void
)
{
	return STATUS_SUCCESS;
}

void
SyscallCpuInit(
	void
)
{
	IA32_STAR_MSR_DATA starMsr;
	WORD kmCsSelector;
	WORD umCsSelector;

	memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

	kmCsSelector = GdtMuGetCS64Supervisor();
	ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

	umCsSelector = GdtMuGetCS32Usermode();
	/// DS64 is the same as DS32
	ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
	ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

	// Syscall RIP <- IA32_LSTAR
	__writemsr(IA32_LSTAR, (QWORD)SyscallEntry);

	LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD)SyscallEntry);

	// Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
	__writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

	LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

	// Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
	// Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
	starMsr.SyscallCsDs = kmCsSelector;

	// Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
	// Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
	starMsr.SysretCsDs = umCsSelector;

	__writemsr(IA32_STAR, starMsr.Raw);

	LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

// SyscallIdIdentifyVersion
STATUS
SyscallValidateInterface(
	IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
	LOG_TRACE_USERMODE("Will check interface version 0x%x from UM against 0x%x from KM\n",
		InterfaceVersion, SYSCALL_IF_VERSION_KM);

	if (InterfaceVersion != SYSCALL_IF_VERSION_KM)
	{
		LOG_ERROR("Usermode interface 0x%x incompatible with KM!\n", InterfaceVersion);
		return STATUS_INCOMPATIBLE_INTERFACE;
	}

	return STATUS_SUCCESS;
}

// STUDENT TODO: implement the rest of the syscalls
STATUS
SyscallFileWrite(
	IN  UM_HANDLE                   FileHandle,
	IN_READS_BYTES(BytesToWrite)
	PVOID                           Buffer,
	IN  QWORD                       BytesToWrite,
	OUT QWORD* BytesWritten
)
{
	UNREFERENCED_PARAMETER(BytesWritten);
	UNREFERENCED_PARAMETER(BytesToWrite);
	UNREFERENCED_PARAMETER(Buffer);


	*BytesWritten = (QWORD)strlen((char*)Buffer) + 1; 
	if (FileHandle == UM_FILE_HANDLE_STDOUT && GetCurrentProcess()->OwnObjectInfo->StdoutOpen == 1) {
		LOG("[%s]:[%s]\n", ProcessGetName(NULL), Buffer);
		return STATUS_SUCCESS;
	}

	return STATUS_NO_HANDLING_REQUIRED;
}

STATUS
SyscallProcessExit(
	IN      STATUS                  ExitStatus
)
{
	PPROCESS currentProcess = GetCurrentProcess();
	if (currentProcess == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	currentProcess->TerminationStatus = ExitStatus;
	ProcessTerminate(currentProcess);

	return currentProcess->TerminationStatus;
}

STATUS
SyscallProcessCreate(
	IN_READS_Z(PathLength)   char* ProcessPath,
	IN          QWORD               PathLength,
	IN_READS_OPT_Z(ArgLength) char* Arguments,
	IN          QWORD               ArgLength,
	OUT         UM_HANDLE*          ProcessHandle
) 
{
	UNREFERENCED_PARAMETER(ArgLength);

	if (PathLength < 1) {
		return STATUS_INVALID_PARAMETER2;
	}
	if (ProcessPath == NULL) {
		return STATUS_INVALID_PARAMETER1;
	}

	char finalPath[260];
	//compiler will give an error for '\' -> needs to be replaced with '\\'
	char partition[30];
	strcpy(partition, IomuGetSystemPartitionPath());
	if (strchr(ProcessPath, '\\') == ProcessPath) {
		sprintf(finalPath, "%sApplications\\%s", partition, ProcessPath);
	}
	else {
		sprintf(finalPath, "%s", ProcessPath);
	}


	PPROCESS currentProcess;
	currentProcess = GetCurrentProcess();
	PPROCESS newProcess;


	STATUS statusCreateProcess = ProcessCreate(finalPath, Arguments, &newProcess);
	if (!SUCCEEDED(statusCreateProcess)) {
		return STATUS_UNSUCCESSFUL;
	}


	QWORD currentIndex = currentProcess->OwnObjectInfo->CurrentIndex;
	currentIndex += 1;

	//we only set the new id for the process + currentIndex
	//the rest is done in the processCreate function -> object type, StdoutOpen
	newProcess->OwnObjectInfo->CurrentIndex = currentIndex;
	newProcess->OwnObjectInfo->id = currentIndex;
	currentProcess->OwnObjectInfo->CurrentIndex = currentIndex;

	//now we can add it to the hashtable
	HashTableInsert(&currentProcess->ProcessHashTable, &newProcess->OwnObjectInfo->HashEntry);

	*ProcessHandle = currentProcess->OwnObjectInfo->CurrentIndex;

	return STATUS_SUCCESS;
}

STATUS 
SyscallProcessCloseHandle(
	IN      UM_HANDLE               ProcessHandle
)
{
	if (ProcessHandle == UM_INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_PARAMETER1;
	}
	if (ProcessHandle < 0 || ProcessHandle > 100) {
		return STATUS_INVALID_PARAMETER1;
	}

	PPROCESS currentProcess = GetCurrentProcess();
	PHASH_ENTRY hashTableProcessEntry = HashTableLookup(&currentProcess->ProcessHashTable, (PHASH_KEY)&ProcessHandle);

	if (hashTableProcessEntry == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	PObjectInfo objectProcess = CONTAINING_RECORD(hashTableProcessEntry, ObjectInfo, HashEntry);
	
	if (objectProcess->objectType != PROCESS_OBJECT) {
		return STATUS_UNSUCCESSFUL;
	}

	if (objectProcess->id == ProcessHandle) {
		HashTableRemove(&currentProcess->ProcessHashTable, (PHASH_KEY)&objectProcess->id);
		ProcessCloseHandle(objectProcess->objectPtr);
		return STATUS_SUCCESS;
	}
	else
		return STATUS_UNSUCCESSFUL;

}

STATUS 
SyscallProcessGetPid(
	IN_OPT  UM_HANDLE               ProcessHandle,
	OUT     PID*                    ProcessId
)
{
	if (ProcessHandle < 0 || ProcessHandle > 100) {
		return STATUS_INVALID_PARAMETER1;
	}

	PPROCESS currentProcess = GetCurrentProcess();
	if (ProcessHandle == UM_INVALID_HANDLE_VALUE) {
		*ProcessId = currentProcess->Id;
	}
	else {
		PHASH_ENTRY hashTableProcessEntry = HashTableLookup(&currentProcess->ProcessHashTable, (PHASH_KEY)&ProcessHandle);
		PObjectInfo objectProcess = CONTAINING_RECORD(hashTableProcessEntry, ObjectInfo, HashEntry);
		if (objectProcess == NULL) {
			return STATUS_UNSUCCESSFUL;
		}
		if (objectProcess->objectType != PROCESS_OBJECT) {
			return STATUS_UNSUCCESSFUL;
		}
		PPROCESS pProcess = (PPROCESS)objectProcess->objectPtr;
		*ProcessId = pProcess->Id;
	}

	return STATUS_SUCCESS;
}

STATUS
SyscallProcessWaitForTermination(
	IN      UM_HANDLE               ProcessHandle,
	OUT     STATUS* TerminationStatus
)
{
	if (ProcessHandle == UM_INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_PARAMETER1;
	}
	if (ProcessHandle < 0 || ProcessHandle > 100) {
		return STATUS_INVALID_PARAMETER1;
	}


	PPROCESS currentProcess = GetCurrentProcess();
	PHASH_ENTRY hashTableProcessEntry = HashTableLookup(&currentProcess->ProcessHashTable, (PHASH_KEY)&ProcessHandle);

	//we search for the entry, if we do no find it the UM_HANDLE is incorrect
	if (hashTableProcessEntry == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	//then we want to obtain the object that we inserted in the hash table
	PObjectInfo objectProcess = CONTAINING_RECORD(hashTableProcessEntry, ObjectInfo, HashEntry);


	//sincer there is only one hash table we need to make sure we have the correct object type->process
	if (objectProcess->objectType != PROCESS_OBJECT) {
		return STATUS_UNSUCCESSFUL;
	}

	//if by any chance the handle is different => an error occured, otherwise continue
	if (objectProcess->id == ProcessHandle) {
		ProcessWaitForTermination((PPROCESS)objectProcess->objectPtr, TerminationStatus);
		return STATUS_SUCCESS;
	}
	else
		return STATUS_UNSUCCESSFUL;

}


STATUS 
SyscallFileCreate(
	IN_READS_Z(PathLength)
	char* Path,
	IN          QWORD                   PathLength,
	IN          BOOLEAN                 Directory,
	IN          BOOLEAN                 Create,
	OUT         UM_HANDLE* FileHandle
)
{
	STATUS pathStatus = MmuIsBufferValid((PVOID)Path, PathLength, PAGE_RIGHTS_READ, GetCurrentProcess());
	if (!SUCCEEDED(pathStatus))
	{
		return STATUS_INVALID_PARAMETER1;
	}
	if (Path == NULL) {
		return STATUS_INVALID_PARAMETER1;
	}
	if (PathLength < 2) {
		return STATUS_INVALID_PARAMETER2;
	}
	

	char finalPath[260];
	//compiler will give an error for '\' -> needs to be replaced with '\\'
	char partition[30];
	strcpy(partition, IomuGetSystemPartitionPath());
	if (strchr(Path, '\\') == Path) {
		sprintf(finalPath, "%sApplications\\%s", partition, Path);
	}
	else {
		sprintf(finalPath, "%s", Path);
	}

	PFILE_OBJECT newFile;
	STATUS createFile = IoCreateFile(&newFile, finalPath, Directory, Create, FALSE);

	if (!SUCCEEDED(createFile)) {
		return createFile;
	}

	PPROCESS currentProcess;
	currentProcess = GetCurrentProcess();
	QWORD currentIndex = currentProcess->OwnObjectInfo->CurrentIndex;
	currentIndex += 1;

	PObjectInfo fileInfo = ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(ObjectInfo), HEAP_PROCESS_TAG, 0);

	if (fileInfo == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	fileInfo->id = currentIndex;
	fileInfo->objectPtr = newFile;
	fileInfo->objectType = FILE_OBJ;
	currentProcess->OwnObjectInfo->CurrentIndex = currentIndex;

	HashTableInsert(&currentProcess->ProcessHashTable, &fileInfo->HashEntry);

	*FileHandle = currentProcess->OwnObjectInfo->CurrentIndex;

	return STATUS_SUCCESS;
}

STATUS
SyscallFileRead(
	IN  UM_HANDLE                   FileHandle,
	OUT_WRITES_BYTES(BytesToRead)
	PVOID                       Buffer,
	IN  QWORD                       BytesToRead,
	OUT QWORD* BytesRead
)
{
	if (FileHandle == UM_INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_PARAMETER1;
	}
	if (FileHandle < 0 || FileHandle > 100) {
		return STATUS_INVALID_PARAMETER1;
	}
	if (FileHandle == UM_FILE_HANDLE_STDOUT) {
		return STATUS_INVALID_PARAMETER1;
	}
	STATUS bufferStatus = MmuIsBufferValid(&Buffer, BytesToRead, PAGE_RIGHTS_READ, GetCurrentProcess());
	if (!SUCCEEDED(bufferStatus))
	{
		return STATUS_INVALID_PARAMETER2;
	}
	PPROCESS currentProcess;
	currentProcess = GetCurrentProcess();

	PHASH_ENTRY hashTableFileEntry = HashTableLookup(&currentProcess->ProcessHashTable, (PHASH_KEY)&FileHandle);
	if (hashTableFileEntry == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	PObjectInfo objectFile = CONTAINING_RECORD(hashTableFileEntry, ObjectInfo, HashEntry);

	if (objectFile->objectType != FILE_OBJ) {
		return STATUS_UNSUCCESSFUL;
	}

	if (objectFile->id == FileHandle) {
		PFILE_OBJECT myFile = objectFile->objectPtr;
		STATUS fileStatus = IoReadFile(myFile, BytesToRead, &myFile->CurrentByteOffset, Buffer, BytesRead);
		if (!SUCCEEDED(fileStatus)) {
			return STATUS_UNSUCCESSFUL;
		}
		return STATUS_SUCCESS;
	}
	else
		return STATUS_UNSUCCESSFUL;
}

STATUS 
SyscallFileClose(
	IN          UM_HANDLE               FileHandle
) 
{
	if (FileHandle == UM_INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_PARAMETER1;
	}
	if (FileHandle < 0 || FileHandle > 100) {
		return STATUS_INVALID_PARAMETER1;
	}
	if (FileHandle == UM_FILE_HANDLE_STDOUT) {
		return STATUS_INVALID_PARAMETER1;
	}

	PPROCESS currentProcess;
	currentProcess = GetCurrentProcess();

	if (FileHandle == UM_FILE_HANDLE_STDOUT && currentProcess->OwnObjectInfo->StdoutOpen == 1) {
		currentProcess->OwnObjectInfo->StdoutOpen = 0;
		return STATUS_SUCCESS;
	}
	if (FileHandle == UM_FILE_HANDLE_STDOUT && currentProcess->OwnObjectInfo->StdoutOpen != 1) {
		return STATUS_SUCCESS;
	}

	PHASH_ENTRY hashTableFileEntry = HashTableLookup(&currentProcess->ProcessHashTable, (PHASH_KEY)&FileHandle);
	if (hashTableFileEntry == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	PObjectInfo objectFile = CONTAINING_RECORD(hashTableFileEntry, ObjectInfo, HashEntry);

	if (objectFile->objectType != FILE_OBJ) {
		return STATUS_UNSUCCESSFUL;
	}

	if (objectFile->id == FileHandle) {
		PFILE_OBJECT myFile = objectFile->objectPtr;
		HashTableRemove(&currentProcess->ProcessHashTable, (PHASH_KEY)&objectFile->HashEntry);
		STATUS fileStatus = IoCloseFile(myFile);
		if (!SUCCEEDED(fileStatus)) {
			return STATUS_UNSUCCESSFUL;
		}
		return STATUS_SUCCESS;
	}
	else
		return STATUS_UNSUCCESSFUL;
}

STATUS
SyscallThreadExit(
	IN  STATUS                      ExitStatus
)
{
	ThreadExit(ExitStatus);

	return STATUS_SUCCESS;
}