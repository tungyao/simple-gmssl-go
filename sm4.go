package simple_gmssl_go

/*
#include <stdlib.h>
#include <string.h>
#include <gmssl/sm4.h>
*/
import "C"
import (
	"bytes"
	"errors"
	"unsafe"
)

const (
	Sm4KeySize   = 16
	Sm4BlockSize = 16

	Sm4CbcIvSize = 16

	Sm4CtrIvSize = 16

	Sm4GcmMinIvSize      = 8
	Sm4GcmMaxIvSize      = 64
	Sm4GcmDefaultIvSize  = 64
	Sm4GcmDefaultTagSize = 16
	Sm4GcmMaxTagSize     = 16
)

type Sm4 struct {
	sm4_key C.SM4_KEY
}

func pkcs7Padding(data []byte) []byte {
	blockSize := 16
	padLen := blockSize - (len(data) % blockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}
func pkcs7Unpadding(data []byte) []byte {
	padLen := data[len(data)-1]
	return data[:len(data)-int(padLen)]
}

func (sm4 *Sm4) Encrypt(in []byte, key []byte, iv []byte) ([]byte, error) {
	if len(iv) != 16 {
		return nil, errors.New("iv size must be 16 bytes")
	}
	if len(key)%16 != 0 {
		return nil, errors.New("key size must be multiple of 16 bytes")
	}
	padded := pkcs7Padding(in)
	nblock := C.size_t(len(padded) / 16)
	tmp_iv := C.malloc(C.size_t(16))
	defer C.free(tmp_iv)
	C.memcpy(tmp_iv, unsafe.Pointer(&iv[0]), C.size_t(16))
	out := make([]byte, len(padded))
	ivarr := (*C.uint8_t)(tmp_iv)
	C.sm4_set_encrypt_key(&sm4.sm4_key, (*C.uchar)(&key[0]))
	C.sm4_cbc_encrypt_blocks(&sm4.sm4_key, ivarr, (*C.uchar)(&padded[0]), nblock, (*C.uchar)(&out[0]))
	return out, nil
}
func (sm4 *Sm4) Decrypt(in []byte, key []byte, iv []byte) ([]byte, error) {
	if len(iv) != 16 {
		return nil, errors.New("iv size must be 16 bytes")
	}
	if len(key)%16 != 0 {
		return nil, errors.New("key size must be multiple of 16 bytes")
	}
	plaintext := make([]byte, len(in))
	tmp_iv := C.malloc(C.size_t(16))
	defer C.free(tmp_iv)
	C.memcpy(tmp_iv, unsafe.Pointer(&iv[0]), C.size_t(16))
	ivarr := (*C.uint8_t)(tmp_iv)
	C.sm4_set_decrypt_key(&sm4.sm4_key, (*C.uchar)(&key[0]))
	nblock := C.size_t(len(in) / 16)
	C.sm4_cbc_decrypt_blocks(&sm4.sm4_key, ivarr, (*C.uchar)(&in[0]), nblock, (*C.uchar)(&plaintext[0]))
	return pkcs7Unpadding(plaintext), nil
}
