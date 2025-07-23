package main

/*
#include <stdio.h>
#include <stdint.h>
#include <gmssl/rand.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/sm2.h>
#include <gmssl/pkcs8.h>
*/
import (
	"C"
)
import (
	"errors"
	"fmt"
	"unsafe"
)

type Sm2 struct {
	sm2_key C.SM2_KEY
	pri     []byte
	pub     []byte
}

func (sm2 *Sm2) GenerateKey() {
	k := C.malloc(C.size_t(512))
	p := C.malloc(C.size_t(512))
	var key *C.uint8_t = (*C.uint8_t)(k)
	if key != nil {
		defer C.free(unsafe.Pointer(key))
	}
	var pub *C.uint8_t = (*C.uint8_t)(p)
	if pub != nil {
		defer C.free(unsafe.Pointer(pub))
	}
	var key_len = C.uint64_t(0)
	var pub_len = C.uint64_t(0)
	C.sm2_key_generate(&sm2.sm2_key)
	C.sm2_private_key_info_to_der(&sm2.sm2_key, &key, &key_len)
	C.sm2_public_key_info_to_der(&sm2.sm2_key, &pub, &pub_len)
	// C.GenKey(&sm2.sm2_key, key, &key_len, pub, &pub_len)
	var keyLen uint64 = *(*uint64)(unsafe.Pointer(&key_len))
	var pubLen uint64 = *(*uint64)(unsafe.Pointer(&pub_len))
	fmt.Println("-----", keyLen, pubLen)
	var keyOut = make([]byte, keyLen)
	var pubOut = make([]byte, pubLen)
	po := uintptr(unsafe.Pointer(k))
	var i uint64
	for i = 0; i < keyLen; i++ {
		j := *(*uint8)(unsafe.Pointer(po))
		keyOut[i] = j
		po += unsafe.Sizeof(j)
	}
	po = uintptr(unsafe.Pointer(p))
	for i = 0; i < pubLen; i++ {
		j := *(*uint8)(unsafe.Pointer(po))
		pubOut[i] = j
		po += unsafe.Sizeof(j)
	}
	sm2.pri = keyOut
	sm2.pub = pubOut
}
func (sm2 *Sm2) Export() ([]byte, []byte) {
	return sm2.pri, sm2.pub
}

func (sm2 *Sm2) ImportPri(pri []byte) {
	sm2.pri = pri
	pri_len := C.size_t(len(pri))
	cData := C.malloc(512)
	defer C.free(cData) // 确保内存被释放
	C.memcpy(cData, unsafe.Pointer(&pri[0]), pri_len)
	p := (*C.uint8_t)(cData)
	attrs := (*C.uint8_t)(C.malloc(C.size_t(0)))
	attrs_len := C.size_t(0)
	C.sm2_private_key_info_from_der(&sm2.sm2_key, &attrs, &attrs_len, &p, &pri_len)
}
func (sm2 *Sm2) ImportPub(pub []byte) {
	sm2.pub = pub
	pub_len := C.size_t(len(pub))
	cData := C.malloc(512)
	defer C.free(cData) // 确保内存被释放
	C.memcpy(cData, unsafe.Pointer(&pub[0]), pub_len)
	p := (*C.uint8_t)(cData)
	pub_len = 0
	C.sm2_public_key_info_from_der(&sm2.sm2_key, &p, &pub_len)
}

func (sm2 *Sm2) Verify(dgst []byte, signature []byte) bool {
	if len(dgst) != C.SM3_DIGEST_SIZE {
		return false
	}
	if 1 != C.sm2_verify(&sm2.sm2_key, (*C.uchar)(&dgst[0]), (*C.uchar)(&signature[0]), C.size_t(len(signature))) {
		return false
	}
	return true
}

func (sm2 *Sm2) Encrypt(in []byte) ([]byte, error) {
	outbuf := make([]byte, C.SM2_MAX_CIPHERTEXT_SIZE)
	var outlen C.size_t
	if C.sm2_encrypt(&sm2.sm2_key, (*C.uchar)(&in[0]), C.size_t(len(in)), (*C.uchar)(&outbuf[0]), &outlen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}

func (sm2 *Sm2) Decrypt(in []byte) ([]byte, error) {
	outbuf := make([]byte, C.SM2_MAX_PLAINTEXT_SIZE)
	var outlen C.size_t
	if C.sm2_decrypt(&sm2.sm2_key, (*C.uchar)(&in[0]), C.size_t(len(in)), (*C.uchar)(&outbuf[0]), &outlen) != 1 {
		return nil, errors.New("Libgmssl inner error")
	}
	return outbuf[:outlen], nil
}
