package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/minio/minio/internal/logger"
)

const (
	salt = "mtyw-oss-password-12345678901234"
)

//func aesEncrypt(passwd string) (key ObjectKey) {
//	data := []byte(salt)
//
//	key = GenerateKey(data,nil)
//	s := key.Seal(data,GenerateIV(rand.Reader), S3.String(), bucket, passwd)
//	//IAAfAJdrqlaeklKZRkMiIn1P8HP7+49aSTqlfM6ZbnQ/mHvQ3nlDQN6F1raABZyHnYyCRcjwb1g/rTcvSu58qw==
//	sr := base64.StdEncoding.EncodeToString(s.Key[:])
//	fmt.Println(sr)
//	return
//}
//func aesDecrypt()  {
//	data := []byte(salt)
//
//	key := GenerateKey(data,nil)
//	sealedKey := SealedKey{
//		IV:        GenerateIV(rand.Reader),
//		Algorithm: SealAlgorithm,
//	}
//	s := key.Unseal(data,sealedKey, S3.String(), bucket, passwd)
//	//IAAfAJdrqlaeklKZRkMiIn1P8HP7+49aSTqlfM6ZbnQ/mHvQ3nlDQN6F1raABZyHnYyCRcjwb1g/rTcvSu58qw==
//	sr := base64.StdEncoding.EncodeToString(s.Key[:])
//	fmt.Println(sr)
//	return
//}

func PasswordEncrypt(password string) string {
	// 不对空字符串加密
	if password == "" {
		return password
	}
	xpass, err := aesEncrypt([]byte(password), []byte(salt))
	if err != nil {
		logger.Error("密码加密失败", err)
		return ""
	}
	pass64 := base64.StdEncoding.EncodeToString(xpass)
	return pass64
}

func PasswordDecrypt(password string) string {
	// 不对空字符串解密
	if password == "" {
		return password
	}
	bytesPass, err := base64.StdEncoding.DecodeString(password)
	if err != nil {
		logger.Error("密码解密失败", err)
		return ""
	}

	t, err := aesDecrypt(bytesPass, []byte(salt))
	if err != nil {
		logger.Error("密码解密失败", err)
		return ""
	}
	return fmt.Sprintf("%s", t)
}

//@brief:填充明文
func pKCS5Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

//@brief:去除填充数据
func pKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//@brief:AES加密
func aesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//AES分组长度为128位，所以blockSize=16，单位字节
	blockSize := block.BlockSize()
	origData = pKCS5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize]) //初始向量的长度必须等于块block的长度16字节
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//@brief:AES解密
func aesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//AES分组长度为128位，所以blockSize=16，单位字节
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize]) //初始向量的长度必须等于块block的长度16字节
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = pKCS5UnPadding(origData)
	return origData, nil
}

func PasswdToKey(passwd string) (ObjectKey, string) {
	var objectEncryptionKey ObjectKey
	var key []byte
	randKey := strings.NewReader("12345678901234567890123456789012")
	sha := sha256.New()
	sha.Write([]byte(passwd))
	key = sha.Sum(nil)
	objectEncryptionKey = GenerateKey(key, randKey)
	//sEnc := base64.StdEncoding.EncodeToString(objectEncryptionKey[:])
	return objectEncryptionKey, base64.URLEncoding.EncodeToString(objectEncryptionKey[:])
}

type AesHandler struct {
	Key       []byte
	BlockSize int
}

func NewAesHnadler(key []byte, blockSize int) *AesHandler {
	return &AesHandler{Key: key, BlockSize: blockSize}
}

func (h *AesHandler) Decrypt(src []byte) ([]byte, error) {
	block, err := aes.NewCipher(h.Key)
	if err != nil {
		return nil, err
	}
	decryptData := make([]byte, len(src))
	tmpBlock := make([]byte, h.BlockSize)

	for i := 0; i < len(src); i += h.BlockSize {
		block.Decrypt(tmpBlock, src[i:i+h.BlockSize])
		copy(decryptData[i:i+h.BlockSize], tmpBlock)
	}
	return h.unPadding(decryptData), nil
}

func (h *AesHandler) unPadding(src []byte) []byte {
	for i := len(src) - 1; ; i-- {
		if src[i] != 0 {
			return src[:i+1]
		}
	}
}

func Base64Decrypt(key, cid string) (string, error) {
	sDec, err := base64.URLEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	cidDe, err := base64.URLEncoding.DecodeString(cid)
	//data, err := hex.DecodeString(cid)
	if err != nil {
		return "", err
	}
	a := NewAesHnadler(sDec, 16)
	res, err := a.Decrypt(cidDe)
	//index := bytes.IndexByte(res, []byte("\u0002")[0])
	//res = res[:index]
	return string(res), err
}

func EncryptLocalPassword(password string) string {
	encrypt, err := aesEncrypt([]byte(password), []byte(salt))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(encrypt)
}

func DecryptLocalPassword(cipher string) string {
	decodeString, err := hex.DecodeString(cipher)
	if err != nil {
		return ""
	}
	decrypt, err := aesDecrypt(decodeString, []byte(salt))
	if err != nil {
		return ""
	}
	return string(decrypt)
}
