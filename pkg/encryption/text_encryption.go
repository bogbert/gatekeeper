package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"github.com/gogatekeeper/gatekeeper/pkg/apperrors"
)

// EncryptDataBlock encrypts the plaintext string with the key.
func EncryptDataBlock(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}

	nonce := make([]byte, gcm.NonceSize())

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptDataBlock decrypts some cipher text.
func DecryptDataBlock(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}

	nonceSize := gcm.NonceSize()

	if len(cipherText) < nonceSize {
		return nil, errors.New("failed to decrypt the ciphertext, the text is too short")
	}

	nonce, input := cipherText[:nonceSize], cipherText[nonceSize:]

	return gcm.Open(nil, nonce, input, nil)
}

// EncodeText encodes the session state information into a value for a cookie to consume.
func EncodeText(plaintext string, key string) (string, error) {
	cipherText, err := EncryptDataBlock([]byte(plaintext), []byte(key))
	if err != nil {
		return "", err
	}

	return base64.RawStdEncoding.EncodeToString(cipherText), nil
}

// DecodeText decodes the session state cookie value.
func DecodeText(state, key string) (string, error) {
	cipherText, err := base64.RawStdEncoding.DecodeString(state)
	if err != nil {
		return "", err
	}
	// step: decrypt the cookie back in the expiration|token
	encoded, err := DecryptDataBlock(cipherText, []byte(key))
	if err != nil {
		return "", apperrors.ErrInvalidSession
	}

	return string(encoded), nil
}

// EncodeCompressedData encrypts compressed binary data and returns base64 encoded result.
// This is optimized for already-compressed data to avoid double encoding.
func EncodeCompressedData(compressedData []byte, key string) (string, error) {
	cipherText, err := EncryptDataBlock(compressedData, []byte(key))
	if err != nil {
		return "", err
	}

	return base64.RawStdEncoding.EncodeToString(cipherText), nil
}

// DecodeCompressedData decrypts data and returns the compressed binary data.
// This is optimized for compressed data to avoid unnecessary string conversion.
func DecodeCompressedData(state, key string) ([]byte, error) {
	cipherText, err := base64.RawStdEncoding.DecodeString(state)
	if err != nil {
		return nil, err
	}

	// decrypt to get back the compressed data
	compressedData, err := DecryptDataBlock(cipherText, []byte(key))
	if err != nil {
		return nil, apperrors.ErrInvalidSession
	}

	return compressedData, nil
}