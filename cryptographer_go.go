// cryptographer_go.go — криптограф (шифрование файлов) на Go

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize   = 16
	nonceSize  = 12
	tagSize    = 16
	iterations = 100000
	keySize    = 32
)

func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)
}

func encryptFile(input, output, password string) error {
	plaintext, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	salt := make([]byte, saltSize)
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	// На выход: salt + nonce + ciphertext (включает тег)
	outFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer outFile.Close()
	if _, err := outFile.Write(salt); err != nil {
		return err
	}
	if _, err := outFile.Write(nonce); err != nil {
		return err
	}
	if _, err := outFile.Write(ciphertext); err != nil {
		return err
	}
	fmt.Printf("Файл зашифрован: %s\n", output)
	return nil
}

func decryptFile(input, output, password string) error {
	encData, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	if len(encData) < saltSize+nonceSize+tagSize {
		return fmt.Errorf("некорректный зашифрованный файл")
	}
	salt := encData[:saltSize]
	nonce := encData[saltSize : saltSize+nonceSize]
	ciphertext := encData[saltSize+nonceSize:]
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	if err := os.WriteFile(output, plaintext, 0644); err != nil {
		return err
	}
	fmt.Printf("Файл расшифрован: %s\n", output)
	return nil
}

func main() {
	if len(os.Args) != 5 {
		fmt.Printf("Использование: %s <encrypt|decrypt> <input> <output> <password>\n", os.Args[0])
		os.Exit(1)
	}
	mode := os.Args[1]
	input := os.Args[2]
	output := os.Args[3]
	password := os.Args[4]

	var err error
	switch mode {
	case "encrypt":
		err = encryptFile(input, output, password)
	case "decrypt":
		err = decryptFile(input, output, password)
	default:
		err = fmt.Errorf("режим должен быть encrypt или decrypt")
	}
	if err != nil {
		fmt.Println("Ошибка:", err)
		os.Exit(1)
	}
}
