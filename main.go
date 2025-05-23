package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/akamensky/argparse"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"log"
	"os"
	"sync"
)

const SuffixEncrypted = "-encrypted"

// PKCS7 padding
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	padLen := int(data[length-1])
	if padLen > length {
		return nil, io.ErrUnexpectedEOF
	}
	return data[:length-padLen], nil
}

func encryptFile(inputPath string, key []byte) error {
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	mode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	out := append(iv, ciphertext...)
	return os.WriteFile(inputPath+SuffixEncrypted, out, 0644)
}

func decryptFile(inputPath string, key []byte) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	if len(data) < aes.BlockSize {
		return io.ErrUnexpectedEOF
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return io.ErrUnexpectedEOF
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return err
	}

	outputPath := inputPath[:len(inputPath)-len(SuffixEncrypted)]
	return os.WriteFile(outputPath, unpadded, 0644)
}

func main() {
	// Argument parsing
	parser := argparse.NewParser("safedotenv", "Securely store .env files using AES encryption on Github repositories for convenience.")
	// --encrypt flag is optional boolean flag to encrypt the file instead of standardly decrypting
	encrypt := parser.Flag("e", "encrypt", &argparse.Options{Required: false, Default: false, Help: "Encrypt .env to .env-encrypted instead of decrypting .env-encrypted to .env"})
	folder := parser.String("d", "directory", &argparse.Options{Required: false, Default: ".", Help: "Directory to scan for files to encrypt/decrypt"})
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
	}

	// Scan user input for passphrase
	key, err := getPassphrase()

	// Declare file paths as an empty vector of filepaths to concatenate when we scan later on
	filePaths := getDotenvPaths(folder, encrypt)

	// Iterate over the file paths and encrypt/decrypt them
	processDotenvFiles(filePaths, encrypt, key)

	log.Println("Done.")
}

func processDotenvFiles(filePaths []string, encrypt *bool, key []byte) {
	var wg sync.WaitGroup
	channel := make(chan error, len(filePaths)) // Buffered channel to avoid blocking

	for _, filePath := range filePaths {
		wg.Add(1)
		if *encrypt {
			go func(filePath string) {
				defer wg.Done()
				err := encryptFile(filePath, key)
				channel <- err
			}(filePath)
		} else {
			go func(filePath string) {
				defer wg.Done()
				err := decryptFile(filePath, key)
				channel <- err
			}(filePath)
		}
	}

	// Wait for all goroutines to finish
	wg.Wait()
	close(channel)

	// Collect and log errors
	for err := range channel {
		if err != nil {
			log.Println("Error:", err)
		}
	}
}

func getDotenvPaths(folder *string, encrypt *bool) []string {
	var filePaths []string
	// Use a stack to process directories iteratively
	stack := []string{*folder}

	for len(stack) > 0 {
		// Pop a directory from the stack
		currentDir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// Read the contents of the current directory
		files, err := os.ReadDir(currentDir)
		if err != nil {
			log.Fatal(err)
		}

		// Iterate over the files and append their paths to the filePaths vector
		for _, file := range files {
			if file.IsDir() {
				// Add subdirectory to the stack
				stack = append(stack, currentDir+"/"+file.Name())
			} else if file.Name() == ".env" && *encrypt == true {
				filePaths = append(filePaths, currentDir+"/"+file.Name())
			} else if file.Name() == ".env-encrypted" && *encrypt == false {
				filePaths = append(filePaths, currentDir+"/"+file.Name())
			}
		}
	}
	log.Println(filePaths)
	return filePaths
}

func getPassphrase() ([]byte, error) {
	// Get user input for the key
	log.Println("Enter passphrase: ")
	var passphrase string
	_, err := fmt.Scanln(&passphrase)
	if err != nil {
		log.Fatal("Error reading passphrase:", err)
	}

	// Derive AES key from passphrase
	salt := []byte("somesalt") // Use a fixed or random salt
	key := pbkdf2.Key([]byte(passphrase), salt, 4096, 32, sha256.New)
	log.Println(key)
	return key, nil
}
