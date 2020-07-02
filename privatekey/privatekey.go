package privatekey

import (
	privateKey "github.com/Apurer/eev/privatekey"
	"golang.org/x/crypto/ssh/terminal"
	"crypto/x509"
	"syscall"
	"errors"
	"bytes"
	"bufio"
	"fmt"
	"os"
)

func Create(keytype string, keysize int, keypath string, alg string, passphrase string, interactive bool) (string, string, error) {

	reader := bufio.NewReader(os.Stdin)

	// creating private key
	for interactive && !(keytype == "RSA" || keytype == "ECDSA") {
		// prompt
		fmt.Println("This is a list of private key types to choose from:")
		fmt.Println("RSA")
		fmt.Println("ECDSA")
		fmt.Println("Please provide type of private key.")
		fmt.Fscan(reader, &keytype)

	}

	if !interactive && !(keytype == "RSA" || keytype == "ECDSA") {
		return keypath, passphrase, errors.New("type of private key does not fit available values.\nAvailable types:\nRSA\nECDSA")
	}

	for interactive && keytype == "RSA" && !(keysize == 128 || keysize == 192 || keysize == 256) {
		// prompt
		fmt.Println("This is a list of RSA private key sizes to choose from:")
		fmt.Println("128")
		fmt.Println("192")
		fmt.Println("256")
		fmt.Println("Please provide size of private key: ")

		fmt.Fscan(reader, &keysize)
	}

	if !interactive && keytype == "RSA" && !(keysize == 128 || keysize == 192 || keysize == 256) {
		return keypath, passphrase, fmt.Errorf("size: %d of private key does not fit available values for ECDSA type.\nAvailable sizes for ECDSA:\n256\n", keysize)
	}

	for interactive && keytype == "ECDSA" && !(keysize == 256) {
		// prompt
		fmt.Println("This is a list of ECDSA private key sizes to choose from:")
		fmt.Println("256")
		fmt.Println("Please provide size of private key.")
		fmt.Fscan(reader, &keysize)
	}

	if !interactive && keytype == "ECDSA" && !(keysize == 256) {
		return keypath, passphrase, fmt.Errorf("size: %d of private key does not fit available values for ECDSA type.\nAvailable sizes for ECDSA:\n256\n", keysize)
	}

	for interactive && !(alg == "AES128" || alg == "AES192" || alg == "AES256" || alg == "") {
		// prompt
		fmt.Println("This is a list of private key encryption algorithms to choose from:")
		fmt.Println("AES128")
		fmt.Println("AES192")
		fmt.Println("AES256")
		fmt.Println("Please provide correct algorithm for private key encryption.")
		fmt.Fscan(reader, &alg)
	}

	if !interactive && !(alg == "AES128" || alg == "AES192" || alg == "AES256") {
		return keypath, passphrase, fmt.Errorf("encryption algorithm: %s of private key does not fit available values.\nAvailable encryption algorithms:\nAES128\nAES192\nAES256", alg)
	}

	for interactive && alg != "" && passphrase == "" {
		// prompt
		fmt.Println("Provide passphrase for private key: ")
		passphrase_bytes, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return keypath, passphrase, fmt.Errorf("%s, passphrase input error", err.Error())
		}
		fmt.Println("Enter same passphrase again: ")
		compare_bytes, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return keypath, passphrase, fmt.Errorf("%s, passphrase input error", err.Error())
		}
		if !bytes.Equal(passphrase_bytes, compare_bytes) {
			fmt.Println("Passwords do not match. Try again.")
			continue
		} else {
			passphrase = string(passphrase_bytes)
		}
	}

	if !interactive && alg != "" && passphrase == "" {
		return keypath, passphrase, errors.New("passphrase for private key encryption is empty")
	}

	var keyType string

	switch keytype {
	case "RSA":
		keyType = privateKey.RSA
	case "ECDSA":
		keyType = privateKey.ECDSA
	default:
		return keypath, passphrase, fmt.Errorf("unknown private key type: %s", keytype)
	}

	var algorithm x509.PEMCipher

	switch alg {
	case "AES128":
		algorithm = privateKey.AES128
	case "AES192":
		algorithm = privateKey.AES192
	case "AES256":
		algorithm = privateKey.AES256
	case "":
		algorithm = 0
	default:
		return keypath, passphrase, fmt.Errorf("unknown private key encryption algorithm: %s", alg)
	}

	for interactive && keypath == "" {
		// prompt
		fmt.Println("Please provide path for private key: ")

		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			keypath = scanner.Text()
		}
	}

	if !interactive && keypath == "" {
		return keypath, passphrase, errors.New("path for private key encryption is empty")
	}

	// generate key
	privkey, err := privateKey.Generate(keyType, keysize)
	if err != nil {
		return keypath, passphrase, fmt.Errorf("%s, error while generating private key", err.Error())
	}
	err = privateKey.Write(keypath, privkey, passphrase, algorithm)
	if err != nil {
		return keypath, passphrase, fmt.Errorf("%s, error while writing private key to file", err.Error())
	}

	return keypath, passphrase, nil
}