package aes

import (
	"golang.org/x/crypto/ssh/terminal"
	AES "github.com/Apurer/eev/aes"
	"encoding/pem"
	"crypto/x509"
	"io/ioutil"
	"syscall"
	"errors"
	"bufio"
	"fmt"
	"os"
)

func Decrypt(decrypt string, env_decrypt string, keypath string, passphrase string, interactive bool) (string, string, error) {

	reader := bufio.NewReader(os.Stdin)
	if keypath == "" {
		keypath = os.Getenv("EEV_privatekey")
		for interactive && keypath == "" {
			// prompt
			fmt.Println("Please provide path for private key: ")

			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				keypath = scanner.Text()
			}
		}

		if !interactive && keypath == "" {
			return keypath, passphrase, errors.New("path of private key not set")
		}
	}

	privkey, err := ioutil.ReadFile(keypath)
	if err != nil {
		if err != nil {
			return keypath, passphrase, fmt.Errorf("%s, private key reading error", err.Error())
		}
	}

	block, _ := pem.Decode(privkey)
	if interactive && x509.IsEncryptedPEMBlock(block) && passphrase == "" {
		// prompt
		fmt.Println("Provide passphrase for private key: ")
		passphrase_bytes, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return keypath, passphrase, fmt.Errorf("%s, passphrase input error", err.Error())
		}

		passphrase = string(passphrase_bytes)
	}

	if !interactive && x509.IsEncryptedPEMBlock(block) && passphrase == "" {
		return keypath, passphrase, errors.New("passphrase for private key decryption is empty")
	}

	if x509.IsEncryptedPEMBlock(block) {
		block, _ := pem.Decode(privkey)
		if block == nil {
			return keypath, passphrase, errors.New("decoded pem block is empty")
		}
		block.Bytes, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		privkey = pem.EncodeToMemory(block)
	}

	if env_decrypt != "" {
		decrypt = os.Getenv(env_decrypt)
	}

	if decrypt == "" {
		fmt.Println("Provide value to be decrypted")

		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			decrypt = scanner.Text()
		}
	}
	// check if key is
	// decrypting value
	decrypted, err := AES.Decrypt(privkey, decrypt)
	if err != nil {
		return keypath, passphrase, fmt.Errorf("%s, error during decrypting value", err.Error())
	}

	fmt.Println(string(decrypted))

	return keypath, passphrase, nil
}

func Encrypt(encrypt string, env_encrypt string, keypath string, passphrase string, interactive bool) error {

	if keypath == "" {
		keypath = os.Getenv("EEV_privatekey")
		for interactive && keypath == "" {
			fmt.Println("Please provide path for private key: ")

			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				keypath = scanner.Text()
			}
		}

		if !interactive && keypath == "" {
			return errors.New("path of private key not set")
		}
	}

	privkey, err := ioutil.ReadFile(keypath)
	if err != nil {
		return fmt.Errorf("%s, private key reading error", err.Error())
	}

	block, _ := pem.Decode(privkey)
	if interactive && x509.IsEncryptedPEMBlock(block) && passphrase == "" {
		// prompt
		fmt.Println("Provide passphrase for private key: ")
		passphrase_bytes, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("%s, passphrase input error", err.Error())
		}

		passphrase = string(passphrase_bytes)
	}

	if !interactive && x509.IsEncryptedPEMBlock(block) && passphrase == "" {
		return errors.New("passphrase for private key decryption is empty")
	}

	if x509.IsEncryptedPEMBlock(block) {
		block, _ := pem.Decode(privkey)
		if block == nil {
			return errors.New("decoded pem block is empty")
		}
		block.Bytes, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		privkey = pem.EncodeToMemory(block)
	}
	// encrypting value

	if env_encrypt != "" {
		encrypt = os.Getenv(env_encrypt)
	}

	if encrypt == "" {
		fmt.Println("Provide value to be decrypted")

		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			encrypt = scanner.Text()
		}
	}

	encrypted, err := AES.Encrypt(privkey, encrypt)
	if err != nil {
		return fmt.Errorf("%s, error during encrypting value", err.Error())
	}

	fmt.Println(encrypted)
	return nil
}