package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	AES "github.com/Apurer/eev/aes"
	privateKey "github.com/Apurer/eev/privatekey"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"os"
	"syscall"
)

/*
	generates private key
	generates encrypted value and puts it into the home directory ~/.eev
	allows for decrypting environment variables
	tells about to which files to add or search help on github and about applying changes by running source command
	copies values of decrypted env variables to the clipboard

	two ways of running script: interactive or non interactive mode
	interactive mode is when important values are not defined using parameters or just no parameters are passed at all
	non interactive mode is when all important values are passed on input
	if one of the values will not get passed program will turn into interactive mode and ask user for this value

	each step will get values and based on passed or not passed value it will continue in interactive or non interactive mode

	maybe at start owkr only with bash_profile and env variables instead of creating directory
	read set in env
	by default copy to clipboard - instead of showing output
	EEV_clipboard - boolean
	EEV_privatekey - path to privatekey
	other env variables even those encrypted can be set with normal names
	don't modify files for now but put generated private keys where use wants

	on interactive mode with no parameters passed give user options on what to do
	- generate private key (needed flags)
		- path (to save private key and how to name it)
		- key type (if is provided it means user wants to create private key - info for non interactive mode)
			-key_type or -type
		- key size (if is provided it means user wants to create private key - info for non interactive mode)
			-key_size or -size
		- passphrase - optional (before chosing algo for encryption)
			-passphrase
		- algorithm for encryption of private key - optional (if is provided then user is asked to provide passphrase in interactive input)
			-enc_alg or -alg

	- encrypt value - by default using private key set in env variables (for non interactive mode it has to be specified what user wants to do - encrypt or decrypt)
	- encrypt - flag: -encrypt=true
		- value to encrypt
		- path to private key or use env variable
		- passphrase - optional if private key is encrypted (if not provided and private key is encrypted then use prompt)

	- decrypt value - by default using private key set in env variables - flag: -decrypt=true or just pass value
		- value to decrypt
		- path to private key or use env variable (tries to use env variable by default if not provided but if it doesn't exist prompt is used)
		- passphrase - optional if private key is encrypted (if not provided and private key is encrypted then use prompt)
	- decrypt value - in interactive mode user can choose if he wants to copy value to clipboard - if value in env variable is not set
	- decrypting value can be done by providing value or name of env variable - give user option
		- decrypt value
		- decrypt env variable
			- copy value to clipboard
			- print output in terminal

	- all of the mentioned can be executed within one run of non interactive - maybe -env_decrypt -env_encrypt for environment variable
		- first by creating private key
		- second by decrypting passed value or env variable - decrypts both values from env variable and passed using same key if passed
		- third  by encrypting passed value or env variable - encrypts both values from env variable and passed using same key if passed
	- info flag for non interactive mode which gives info about what happened during execution or returns output line by line
		- for private key generates element in passed path returning 0 for given line or empty line
		- for encrypted value outputs decrypted value in terminal
		- for encrypting outputs encrypted value in terminal
*/

func CreatePrivateKey(keytype string, keysize int, keypath string, alg string, passphrase string, interactive bool) (string, string, error) {

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
		//var keySize int
		fmt.Fscan(reader, &keysize)
		//keysize = keySize
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
		fmt.Fscan(reader, &keypath)
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

func Decrypt(decrypt string, env_decrypt string, keypath string, passphrase string, interactive bool) (string, string, error) {

	reader := bufio.NewReader(os.Stdin)
	if keypath == "" {
		keypath = os.Getenv("EEV_privatekey")
		for interactive && keypath == "" {
			// prompt
			fmt.Println("Please provide path for private key: ")
			fmt.Fscan(reader, &keypath)
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
		fmt.Fscan(reader, &decrypt)
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

	reader := bufio.NewReader(os.Stdin)

	if keypath == "" {
		keypath = os.Getenv("EEV_privatekey")
		for interactive && keypath == "" {
			fmt.Println("Please provide path for private key: ")
			fmt.Fscan(reader, &keypath)
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
		fmt.Fscan(reader, &encrypt)
	}

	encrypted, err := AES.Encrypt(privkey, encrypt)
	if err != nil {
		return fmt.Errorf("%s, error during encrypting value", err.Error())
	}

	fmt.Println(encrypted)
	return nil
}

func main() {

	interactive := flag.Bool("interactive", true, "sets mode of running program")
	keytype := flag.String("type", "", "type of private key")
	keysize := flag.Int("size", 0, "size of pivate key in bits")
	keypath := flag.String("path", "", "path to save private key") // check if path exists otherwise try to resolve via env variable
	alg := flag.String("alg", "", "encryption algorithm with which private key is encrypted")
	passphrase := flag.String("passphrase", "", "passphrase with which private key is encrypted")

	decrypt := flag.String("decrypt", "", "value to be decrypted")
	env_decrypt := flag.String("env_decrypt", "", "environment variable to be decrypted")

	encrypt := flag.String("encrypt", "", "value to be encrypted")
	env_encrypt := flag.String("env_encrypt", "", "environment variable to be encrypted")

	flag.Parse()

	var err error

	if *keytype != "" || *keysize != 0 || *alg != "" {
		*keypath, *passphrase, err = CreatePrivateKey(*keytype, *keysize, *keypath, *alg, *passphrase, *interactive)
		if err != nil {
			log.Fatal(err)
		}
	}
	if *decrypt != "" || *env_decrypt != "" {
		*keypath, *passphrase, err = Decrypt(*decrypt, *env_decrypt, *keypath, *passphrase, *interactive)
		if err != nil {
			log.Fatal(err)
		}
	}
	if *encrypt != "" || *env_encrypt != "" {
		err = Encrypt(*encrypt, *env_encrypt, *keypath, *passphrase, *interactive)
		if err != nil {
			log.Fatal(err)
		}
	}
}
