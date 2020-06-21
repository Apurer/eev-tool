package main 

import (
	privateKey "github.com/Apurer/eev/privatekey"
	"golang.org/x/crypto/ssh/terminal"
	AES "github.com/Apurer/eev/aes"
	"encoding/pem"
	"crypto/x509"
	//"runtime"
	"io/ioutil"
	"syscall"
	"bytes"
	//"strings"
	"bufio"
	"flag"
	"fmt"
	"log"
    "os"
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

func main() {

	reader := bufio.NewReader(os.Stdin)

	// check flags regarding encrypting or decrypting value
	// check if key type or key size is not empty
	// else use interactive mode to define what is user intend
	// there is only one path flag and its for private key 
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

	if *keytype != "" || *keysize != 0 || *alg != "" {
		// creating private key
		for *interactive && !(*keytype ==  "RSA" || *keytype ==  "ECDSA") {
			// prompt
			fmt.Println("This is a list of private key types to choose from:")
			fmt.Println("RSA")
			fmt.Println("ECDSA")
			fmt.Println("Please provide type of private key.")
			fmt.Fscan(reader, keytype)

		}

		if !*interactive && !(*keytype ==  "RSA" || *keytype ==  "ECDSA") {
			log.Fatal("Type of private key does not fit available values.\nAvailable types:\nRSA\nECDSA")
		}

		for *interactive && *keytype ==  "RSA" && !(*keysize == 128 || *keysize == 192 || *keysize == 256)  {
			// prompt
			fmt.Println("This is a list of RSA private key sizes to choose from:")
			fmt.Println("128")
			fmt.Println("192")
			fmt.Println("256")
			fmt.Println("Please provide size of private key: ")
			//var keySize int
			fmt.Fscan(reader, keysize)
			//*keysize = keySize
		}

		if !*interactive && *keytype ==  "RSA" && !(*keysize == 128 || *keysize == 192 || *keysize == 256) {
			log.Fatalf("Size: %d of private key does not fit available values for RSA type.\nAvailable sizes for RSA:\n128\n192\n256\n", keysize)
		}

		for *interactive && *keytype ==  "ECDSA" && !(*keysize == 256) {
			// prompt
			fmt.Println("This is a list of ECDSA private key sizes to choose from:")
			fmt.Println("256")
			fmt.Println("Please provide size of private key.")
			fmt.Fscan(reader, keysize)
		}

		if !*interactive && *keytype ==  "ECDSA" && !(*keysize == 256) {
			log.Fatalf("Size: %d of private key does not fit available values for ECDSA type.\nAvailable sizes for ECDSA:\n256\n", keysize)
		}

		for *interactive && !(*alg == "AES128" || *alg == "AES192" || *alg == "AES256" || *alg == "") {
			// prompt
			fmt.Println("This is a list of private key encryption algorithms to choose from:")
			fmt.Println("AES128")
			fmt.Println("AES192")
			fmt.Println("AES256")
			fmt.Println("Please provide correct algorithm for private key encryption.")
			fmt.Fscan(reader, alg)
		}

		if !*interactive && !(*alg == "AES128" || *alg == "AES192" || *alg == "AES256") {
			log.Fatalf("Encryption algorithm: %s of private key does not fit available values.\nAvailable encryption algorithms:\nAES128\nAES192\nAES256", alg)
		}
		
		for *interactive && *alg != "" && *passphrase == "" {
			// prompt
			fmt.Println("Provide passphrase for private key: ")
			passphrase_bytes, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatal(err, " passphrase input error")
			}
			fmt.Println("Enter same passphrase again: ")
			compare_bytes, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatal(err, " passphrase input error")
			}
			if !bytes.Equal(passphrase_bytes, compare_bytes) {
				log.Fatal("Passwords do not match. Try again.")
			} else {
				*passphrase = string(passphrase_bytes)
			}
		}

		if !*interactive && *alg != "" && *passphrase == "" {
			log.Fatal("Passphrase for private key encryption is empty")
		}

		var keyType string 

		switch *keytype {
		case "RSA":
			keyType = privateKey.RSA
		case "ECDSA":
			keyType = privateKey.ECDSA
		default:
			log.Fatalf("Unknown private key type: %s.\n", *keytype)
		}

		var algorithm x509.PEMCipher

		switch *alg {
		case "AES128":
			algorithm = privateKey.AES128
		case "AES192":
			algorithm = privateKey.AES192
		case "AES256":
			algorithm  = privateKey.AES256
		case "":
			algorithm = 0
		default:
			log.Fatalf("Unknown private key encryption algorithm: %s.\n", *alg)
		}

		for *interactive && *keypath == "" {
			// prompt
			fmt.Println("Please provide path for private key: ")
			fmt.Fscan(reader, keypath)
		}

		if !*interactive && *keypath == "" {
			log.Fatal("Path for private key encryption is empty")
		}

		// generate key
		privkey, err := privateKey.Generate(keyType, *keysize)
		if err != nil {
			log.Fatal(err, " error while generating private key")
		}
		err = privateKey.Write(*keypath, privkey, *passphrase, algorithm)
		if err != nil {
			log.Fatal(err, " error while writing private key to file")
		} 
	}

	if *decrypt != "" || *env_decrypt != "" {
		if *keypath == "" {
			*keypath = os.Getenv("EEV_privatekey")
			for *interactive && *keypath == "" {
				// prompt
				fmt.Println("Please provide path for private key: ")
				fmt.Fscan(reader, keypath)
			}

			if !*interactive && *keypath == "" {
				log.Fatal("Path of private key not set")
			}
		}

		privkey, err := ioutil.ReadFile(*keypath)
		if err != nil {
			log.Fatal(err, " private key reading error")
		}

		block, _ := pem.Decode(privkey)
		if *interactive && x509.IsEncryptedPEMBlock(block) && *passphrase == "" {
			// prompt
			fmt.Println("Provide passphrase for private key: ")
			passphrase_bytes, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatal(err, " passphrase input error")
			}
			fmt.Println("Enter same passphrase again: ")
			compare_bytes, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatal(err, " passphrase input error")
			}
			if !bytes.Equal(passphrase_bytes, compare_bytes) {
				log.Fatal("Passwords do not match. Try again.")
			} else {
				*passphrase = string(passphrase_bytes)
			}
		}

		if !*interactive && x509.IsEncryptedPEMBlock(block) && *passphrase == "" {
			log.Fatal("Passphrase for private key decryption is empty")
		}

		if x509.IsEncryptedPEMBlock(block) {
			block, _ := pem.Decode(privkey)
			if block == nil {
				log.Fatal("Decoded pem block is empty")
			}
			block.Bytes, err = x509.DecryptPEMBlock(block, []byte(*passphrase))
			privkey = pem.EncodeToMemory(block)
		}

		if *env_decrypt != "" {
			*decrypt = os.Getenv(*env_decrypt)
		}

		if *decrypt == "" {
			fmt.Println("Provide value to be decrypted")
			fmt.Fscan(reader, decrypt)
		}
		// check if key is 
		// decrypting value
		decrypted, err := AES.Decrypt(privkey, *decrypt)
		if err != nil {
			log.Fatal(err, "Error during decrypting value")
		}

		fmt.Println(string(decrypted))
	}

	if *encrypt != "" || *env_encrypt != "" {
		if *keypath == "" {
			*keypath = os.Getenv("EEV_privatekey")
			for *interactive && *keypath == ""  {
				// prompt
				fmt.Println("Please provide path for private key: ")
				fmt.Fscan(reader, keypath)
			}

			if !*interactive && *keypath == "" {
				log.Fatal("Path of private key not set")
			}
		}

		privkey, err := ioutil.ReadFile(*keypath)
		if err != nil {
			log.Fatal(err, " private key reading error")
		}

		block, _ := pem.Decode(privkey)
		if *interactive && x509.IsEncryptedPEMBlock(block) && *passphrase == "" {
			// prompt
			fmt.Println("Provide passphrase for private key: ")
			passphrase_bytes, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatal(err, " passphrase input error")
			}
			fmt.Println("Enter same passphrase again: ")
			compare_bytes, err := terminal.ReadPassword(int(syscall.Stdin))
			if err != nil {
				log.Fatal(err, " passphrase input error")
			}
			if !bytes.Equal(passphrase_bytes, compare_bytes) {
				log.Fatal("Passwords do not match. Try again.")
			} else {
				*passphrase = string(passphrase_bytes)
			}
		}

		if !*interactive && x509.IsEncryptedPEMBlock(block) && *passphrase == "" {
			log.Fatal("Passphrase for private key decryption is empty")
		}

		if x509.IsEncryptedPEMBlock(block) {
			block, _ := pem.Decode(privkey)
			if block == nil {
				log.Fatal("Decoded pem block is empty")
			}
			block.Bytes, err = x509.DecryptPEMBlock(block, []byte(*passphrase))
			privkey = pem.EncodeToMemory(block)
		}
		// encrypting value

		if *env_encrypt != "" {
			*encrypt = os.Getenv(*env_encrypt)
		}

		if *encrypt == "" {
			fmt.Println("Provide value to be decrypted")
			fmt.Fscan(reader, encrypt)
		}

		encrypted, err := AES.Encrypt(privkey, *encrypt)
		if err != nil {
			log.Fatal(err, "Error during encrypting value")
		}

		fmt.Println(encrypted)

		// switch os := runtime.GOOS; os {
		// case "darwin":
		// 	fmt.Println("OS X.")
		// case "linux":
		// 	fmt.Println("Linux.")
		// case "windows":
		// 	fmt.Println("Windows.")
		// default:
		// 	// freebsd, openbsd,
		// 	// plan9, windows...
		// 	fmt.Printf("%s.\n", os)
		// }
	}
}