package main

import (
	privateKey "github.com/Apurer/eev-tool/privatekey"
	AES "github.com/Apurer/eev-tool/aes"
	"flag"
	"log"
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
		*keypath, *passphrase, err = privateKey.Create(*keytype, *keysize, *keypath, *alg, *passphrase, *interactive)
		if err != nil {
			log.Fatal(err)
		}
	}
	if *decrypt != "" || *env_decrypt != "" {
		*keypath, *passphrase, err = AES.Decrypt(*decrypt, *env_decrypt, *keypath, *passphrase, *interactive)
		if err != nil {
			log.Fatal(err)
		}
	}
	if *encrypt != "" || *env_encrypt != "" {
		err = AES.Encrypt(*encrypt, *env_encrypt, *keypath, *passphrase, *interactive)
		if err != nil {
			log.Fatal(err)
		}
	}
}
