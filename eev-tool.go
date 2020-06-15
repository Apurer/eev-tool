package main 

import (
	"golang.org/x/crypto/ssh/terminal"
	"runtime"
	"syscall"
	"strings"
	"bufio"
	"flag"
    "fmt"
    "os"
)

// all values will have to be passed here 

func InteractiveMode() {

}
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
		- key size (if is provided it means user wants to create private key - info for non interactive mode)
		- passphrase - optional (before chosing algo for encryption)
		- alg for encryption of private key - optional (if is provided then user is asked to provide passphrase in interactive input)

	- encrypt value - by default using private key set in env variables (for non interactive mode it has to be specified what user wants to do - encrypt or decrypt)
	- encrypt - flag: -encrypt=true
		- value to encrypt
		- path to private key or use env variable
		- passphrase - optional if private key is encrypted (if not provided and private key is encrypted then use prompt)

	- decrypt value - by default using private key set in env variables - flag: -decrypt=true
		- value to decrypt
		- path to private key or use env variable (tries to use env variable by default if not provided but if it doesn't exist prompt is used)
		- passphrase - optional if private key is encrypted (if not provided and private key is encrypted then use prompt)
	- decrypt value - in interactive mode user can choose if he wants to copy value to clipboard - if value in env variable is not set
	- decrypting value can be done by providing value or name of env variable - give user option
		- decrypt value
		- decrypt env variable
			- copy value to clipboard
			- print output in terminal
*/	
func main() {

	// check flags regarding encrypting or decrypting value
	// check if key type or key size is not empty
	// else use interactive mode to define what is user intend

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Enter Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err == nil {
		fmt.Println("\nPassword typed: " + string(bytePassword))
		fmt.Println(int(syscall.Stdin))
	}
	password := string(bytePassword)

	switch os := runtime.GOOS; os {
	case "darwin":
		fmt.Println("OS X.")
	case "linux":
		fmt.Println("Linux.")
	case "windows":
		fmt.Println("Windows.")
	default:
		// freebsd, openbsd,
		// plan9, windows...
		fmt.Printf("%s.\n", os)
	}
}
}