// Don't trust me with cryptography.

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/docopt/docopt-go"
	"golang.org/x/crypto/argon2"
)

// This is not a serious implementation. A serious implementation would:
// 1. suggest a more sane notifier
// 2. encode argon2 params in the initial seed words i.e. dsw:<m>:<i>:<t>:32:<seedWords>
// 3. have error checking for the input bytes to check it's not randomly corrupt
// 4. make sure it follows BIP39
// 5. think more about which hash function to use
// 6. have code highly optimized to close as many vectors where an attacker could gain advantage
// 7. have tests

const USAGE = `dsw

Usage:
  dsw create <seed> [--verbose]
  dsw recover <seed> [--verbose]

Make sure to save your initial seed words and the checkpoint input.
`

type Argon2Params struct {
	memory     uint32
	iterations uint32
	threads    uint8
	keyLen     uint32
}

func main() {
	var err error

	flag.Parse()
	log.SetPrefix("<> ")

	opts, err := docopt.ParseArgs(USAGE, flag.Args(), "")
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// Params for ~1 second on my PC
	p := &Argon2Params{
		memory:     64 * 1024,
		iterations: 100,
		threads:    16,
		keyLen:     32,
	}

	wordlist := ReadWords()
	verbose, _ := opts.Bool("--verbose")

	switch {
	case opts["create"].(bool):
		seed := opts["<seed>"].(string)
		if len(strings.Split(seed, " ")) != 24 {
			fmt.Println("Error: seed words passed is not 24 words.")
			return
		}
		finalInput, err := Create(300, 5, []byte(seed), p, verbose)
		if err != nil {
			log.Fatal(err)
		}
		// Transform the hash to seed words
		delayedSeed := H2Seed(finalInput, wordlist)
		fmt.Println("\nReal seed words: ", delayedSeed)
	case opts["recover"].(bool):
		seed := opts["<seed>"].(string)
		if len(strings.Split(seed, " ")) != 24 {
			fmt.Println("Error: seed words passed is not 24 words.")
			return
		}
		finalInput, err := Recover(300, 5, []byte(seed), p, verbose)
		if err != nil {
			log.Fatal(err)
		}
		// Transform the hash to seed words
		delayedSeed := H2Seed(finalInput, wordlist)
		fmt.Println("\nReal seed words: ", delayedSeed)
	}
}

// Starts with an input passed and builds a hashchain of length n from it
func BuildHashchain(n int, input []byte, p *Argon2Params, verbose bool) ([]byte, error) {
	var err error
	var hash []byte

	start := time.Now()
	for i := 0; i < n; i++ {
		hash, err = H(input, p)
		if err != nil {
			log.Fatal(err)
		}
		if verbose {
			fmt.Println("Iterations left: ", n-i)
			fmt.Println(hex.EncodeToString(hash))
		}
		input = hash
	}
	elapsed := time.Since(start)
	if verbose {
		log.Printf("Hash took %s", elapsed)
	}

	return input, nil
}

// Computes the left side of the hashchain (up to the checkpoint)
func ComputeLeft(n int, input []byte, p *Argon2Params, verbose bool) []byte {
	// Builds the hashchain up to the checkpoint
	input, err := BuildHashchain(n, input, p, verbose)
	if err != nil {
		log.Fatal(err)
	}
	// Derive the username and password for the notifier in case we need it
	username, password := DeriveUsernamePassword(input)
	fmt.Println("Email username:", username)
	fmt.Println("Email password:", password)
	fmt.Println("")

	return input
}

// Computes the right side of the hashchain (from the checkpoint to the end)
func ComputeRight(n int, input []byte, p *Argon2Params, verbose bool) []byte {
	finalInput, err := BuildHashchain(n, input, p, verbose)
	if err != nil {
		log.Fatal(err)
	}
	return finalInput
}

// Creates a hashchain of length N with M being the checkpoint. The genesis is the given input
func Create(n int, m int, input []byte, p *Argon2Params, verbose bool) ([]byte, error) {
	leftInput := ComputeLeft(m, input, p, verbose)

	// Create a random checkpoint input
	checkpointInput, err := RndBytes(32)
	if err != nil {
		log.Fatal(err)
	}
	checkpointInputHex := hex.EncodeToString(checkpointInput)
	fmt.Println("Generated checkpoint input: ", checkpointInputHex)
	// Confirmation step
	fmt.Println(`
Save the checkpoint input to your notifier.

Protonmail notifier:
1. Create a protonmail account with the username and password described above
2. Send an email to the same account you created with the content being the checkpoint input as described above
3. Download and login to protonmail app on your Android phone

This way, if you're logged into this account on your mobile, you'll get notified whenever someone accesses the email to read the secret checkpoint input.

Once you're done, please copy the checkpoint input and paste it here to confirm you've copied the right thing. Checkpoint input:
	`)
	var checkpointInputStr string
	_, err = fmt.Scanln(&checkpointInputStr)
	if err != nil {
		log.Fatal(err)
	}
	if checkpointInputStr != checkpointInputHex {
		log.Fatal("Incorrect paste of the checkpoint input. Exiting.")
	}

	// Add the checkpoint input to our input and compute the right side
	joinedCheckpointInput := append(leftInput[:], checkpointInput[:]...)
	finalInput := ComputeRight(n-m, joinedCheckpointInput, p, verbose)
	return finalInput, nil
}

// Recovers a hashchain of length N with M being the checkpoint. The genesis is the given input
func Recover(n int, m int, input []byte, p *Argon2Params, verbose bool) ([]byte, error) {
	leftInput := ComputeLeft(m, input, p, verbose)

	// Ask the user to provide the checkpoint input
	fmt.Println(`Please get the checkpoint input from your notifier (i.e. email) and paste it below.

Example Protonmail notifier recovery:
1. Login to a protonmail account with the username and password described above
2. Find the email with the checkpoint input string and paste the string to the terminal
3. Wait for the program to compute the remaining hashchain

Paste the checkpoint input here:`)
	var checkpointInputStr string
	_, err := fmt.Scanln(&checkpointInputStr)
	if err != nil {
		log.Fatal(err)
	}
	checkpointInput, err := hex.DecodeString(checkpointInputStr)
	if err != nil {
		log.Fatal(err)
	}

	// Add the checkpoint input to our input and compute the right side
	joinedCheckpointInput := append(leftInput[:], checkpointInput[:]...)
	finalInput := ComputeRight(n-m, joinedCheckpointInput, p, verbose)
	return finalInput, nil
}

func DeriveUsernamePassword(hash []byte) (string, string) {
	passwordHash := sha256.Sum256(hash)
	usernameHash := sha256.Sum256(passwordHash[:])
	username := "dsw0" + hex.EncodeToString(usernameHash[:])
	password := hex.EncodeToString(passwordHash[:])

	return username[:32], password[:32]
}

// TODO: fix this
func H2Seed(hash []byte, wordlist []string) []string {
	result := []string{}
	// compute hash H, pick word, set hash
	for i := 0; i < 24; i++ {
		// Compute hash h1 from hash
		h1 := sha256.Sum256(hash)
		// Add word for h1
		myUint := binary.BigEndian.Uint64(h1[:])
		result = append(result, wordlist[myUint%2048])
		// set hash to h1
		hash = h1[:]
	}

	return result
}

// Computes the Argon2 hash
func H(input []byte, p *Argon2Params) ([]byte, error) {
	salt := []byte{}
	hash := argon2.IDKey(input, salt, p.iterations, p.memory, p.threads, p.keyLen)

	return hash, nil
}

func RndBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Reads the BIP39 words
func ReadWords() []string {
	result := []string{}
	file, err := os.Open("english.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		result = append(result, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return result
}
