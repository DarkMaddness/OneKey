package engine

import (
	"bufio"
	"bytes"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/1Password/srp"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

type state int

const (
	PARSE_URL state = iota
	VERIFY_URL
	OPTIONS
	REGISTER
	AUTHENTICATE
	LOG_OUT
	ERROR
	EXIT
)

var (
	ErrUsernameTaken    = errors.New("Username Taken.")
	ErrUsernameNotFound = errors.New("Username not found.")
	ErrBadPassword      = errors.New("Incorrect Password.")
)

func ParseURL() (state state, serverURL string, err error) {
	if len(os.Args) != 2 {
		return ERROR, "", errors.New("The client takes exactly 1 additional argument, The base url of the server you are trying to connect to. Ex 192.168.1.47:32500 or mypasswordmanager.ca")
	}
	return VERIFY_URL, os.Args[1], nil
}

func VerifyURL(url string) (state state, err error) {

	// Send GET request to server.
	res, err := http.Get("http://" + url + "/ping")
	if err != nil {
		return ERROR, err
	}
	defer res.Body.Close()

	// Check status code.
	if res.StatusCode != http.StatusOK {
		return ERROR, fmt.Errorf("Server responded with status code:  %d", res.StatusCode)
	}

	// Decode response.
	decoded := struct {
		Name    string
		Version string
	}{}
	if err = json.NewDecoder(res.Body).Decode(&decoded); err != nil {
		return ERROR, err
	}

	// Verify response is what we expect.
	if decoded.Name != "Onekey" {
		return ERROR, errors.New("Incorrect name, you may want to check your URL.")
	} else if decoded.Version != "Alpha" {
		return ERROR, errors.New("Incompatible version")
	}
	fmt.Println("Connected to server.")
	return OPTIONS, nil
}

func Options(loggedIn bool) (state state) {
	scanner := bufio.NewScanner(os.Stdin)

	// Show options for a loggend in user if they are logged in, otherwise show options for a not logged in user.
	if loggedIn {
		const (
			Log_out int = iota
		)
		for {
			fmt.Println("Options:\n" +
				"0: Log Out")
			fmt.Println("Choose one of the options by entering it's number.")

			// Scan in from the terminal.
			if !scanner.Scan() {
				_ = scanner.Err()
				fmt.Println("Error parsing choice. Please choose again.")
				continue
			}

			// Parse out the first word/number/phrase.
			choice, err := strconv.Atoi(strings.Split(scanner.Text(), " ")[0])
			if err != nil {
				fmt.Println("Error parsing choice. Please choose again.")
				continue
			}

			// Switch on the word/number/phrase.
			switch choice {
			case Log_out:
				return LOG_OUT
			default:
				fmt.Println("Choice outside expected range. Please choose again.")
				continue
			}
		}
	} else {
		const (
			Register int = iota
			Log_In
			Exit
		)
		for {
			fmt.Println("Options:\n" +
				"0: Register\n" +
				"1: Log In\n" +
				"2: Exit")
			fmt.Println("Choose one of the options by entering it's number.")

			// Scan in from the terminal.
			if !scanner.Scan() {
				_ = scanner.Err()
				fmt.Println("Error parsing choice. Please choose again.")
				continue
			}

			// Parse out the first word/number/phrase.
			choice, err := strconv.Atoi(strings.Split(scanner.Text(), " ")[0])
			if err != nil {
				fmt.Println("Error parsing choice. Please choose again.")
				continue
			}

			// Switch on the word/number/phrase.
			switch choice {
			case Register:
				return REGISTER
			case Log_In:
				return AUTHENTICATE
			case Exit:
				return EXIT
			default:
				fmt.Println("Choice outside expected range. Please choose again.")
				continue
			}
		}
	}
}

func Register(serverURL string) (state state, err error) {
	password := ""

	// Get a password from the user, or return to options if user hits esc.
	for {
		fmt.Println("Enter your password. (Press esc to return to option select.)")
		password, err = getRawInput(true)
		fmt.Println()
		if err != nil {
			return ERROR, err
		} else if password == "" { // This will be the selected branch if they hit esc.
			return OPTIONS, nil
		} else if len(password) < 8 {
			println("Password must be at least 8 characters.")
			continue
		}
		break
	}

	// Confirm the password, or return to options if user hits esc.
	for {
		fmt.Println("Confirm your password. (Press esc to return to option select.)")
		confirm, err := getRawInput(true)
		fmt.Println()
		if err != nil {
			return ERROR, err
		} else if confirm == "" { // This will be the selected branch if they hit esc.
			return OPTIONS, nil
		} else if confirm != password {
			println("Passwords do not match.")
			continue
		}
		break
	}

	// Get a username from the user and try to register the account. If the username is already taken, reprompt for a new username.
	for {

		// Get username.
		fmt.Println("Enter username. (Press esc to return to option select.)")
		username, err := getRawInput(false)
		fmt.Println()
		if err != nil {
			return ERROR, err
		} else if username == "" {
			return OPTIONS, nil
		}

		// Form and send request.
		err = RegistrationHelper(password, username, serverURL)
		if err != nil {
			if errors.Is(err, ErrUsernameTaken) {
				fmt.Println("Username already in use, you must choose a different one.")
				continue
			} else {
				return ERROR, err
			}
		}

		fmt.Println("Account registered.")
		return OPTIONS, nil
	}
}

func RegistrationHelper(password string, username string, serverURL string) (err error) {

	// Generate the salt and srp verifier.
	salt := make([]byte, 16)
	rand.Read(salt)
	_, srpKey, err := deriveKeys([]byte(password), salt)
	if err != nil {
		return err
	}
	srpClient := srp.NewSRPClient(srp.KnownGroups[srp.RFC5054Group4096], big.NewInt(0).SetBytes(srpKey), nil)
	verifier, err := srpClient.Verifier()
	if err != nil {
		return err
	}

	// Construct request body.
	req := mustMarshal(struct {
		Username string
		Salt     []byte
		Verifier *big.Int
	}{
		Username: username,
		Salt:     salt,
		Verifier: verifier,
	})

	// Send request.
	res, err := http.Post("http://"+serverURL+"/register", "application/json", bytes.NewReader(req))
	if err != nil {
		return err
	}
	res.Body.Close()

	// Check status code.
	if res.StatusCode == http.StatusConflict {
		return ErrUsernameTaken
	} else if res.StatusCode == http.StatusBadRequest {
		return errors.New("Something went wrong, server returned status code: 400 Bad Request.")
	} else if res.StatusCode != http.StatusCreated {
		return fmt.Errorf("Server responded with status code: %d", res.StatusCode)
	}

	return nil
}

func Authenticate(serverURL string) (state state, success bool, sessionToken [16]byte, adminToken [16]byte, aesKey []byte, username string, err error) {
	for {

		// Get username.
		fmt.Println("Enter your username. (Press esc to return back to option select.)")
		username, err := getRawInput(false)
		fmt.Println()
		if err != nil {
			return ERROR, false, [16]byte{}, [16]byte{}, nil, "", err
		} else if username == "" {
			return OPTIONS, false, [16]byte{}, [16]byte{}, nil, "", nil
		}

		// Get password.
		fmt.Println("Enter your password. (Press esc to return back to option select.)")
		password, err := getRawInput(true)
		fmt.Println()
		if err != nil {
			return ERROR, false, [16]byte{}, [16]byte{}, nil, "", err
		} else if password == "" {
			return OPTIONS, false, [16]byte{}, [16]byte{}, nil, "", nil
		}

		// Attempt authentication.
		sessionToken, adminToken, aesKey, err = AuthenticationHelper(serverURL, username, password)
		if err != nil {
			if errors.Is(err, ErrUsernameNotFound) {
				fmt.Println("Username not found.")
				continue
			} else if errors.Is(err, ErrBadPassword) {
				fmt.Println("Invalid Password")
				continue
			} else {
				return ERROR, false, [16]byte{}, [16]byte{}, nil, "", err
			}
		}
		return OPTIONS, true, sessionToken, adminToken, aesKey, username, nil
	}
}

func AuthenticationHelper(serverURL string, username string, password string) (sessionToken [16]byte, adminToken [16]byte, aesKey []byte, err error) {

	// Send request for salt.
	saltRes, err := http.Get("http://" + serverURL + "/salt/" + username)
	if err != nil {
		return [16]byte{}, [16]byte{}, nil, err
	}
	defer saltRes.Body.Close()
	// Check status code.
	if saltRes.StatusCode == http.StatusBadRequest {
		return [16]byte{}, [16]byte{}, nil, ErrUsernameNotFound
	} else if saltRes.StatusCode != http.StatusOK {
		return [16]byte{}, [16]byte{}, nil, fmt.Errorf("Server responded with status code: %d", saltRes.StatusCode)
	}

	// Extract salt.
	saltBody := struct {
		Salt []byte
	}{}
	err = json.NewDecoder(saltRes.Body).Decode(&saltBody)
	saltRes.Body.Close()
	if err != nil {
		return [16]byte{}, [16]byte{}, nil, err
	}
	salt := saltBody.Salt

	// Derive keys.
	aesKey, srpKey, err := deriveKeys([]byte(password), salt)
	if err != nil {
		return [16]byte{}, [16]byte{}, nil, err
	}

	// Start handshake.
	srpClient := srp.NewSRPClient(srp.KnownGroups[srp.RFC5054Group4096], big.NewInt(0).SetBytes(srpKey), nil)
	req := mustMarshal(struct {
		Username string
		A        *big.Int
	}{
		Username: username,
		A:        srpClient.EphemeralPublic(),
	})

	// Send request.
	auth1Res, err := http.Post("http://"+serverURL+"/auth1", "application/json", bytes.NewReader(req))
	if err != nil {
		return [16]byte{}, [16]byte{}, nil, err
	}
	defer auth1Res.Body.Close()
	// Check status code.
	if auth1Res.StatusCode == http.StatusBadRequest {
		return [16]byte{}, [16]byte{}, nil, ErrUsernameNotFound
	} else if auth1Res.StatusCode != http.StatusOK {
		return [16]byte{}, [16]byte{}, nil, fmt.Errorf("Server responded with status code: %d", auth1Res.StatusCode)
	}

	// Extract B, Server Proof (M2), and AuthID.
	auth1Body := struct {
		B      *big.Int
		M2     []byte
		AuthID string
	}{}
	err = json.NewDecoder(auth1Res.Body).Decode(&auth1Body)
	auth1Res.Body.Close()
	if err != nil {
		return [16]byte{}, [16]byte{}, nil, err
	}

	// Continue handshake.
	err = srpClient.SetOthersPublic(auth1Body.B)
	if err != nil {
		return [16]byte{}, [16]byte{}, nil, err
	}

	// Generate key. This isn't being used, but generating it is a hard requirement for GoodServerProof() and ClientProof().
	_, err = srpClient.Key()
	if err != nil {
		return [16]byte{}, [16]byte{}, nil, err
	}

	// Check server proof. If it passes then generate our client proof.
	// If the server proof fails, then we know that the password was wrong,
	// though for the sake of keeping the server state cleaner, we will complete the
	// second part of the srp handskae regardless of wheather the server proof passes.
	// In the case the server proof fails, we will pass an empty slice as our client proo.
	m1 := make([]byte, 0)
	if srpClient.GoodServerProof(salt, username, auth1Body.M2) {
		m1, err = srpClient.ClientProof()
		if err != nil {
			return [16]byte{}, [16]byte{}, nil, err
		}
	}
	req = mustMarshal(struct {
		M1     []byte
		AuthID string
	}{
		M1:     m1,
		AuthID: auth1Body.AuthID,
	})

	// Send request.
	auth2Res, err := http.Post("http://"+serverURL+"/auth2", "application/json", bytes.NewReader(req))
	if err != nil {
		return [16]byte{}, [16]byte{}, nil, err
	}
	defer auth2Res.Body.Close()
	// Check status code.
	if auth2Res.StatusCode == http.StatusBadRequest {
		return [16]byte{}, [16]byte{}, nil, ErrBadPassword
	} else if auth2Res.StatusCode != http.StatusOK {
		return [16]byte{}, [16]byte{}, nil, fmt.Errorf("Server responded with status code: %d", auth2Res.StatusCode)
	}

	// Extract tokens.
	auth2Body := struct {
		SessionToken []byte
		AdminToken   []byte
	}{}
	err = json.NewDecoder(auth2Res.Body).Decode(&auth2Body)
	auth2Res.Body.Close()
	if err != nil {
		return [16]byte{}, [16]byte{}, nil, err
	}
	return [16]byte(auth2Body.SessionToken), [16]byte(auth2Body.AdminToken), aesKey, nil
}

func LogOut(serverURL string, sessionTk [16]byte) (state state, sessionActive bool, sessionToken [16]byte, adminToken [16]byte, aesKey []byte, username string, err error) {

	// Construct request body.
	req := mustMarshal(struct {
		SessionToken [16]byte
	}{
		SessionToken: sessionTk,
	})

	// Send first request.
	attempt1, err := http.Post("http://"+serverURL+"/logout", "application/json", bytes.NewReader(req))

	// If we got a response then close the body.
	if err == nil {
		attempt1.Body.Close()
	}

	// Check if it succeded. If it failed then try once more.
	if err != nil || attempt1.StatusCode != http.StatusOK {

		// Send second request.
		attempt2, err := http.Post("http://"+serverURL+"/logout", "application/json", bytes.NewReader(req))

		// If we get a response then close the body.
		if err == nil {
			attempt2.Body.Close()
		}
	}

	// Regardless of response set tokens and keys to type initialization values.
	// Even if the requests failed, we keep the appearance that they succeded.
	return OPTIONS, false, [16]byte{}, [16]byte{}, nil, "", nil
}

func getRawInput(hidden bool) (word string, err error) {

	// Our return string.
	key := make([]byte, 0)

	// Create a reader, and set the terminal to raw mode.
	reader := bufio.NewReader(os.Stdin)
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}

	// Make it so the terminal will revert to normal mode once the function returns.
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	for {

		// Create a charater holder, and read 1 byte from standard in.
		var char byte
		char, err = reader.ReadByte()
		if err != nil {
			return "", err
		}

		// Switch on the character.
		switch char {

		// Tab and space.
		case 9, 32:
			continue

		// Enter.
		case 13:
			return string(key), nil

		// Esc.
		case 27:

			// We must check whether esc was pressed, or if it is the start of an escape sequence like an arrow key.
			// To do that we are going to give it a moment, and then we are going to check the buffer, if it is empty then it was
			// the esc key, if there is something in the buffer then it was something else, so we will flush the buffer, and continue.
			time.Sleep(1 * time.Millisecond)
			if reader.Buffered() == 0 {
				return "", nil
			} else {
				reader.Discard(reader.Buffered())
			}

		// Backspace.
		case 127:

			// If the key is not empty, then remove the last character.
			if len(key) != 0 {

				// Remove last char from key.
				key = key[:len(key)-1]

				// Remove last char from terminal.
				fmt.Print("\033[D\033[K")
			}
		default:

			// Add the character to key.
			key = append(key, char)

			// If hidden is true print an asterisk, else print the typed character.
			if hidden {
				fmt.Printf("%c", '*')
			} else {
				fmt.Printf("%c", char)
			}
		}
	}
}

func deriveKeys(password []byte, salt []byte) (aesKey []byte, srpKey []byte, err error) {
	const (
		AES_INFO string = "AES256_Info_String"
		SRP_INFO string = "SRP_Info_String"
	)
	// Derive keys.
	masterKey := argon2.IDKey(password, salt, 1, 2048*1024, 4, 32)
	aesKey, err = hkdf.Key(sha256.New, masterKey, salt, AES_INFO, 32)
	if err != nil {
		return nil, nil, err
	}
	srpKey, err = hkdf.Key(sha256.New, masterKey, salt, SRP_INFO, 32)
	if err != nil {
		return nil, nil, err
	}
	return aesKey, srpKey, nil
}

func mustMarshal(v any) []byte {
	ret, err := json.Marshal(v)
	if err != nil {
		panic("Json Marshaling failed: " + err.Error())
	}
	return ret
}
