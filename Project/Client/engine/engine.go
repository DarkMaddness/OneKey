package engine

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

type State int

const (
	PARSE_URL State = iota
	VERIFY_URL
	OPTIONS
	REGISTER
	AUTHENTICATE
	RE_AUTHENTICATE
	ENTRIES
	GET_ENTRY
	NEW_ENTRY
	CREATE_ENTRY
	EDIT_ENTRY_DETAILS
	UPDATE_ENTRY
	DELETE_ENTRY
	LOG_OUT
	DELETE_ACCOUNT
	ERROR
	EXIT
)
const NO_RETRY State = -1

var (
	ErrUsernameTaken    = errors.New("Username Taken.")
	ErrUsernameNotFound = errors.New("Username not found.")
	ErrBadPassword      = errors.New("Incorrect Password.")
)

func ParseURL() (state State, serverURL string, err error) {
	if len(os.Args) != 2 {
		return ERROR, "", errors.New("The client takes exactly 1 additional argument, The base url of the server you are trying to connect to. Ex 192.168.1.47:32500 or mypasswordmanager.ca")
	}
	return VERIFY_URL, os.Args[1], nil
}

func VerifyURL(url string) (state State, err error) {

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

func Options(loggedIn bool) (state State) {
	scanner := bufio.NewScanner(os.Stdin)

	// Show options for a loggend in user if they are logged in, otherwise show options for a not logged in user.
	if loggedIn {
		const (
			Log_out int = iota
			Get_entries
			Delete_account
		)
		fmt.Println("Options:\n" +
			"0: Log Out\n" +
			"1: Get Entries\n" +
			"2: Delete Account")
		fmt.Print("Choice: ")
		for {

			// Scan in from the terminal.
			if !scanner.Scan() {
				_ = scanner.Err()
				fmt.Print("\033[A\033[2K")
				fmt.Print("Error parsing choice. Please choose again: ")
				continue
			}

			// Parse out the first word/number/phrase.
			choice, err := strconv.Atoi(strings.Split(scanner.Text(), " ")[0])
			if err != nil {
				fmt.Print("\033[A\033[2K")
				fmt.Print("Error parsing choice. Please choose again: ")
				continue
			}

			// Switch on the word/number/phrase.
			switch choice {
			case Log_out:
				fmt.Print("\033[5A\033[J")
				return LOG_OUT
			case Get_entries:
				fmt.Print("\033[5A\033[J")
				return ENTRIES
			case Delete_account:
				fmt.Print("\033[5A\033[J")
				return DELETE_ACCOUNT
			default:
				fmt.Print("\033[A\033[2K")
				fmt.Print("Choice outside expected range. Please choose again: ")
				continue
			}
		}
	} else {
		const (
			Exit int = iota
			Log_In
			Register
		)
		fmt.Println("Options:\n" +
			"0: Exit\n" +
			"1: Log In\n" +
			"2: Register")
		fmt.Print("Choice: ")
		for {

			// Scan in from the terminal.
			if !scanner.Scan() {
				_ = scanner.Err()
				fmt.Print("\033[A\033[2K")
				fmt.Print("Error parsing choice. Please choose again: ")
				continue
			}

			// Parse out the first word/number/phrase.
			choice, err := strconv.Atoi(strings.Split(scanner.Text(), " ")[0])
			if err != nil {
				fmt.Print("\033[A\033[2K")
				fmt.Print("Error parsing choice. Please choose again: ")
				continue
			}

			// Switch on the word/number/phrase.
			switch choice {
			case Exit:
				fmt.Print("\033[5A\033[J")
				return EXIT
			case Log_In:
				fmt.Print("\033[5A\033[J")
				return AUTHENTICATE
			case Register:
				fmt.Print("\033[5A\033[J")
				return REGISTER
			default:
				fmt.Print("\033[A\033[2K")
				fmt.Print("Choice outside expected range. Please choose again: ")
				continue
			}
		}
	}
}

func Register(serverURL string) (state State, err error) {
	password := ""

	// Get a password from the user, or return to options if user hits esc.
	for {
		fmt.Print("(Press esc to return to option select.) Enter your password: ")
		password, err = getRawInput(true, "")
		fmt.Print("\n\033[A\033[2K")
		if err != nil {
			return ERROR, err
		} else if password == "" { // This will be the selected branch if they hit esc.
			return OPTIONS, nil
		} else if len(password) < 8 {
			fmt.Print("Password must be at least 8 characters | ")
			continue
		}
		break
	}

	// Confirm the password, or return to options if user hits esc.
	for {
		fmt.Print("(Press esc to return to option select.) Confirm your password: ")
		confirm, err := getRawInput(true, "")
		fmt.Print("\n\033[A\033[2K")
		if err != nil {
			return ERROR, err
		} else if confirm == "" { // This will be the selected branch if they hit esc.
			return OPTIONS, nil
		} else if confirm != password {
			fmt.Print("Passwords do not match | ")
			continue
		}
		break
	}

	// Get a username from the user and try to register the account. If the username is already taken, reprompt for a new username.
	for {

		// Get username.
		fmt.Print("(Press esc to return to option select.) Enter username: ")
		username, err := getRawInput(false, "")
		fmt.Print("\n\033[A\033[2K")
		if err != nil {
			return ERROR, err
		} else if username == "" { // This will be the selected branch if they hit esc.
			return OPTIONS, nil
		}

		// Form and send request.
		err = RegistrationHelper(password, username, serverURL)
		if err != nil {
			if errors.Is(err, ErrUsernameTaken) {
				fmt.Print("Username already in use, you must choose a different one | ")
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

func Authenticate(serverURL string) (state State, sessionToken [16]byte, adminToken [16]byte, aesKey []byte, username string, err error) {
	for {

		// Get username.
		fmt.Print("(Press esc to return to option select.) Enter your username: ")
		username, err := getRawInput(false, "")
		fmt.Print("\n\033[A\033[2K")
		if err != nil {
			return ERROR, [16]byte{}, [16]byte{}, nil, "", err
		} else if username == "" { // This will be the selected branch if they hit esc.
			return OPTIONS, [16]byte{}, [16]byte{}, nil, "", nil
		}

		// Get password.
		fmt.Print("(Press esc to return to option select.) Enter your password: ")
		password, err := getRawInput(true, "")
		fmt.Print("\n\033[A\033[2K")
		if err != nil {
			return ERROR, [16]byte{}, [16]byte{}, nil, "", err
		} else if password == "" { // This will be the selected branch if they hit esc.
			return OPTIONS, [16]byte{}, [16]byte{}, nil, "", nil
		}

		// Attempt authentication.
		sessionToken, adminToken, aesKey, err = AuthenticationHelper(serverURL, username, password)
		if err != nil {
			if errors.Is(err, ErrUsernameNotFound) {
				fmt.Print("Username not found | ")
				continue
			} else if errors.Is(err, ErrBadPassword) {
				fmt.Print("Invalid Password | ")
				continue
			} else {
				return ERROR, [16]byte{}, [16]byte{}, nil, "", err
			}
		}
		return OPTIONS, sessionToken, adminToken, aesKey, username, nil
	}
}

func ReAuthenticate(serverURL string, username string, retryState State) (state State, sessionToken [16]byte, adminToken [16]byte, aesKey []byte, err error) {
	for {

		// Get password.
		fmt.Print("(Press esc to return to option select.) Enter your password: ")
		password, err := getRawInput(true, "")
		fmt.Print("\n\033[A\033[2K")
		if err != nil {
			return ERROR, [16]byte{}, [16]byte{}, nil, err
		} else if password == "" { // This will be the selected branch if they hit esc.
			return OPTIONS, [16]byte{}, [16]byte{}, nil, nil
		}

		// Attempt authentication.
		sessionToken, adminToken, aesKey, err = AuthenticationHelper(serverURL, username, password)
		if err != nil {
			if errors.Is(err, ErrUsernameNotFound) {
				fmt.Print("Username not found | ")
				return OPTIONS, [16]byte{}, [16]byte{}, nil, nil
			} else if errors.Is(err, ErrBadPassword) {
				fmt.Print("Invalid Password | ")
				continue
			} else {
				return ERROR, [16]byte{}, [16]byte{}, nil, err
			}
		}
		return retryState, sessionToken, adminToken, aesKey, nil
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

func Entries(serverURL string, sessionToken [16]byte, aesKey []byte) (state State, entryID int, retryState State, err error) {

	// Construct request body.
	req := mustMarshal(struct {
		SessionToken [16]byte
	}{
		sessionToken,
	})
	// Send request.
	res, err := http.Post("http://"+serverURL+"/titles", "application/json", bytes.NewReader(req))
	if err != nil {
		return ERROR, 0, NO_RETRY, err
	}
	defer res.Body.Close()
	// Check status code.
	if res.StatusCode == http.StatusUnauthorized {
		return RE_AUTHENTICATE, 0, ENTRIES, nil
	} else if res.StatusCode != http.StatusOK {
		return ERROR, 0, NO_RETRY, fmt.Errorf("Server responded with status code: %d", res.StatusCode)
	}

	// Extract titles.
	encryptedTitles := []struct {
		ID    int
		Title []byte
	}{}
	err = json.NewDecoder(res.Body).Decode(&encryptedTitles)
	if err != nil {
		return ERROR, 0, NO_RETRY, err
	}

	// Print prompt.
	fmt.Println("Options:\n" +
		"0: Return to main options select")
	ciph, err := aes.NewCipher(aesKey)
	if err != nil {
		return ERROR, 0, NO_RETRY, err
	}
	decrypter, err := cipher.NewGCMWithRandomNonce(ciph)
	if err != nil {
		return ERROR, 0, NO_RETRY, err
	}
	for index, title := range encryptedTitles {
		text, err := decrypter.Open(nil, nil, title.Title, nil)
		if err != nil {
			return ERROR, 0, NO_RETRY, err
		}
		fmt.Printf("%d: Inspect entry: %s\n", index+1, string(text))
	}
	fmt.Printf("%d: Create new entry\n", len(encryptedTitles)+1)

	// Get choice.
	fmt.Print("Choice: ")
	scanner := bufio.NewScanner(os.Stdin)
	for {

		// Scan in from the terminal.
		if !scanner.Scan() {
			_ = scanner.Err()
			fmt.Print("Error parsing choice. Please choose again: ")
			continue
		}

		// Parse out the first number/word.
		choice, err := strconv.Atoi(strings.Split(scanner.Text(), " ")[0])
		if err != nil {
			fmt.Print("Error parsing choice. Please choose again: ")
			continue
		}

		// Switch on the number.
		switch {
		case choice == 0:
			fmt.Printf("\033[%dA\033[J", len(encryptedTitles)+4)
			return OPTIONS, 0, NO_RETRY, nil
		case choice > 0 && choice <= len(encryptedTitles):
			fmt.Printf("\033[%dA\033[J", len(encryptedTitles)+4)
			return GET_ENTRY, encryptedTitles[choice-1].ID, NO_RETRY, nil
		case choice == len(encryptedTitles)+1:
			fmt.Printf("\033[%dA\033[J", len(encryptedTitles)+4)
			return NEW_ENTRY, 0, NO_RETRY, nil
		default:
			fmt.Print("Choice outside expected range. Please choose again: ")
			continue
		}
	}
}

func Entry(serverURL string, sessionToken [16]byte, aesKey []byte, entryID int) (state State, retryState State, err error) {

	// Construct request body.
	req := mustMarshal(struct {
		SessionToken [16]byte
		EntryID      int
	}{
		sessionToken,
		entryID,
	})

	// Send request.
	res, err := http.Post("http://"+serverURL+"/entry", "application/json", bytes.NewReader(req))
	if err != nil {
		return ERROR, NO_RETRY, err
	}
	defer res.Body.Close()
	// Check status code.
	if res.StatusCode == http.StatusUnauthorized {
		return RE_AUTHENTICATE, GET_ENTRY, nil
	} else if res.StatusCode == http.StatusNotFound {
		fmt.Println("Entry not found, it may have been deleted.")
		return ENTRIES, NO_RETRY, nil
	} else if res.StatusCode != http.StatusOK {
		return ERROR, NO_RETRY, fmt.Errorf("Server responded with status code: %d", res.StatusCode)
	}

	// Extract entry.
	encryptedEntry := struct {
		Title []byte
		Data  []byte
	}{}
	err = json.NewDecoder(res.Body).Decode(&encryptedEntry)
	if err != nil {
		return ERROR, NO_RETRY, err
	}
	ciph, err := aes.NewCipher(aesKey)
	if err != nil {
		return ERROR, NO_RETRY, err
	}
	decrypter, err := cipher.NewGCMWithRandomNonce(ciph)
	if err != nil {
		return ERROR, NO_RETRY, err
	}
	title, err := decrypter.Open(nil, nil, encryptedEntry.Title, nil)
	if err != nil {
		return ERROR, NO_RETRY, err
	}
	data, err := decrypter.Open(nil, nil, encryptedEntry.Data, nil)
	if err != nil {
		return ERROR, NO_RETRY, err
	}
	decryptedDetails := struct {
		Username string
		Password string
	}{}
	err = json.Unmarshal(data, &decryptedDetails)
	if err != nil {
		return ERROR, NO_RETRY, err
	}

	// Print prompt.
	fmt.Printf("Title: %s\nUsername: %s\nPassword: %s\n", string(title), decryptedDetails.Username, decryptedDetails.Password)
	fmt.Println("Options:\n" +
		"0: Go back to entries\n" +
		"1: Edit entry\n" +
		"2: Delete entry")
	fmt.Print("Choice: ")

	// Get choice.
	scanner := bufio.NewScanner(os.Stdin)
	for {

		// Scan in from the terminal.
		if !scanner.Scan() {
			_ = scanner.Err()
			fmt.Print("\033[A\033[2K")
			fmt.Print("Error parsing choice. Please choose again: ")
			continue
		}

		// Parse out the first number/word.
		choice, err := strconv.Atoi(strings.Split(scanner.Text(), " ")[0])
		if err != nil {
			fmt.Print("\033[A\033[2K")
			fmt.Print("Error parsing choice. Please choose again: ")
			continue
		}

		// Switch on the number.
		switch choice {
		case 0:
			fmt.Print("\033[8A\033[J")
			return ENTRIES, NO_RETRY, nil
		case 1:
			fmt.Print("\033[8A\033[J")
			return EDIT_ENTRY_DETAILS, NO_RETRY, nil
		case 2:
			fmt.Print("\033[8A\033[J")
			return DELETE_ENTRY, NO_RETRY, nil
		default:
			fmt.Print("\033[A\033[2K")
			fmt.Print("Choice outside expected range. Please choose again: ")
			continue
		}
	}
}

func NewEntry(aesKey []byte) (state State, encryptedTitle []byte, encryptedData []byte, err error) {
	scanner := bufio.NewScanner(os.Stdin)

	// Prompt title.
	// fmt.Println()
	// fmt.Print("\033[A\033[2K")
	fmt.Print("Enter Title: ")
	var title string
	for {

		// Scan in from the terminal.
		if !scanner.Scan() {
			_ = scanner.Err()
			fmt.Print("\033[A\033[2K")
			fmt.Print("Error parsing input. Please try entering your title again: ")
			continue
		}
		title = scanner.Text()
		fmt.Print("\033[A\033[2K")
		break
	}

	// Prompt username.
	fmt.Print("Enter Username: ")
	var username string
	for {

		// Scan in from the terminal.
		if !scanner.Scan() {
			_ = scanner.Err()
			fmt.Print("\033[A\033[2K")
			fmt.Print("Error parsing input. Please try entering your title again: ")
			continue
		}
		username = scanner.Text()
		fmt.Print("\033[A\033[2K")
		break
	}

	// Prompt password.
	fmt.Print("Enter Password: ")
	var password string
	for {

		// Scan in from the terminal.
		if !scanner.Scan() {
			_ = scanner.Err()
			fmt.Print("\033[A\033[2K")
			fmt.Print("Error parsing input. Please try entering your title again: ")
			continue
		}
		password = scanner.Text()
		fmt.Print("\033[A\033[2K")
		break
	}

	// Prompt confirmation.
	fmt.Printf("Title: %s\nUsername: %s\nPassword: %s\n\n\033[ADoes this look correct? Enter 0 to return back to entries, Enter 1 to proceed: ", title, username, password)
loop:
	for {

		// Scan in from the terminal.
		if !scanner.Scan() {
			_ = scanner.Err()
			fmt.Print("\033[A\033[2K")
			fmt.Print("Error parsing choice. Please choose again: ")
			continue
		}

		// Parse out the first number/word.
		choice, err := strconv.Atoi(strings.Split(scanner.Text(), " ")[0])
		if err != nil {
			fmt.Print("\033[A\033[2K")
			fmt.Print("Error parsing choice. Please choose again: ")
			continue
		}

		// Switch on the number.
		switch choice {
		case 0:
			fmt.Print("\033[4A\033[J")
			return ENTRIES, nil, nil, nil
		case 1:
			fmt.Print("\033[4A\033[J")
			break loop
		default:
			fmt.Print("\033[A\033[2K")
			fmt.Print("Choice outside expected range. Please choose again: ")
			continue
		}
	}

	// Encrypt data.
	dataBytes := mustMarshal(struct {
		Username string
		Password string
	}{
		Username: username,
		Password: password,
	})

	// Encrypt title and data.
	ciph, err := aes.NewCipher(aesKey)
	if err != nil {
		return ERROR, nil, nil, err
	}
	encrypter, err := cipher.NewGCMWithRandomNonce(ciph)
	if err != nil {
		return ERROR, nil, nil, err
	}
	encryptedTitle = encrypter.Seal(nil, nil, []byte(title), nil)
	encryptedData = encrypter.Seal(nil, nil, dataBytes, nil)

	return CREATE_ENTRY, encryptedTitle, encryptedData, nil
}

func CreateEntry(serverURL string, sessionToken [16]byte, adminToken [16]byte, encryptedTitle []byte, encryptedData []byte) (state State, retryState State, err error) {

	// Construct request body.
	req := mustMarshal(struct {
		SessionToken [16]byte
		AdminToken   [16]byte
		Title        []byte
		Data         []byte
	}{
		SessionToken: sessionToken,
		AdminToken:   adminToken,
		Title:        encryptedTitle,
		Data:         encryptedData,
	})

	// Send request.
	res, err := http.Post("http://"+serverURL+"/new_entry", "application/json", bytes.NewReader(req))
	if err != nil {
		return ERROR, NO_RETRY, err
	}
	defer res.Body.Close()
	// Check status code.
	if res.StatusCode == http.StatusUnauthorized {
		return RE_AUTHENTICATE, CREATE_ENTRY, nil
	} else if res.StatusCode == http.StatusForbidden {
		return RE_AUTHENTICATE, CREATE_ENTRY, nil
	} else if res.StatusCode != http.StatusCreated {
		return ERROR, NO_RETRY, fmt.Errorf("Server responded with status code: %d", res.StatusCode)
	}

	fmt.Println("Entry Created")
	return ENTRIES, NO_RETRY, nil
}

func EditEntry(serverURL string, sessionToken [16]byte, aesKey []byte, entryID int) (state State, retryState State, encryptedTitle []byte, encryptedData []byte, err error) {

	// Construct request body.
	req := mustMarshal(struct {
		SessionToken [16]byte
		EntryID      int
	}{
		sessionToken,
		entryID,
	})

	// Send request.
	res, err := http.Post("http://"+serverURL+"/entry", "application/json", bytes.NewReader(req))
	if err != nil {
		return ERROR, NO_RETRY, nil, nil, err
	}
	defer res.Body.Close()
	// Check status code.
	if res.StatusCode == http.StatusUnauthorized {
		return RE_AUTHENTICATE, EDIT_ENTRY_DETAILS, nil, nil, nil
	} else if res.StatusCode == http.StatusNotFound {
		fmt.Println("Entry not found, it may have been deleted.")
		return ENTRIES, NO_RETRY, nil, nil, nil
	} else if res.StatusCode != http.StatusOK {
		return ERROR, NO_RETRY, nil, nil, fmt.Errorf("Server responded with status code: %d", res.StatusCode)
	}

	// Extract entry.
	encryptedEntry := struct {
		Title []byte
		Data  []byte
	}{}
	err = json.NewDecoder(res.Body).Decode(&encryptedEntry)
	if err != nil {
		return ERROR, NO_RETRY, nil, nil, err
	}
	ciph, err := aes.NewCipher(aesKey)
	if err != nil {
		return ERROR, NO_RETRY, nil, nil, err
	}
	crypter, err := cipher.NewGCMWithRandomNonce(ciph)
	if err != nil {
		return ERROR, NO_RETRY, nil, nil, err
	}
	title, err := crypter.Open(nil, nil, encryptedEntry.Title, nil)
	if err != nil {
		return ERROR, NO_RETRY, nil, nil, err
	}
	data, err := crypter.Open(nil, nil, encryptedEntry.Data, nil)
	if err != nil {
		return ERROR, NO_RETRY, nil, nil, err
	}
	decryptedDetails := struct {
		Username string
		Password string
	}{}
	err = json.Unmarshal(data, &decryptedDetails)
	if err != nil {
		return ERROR, NO_RETRY, nil, nil, err
	}

	// Edit title.
	fmt.Print("(Press esc to return to entries.) Edit title: ")
	newTitle, err := getRawInput(false, string(title))
	fmt.Print("\n\033[A\033[2K")
	if err != nil {
		return ERROR, NO_RETRY, nil, nil, err
	} else if newTitle == "" { // This will be the selected branch if they hit esc.
		return ENTRIES, NO_RETRY, nil, nil, nil
	}

	// Edit username.
	fmt.Print("(Press esc to return to entries.) Edit username: ")
	newUsername, err := getRawInput(false, decryptedDetails.Username)
	fmt.Print("\n\033[A\033[2K")
	if err != nil {
		return ERROR, NO_RETRY, nil, nil, err
	} else if newUsername == "" { // This will be the selected branch if they hit esc.
		return ENTRIES, NO_RETRY, nil, nil, nil
	}

	// Edit password.
	fmt.Print("(Press esc to return to entries.) Edit password: ")
	newPassword, err := getRawInput(false, decryptedDetails.Password)
	fmt.Print("\n\033[A\033[2K")
	if err != nil {
		return ERROR, NO_RETRY, nil, nil, err
	} else if newPassword == "" { // This will be the selected branch if they hit esc.
		return ENTRIES, NO_RETRY, nil, nil, nil
	}

	// Encrypt title and data.
	dataBytes := mustMarshal(struct {
		Username string
		Password string
	}{
		Username: newUsername,
		Password: newPassword,
	})
	encryptedTitle = crypter.Seal(nil, nil, []byte(newTitle), nil)
	encryptedData = crypter.Seal(nil, nil, dataBytes, nil)

	return UPDATE_ENTRY, NO_RETRY, encryptedTitle, encryptedData, nil
}

func UpdateEntry(serverURL string, sessionToken [16]byte, adminToken [16]byte, encryptedTitle []byte, encryptedData []byte, entryID int) (state State, retryState State, err error) {

	// Construct request body.
	req := mustMarshal(struct {
		SessionToken [16]byte
		AdminToken   [16]byte
		Title        []byte
		Data         []byte
		EntryID      int
	}{
		SessionToken: sessionToken,
		AdminToken:   adminToken,
		Title:        encryptedTitle,
		Data:         encryptedData,
		EntryID:      entryID,
	})

	// Send request.
	res, err := http.Post("http://"+serverURL+"/update_entry", "application/json", bytes.NewReader(req))
	if err != nil {
		return ERROR, NO_RETRY, err
	}
	defer res.Body.Close()
	// Check status code.
	if res.StatusCode == http.StatusUnauthorized {
		return RE_AUTHENTICATE, UPDATE_ENTRY, nil
	} else if res.StatusCode == http.StatusForbidden {
		return RE_AUTHENTICATE, UPDATE_ENTRY, nil
	} else if res.StatusCode != http.StatusNoContent {
		return ERROR, NO_RETRY, fmt.Errorf("Server responded with status code: %d", res.StatusCode)
	}

	fmt.Println("Entry Updated")
	return GET_ENTRY, NO_RETRY, nil
}

func DeleteEntry(serverURL string, sessionToken [16]byte, adminToken [16]byte, entryID int) (state State, retryState State, err error) {

	// Construct request body.
	req := mustMarshal(struct {
		SessionToken [16]byte
		AdminToken   [16]byte
		EntryID      int
	}{
		SessionToken: sessionToken,
		AdminToken:   adminToken,
		EntryID:      entryID,
	})

	// Send request.
	res, err := http.Post("http://"+serverURL+"/delete_entry", "application/json", bytes.NewReader(req))
	if err != nil {
		return ERROR, NO_RETRY, err
	}
	defer res.Body.Close()
	// Check status code.
	if res.StatusCode == http.StatusUnauthorized {
		return RE_AUTHENTICATE, DELETE_ENTRY, nil
	} else if res.StatusCode == http.StatusForbidden {
		return RE_AUTHENTICATE, DELETE_ENTRY, nil
	} else if res.StatusCode != http.StatusNoContent {
		return ERROR, NO_RETRY, fmt.Errorf("Server responded with status code: %d", res.StatusCode)
	}

	fmt.Println("Entry Deleted")
	return ENTRIES, NO_RETRY, nil
}

func LogOut(serverURL string, sessionTk [16]byte) (state State, sessionToken [16]byte, adminToken [16]byte, aesKey []byte, username string, entryID int, encryptedTitle []byte, encrytpedData []byte) {

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
	return OPTIONS, [16]byte{}, [16]byte{}, nil, "", -1, nil, nil
}

func DeleteAccount(serverURL string, sessionToken [16]byte, adminToken [16]byte) (state State, retryState State, err error) {

	// Construct request body.
	req := mustMarshal(struct {
		SessionToken [16]byte
		AdminToken   [16]byte
	}{
		SessionToken: sessionToken,
		AdminToken:   adminToken,
	})

	// Send request.
	res, err := http.Post("http://"+serverURL+"/delete_account", "application/json", bytes.NewReader(req))
	if err != nil {
		return ERROR, NO_RETRY, err
	}
	defer res.Body.Close()
	// Check status code.
	if res.StatusCode == http.StatusUnauthorized {
		return RE_AUTHENTICATE, DELETE_ACCOUNT, nil
	} else if res.StatusCode == http.StatusForbidden {
		return RE_AUTHENTICATE, DELETE_ACCOUNT, nil
	} else if res.StatusCode != http.StatusNoContent {
		return ERROR, NO_RETRY, fmt.Errorf("Server responded with status code: %d", res.StatusCode)
	}

	fmt.Println("Account Deleted")
	return LOG_OUT, NO_RETRY, nil
}

func getRawInput(hidden bool, initial string) (word string, err error) {

	// Our return string.
	key := []byte(initial)

	// Create a reader, and set the terminal to raw mode.
	reader := bufio.NewReader(os.Stdin)
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}

	// Populate initial text.
	fmt.Print(initial)

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
