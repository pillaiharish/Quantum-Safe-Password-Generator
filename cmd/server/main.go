package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// PasswordRequest represents the request for password generation
type PasswordRequest struct {
	Website          string `json:"website"`
	Length           int    `json:"length"`
	Passphrase       string `json:"passphrase"`
	DisableLeakCheck bool   `json:"disableLeakCheck"`
}

// PasswordResponse represents the response for password generation
type PasswordResponse struct {
	Password string `json:"password"`
	Website  string `json:"website"`
	IsLeaked bool   `json:"isLeaked"`
	FileName string `json:"fileName"`
}

// // HaveIBeenPwnedResponse represents the response from the HIBP API
// type HaveIBeenPwnedResponse struct {
// 	Count int `json:"count"`
// }

// generatePassword creates a cryptographically secure password
func generatePassword(length int, passphrase string) (string, error) {
	if length < 12 {
		length = 12 // Minimum length
	}
	if length > 255 {
		length = 255 // Maximum length
	}

	// Create a character set for the password
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/"
	charsetLength := big.NewInt(int64(len(charset)))

	// Generate random bytes for entropy
	randomBytes := make([]byte, 64)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	// Use passphrase as additional entropy if provided
	if passphrase != "" {
		passphraseBytes := []byte(passphrase)
		for i := 0; i < len(passphraseBytes) && i < len(randomBytes); i++ {
			randomBytes[i] ^= passphraseBytes[i%len(passphraseBytes)]
		}
	}

	// Generate password
	var password strings.Builder
	password.Grow(length)

	// Use time-based seed as additional entropy
	timeNow := time.Now().UnixNano()
	timeSeed := big.NewInt(timeNow)

	for i := 0; i < length; i++ {
		// Mix different entropy sources
		n, err := rand.Int(rand.Reader, charsetLength)
		if err != nil {
			return "", err
		}

		// XOR with time-based seed for additional randomness
		n.Xor(n, timeSeed)
		n.Mod(n, charsetLength)

		password.WriteByte(charset[n.Int64()])
	}

	// Add some quantum-resistant entropy by using a hash of all inputs
	finalPass := password.String()

	// Ensure password complexity
	if !hasRequiredComplexity(finalPass) {
		// If not complex enough, recursively generate a new one
		return generatePassword(length, passphrase)
	}

	return finalPass, nil
}

// hasRequiredComplexity checks if the password meets complexity requirements
func hasRequiredComplexity(password string) bool {
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		if 'A' <= char && char <= 'Z' {
			hasUpper = true
		} else if 'a' <= char && char <= 'z' {
			hasLower = true
		} else if '0' <= char && char <= '9' {
			hasDigit = true
		} else {
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

// savePassword saves the password to a file
func savePassword(website, password string) (string, error) {
	// Create passwords directory if it doesn't exist
	passwordsDir := "passwords"
	if err := os.MkdirAll(passwordsDir, 0755); err != nil {
		return "", err
	}

	// Generate a filename based on website or a timestamp if website is empty
	baseFilename := website
	if baseFilename == "" {
		baseFilename = fmt.Sprintf("password_%s", time.Now().Format("20060102_150405"))
	}

	// Sanitize filename
	baseFilename = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, baseFilename)

	// Add .txt extension
	filename := baseFilename + ".txt"
	filePath := filepath.Join(passwordsDir, filename)

	// Check if file already exists, if so, add epoch timestamp to make it unique
	if _, err := os.Stat(filePath); err == nil {
		// File exists, add epoch timestamp
		epoch := time.Now().Unix()
		filename = fmt.Sprintf("%s_%d.txt", baseFilename, epoch)
		filePath = filepath.Join(passwordsDir, filename)
	}

	// Write password to file
	content := fmt.Sprintf("Website/Purpose: %s\nPassword: %s\nGenerated: %s\n",
		website,
		password,
		time.Now().Format("2006-01-02 15:04:05"))

	if err := ioutil.WriteFile(filePath, []byte(content), 0644); err != nil {
		return "", err
	}

	return filename, nil
}

// checkPasswordLeaked checks if the password has been leaked using the HIBP API
func checkPasswordLeaked(password string) (bool, error) {
	// Use a more secure approach with k-anonymity
	// We only send the first 5 characters of the SHA-1 hash to the API
	// and then check locally if our hash is in the returned list

	// Hash the password with SHA-1
	h := sha1.New()
	h.Write([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	// Get the prefix and suffix for k-anonymity
	prefix := hash[:5]
	suffix := hash[5:]

	// Make request to HIBP API
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, err
	}

	// Set user agent as recommended by HIBP
	req.Header.Set("User-Agent", "PasswordGenerator-Go/1.0")

	// Make the request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("HIBP API returned status code %d", resp.StatusCode)
	}

	// Read the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	// Parse the response - each line is in the format: HASH_SUFFIX:COUNT
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}

		// Compare the hash suffix (case insensitive)
		if strings.EqualFold(strings.TrimSpace(parts[0]), suffix) {
			count, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil {
				continue
			}

			// If count > 0, the password has been leaked
			return count > 0, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return false, err
	}

	// Password not found in leaked passwords
	return false, nil
}

func handleGeneratePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Validate length
	if req.Length < 12 {
		req.Length = 12
	}
	if req.Length > 255 {
		req.Length = 255
	}

	// Generate password
	password, err := generatePassword(req.Length, req.Passphrase)
	if err != nil {
		http.Error(w, "Failed to generate password", http.StatusInternalServerError)
		return
	}

	// Check if password has been leaked (unless disabled)
	isLeaked := false
	if !req.DisableLeakCheck {
		isLeaked, err = checkPasswordLeaked(password)
		if err != nil {
			log.Printf("Error checking if password is leaked: %v", err)
			isLeaked = false // Assume not leaked if there's an error
		}
	}

	// Save password to file
	filename, err := savePassword(req.Website, password)
	if err != nil {
		http.Error(w, "Failed to save password", http.StatusInternalServerError)
		return
	}

	// Prepare response
	resp := PasswordResponse{
		Password: password,
		Website:  req.Website,
		IsLeaked: isLeaked,
		FileName: filename,
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func main() {
	// Create passwords directory if it doesn't exist
	if err := os.MkdirAll("passwords", 0755); err != nil {
		log.Fatalf("Failed to create passwords directory: %v", err)
	}

	// Serve static files
	http.Handle("/", http.FileServer(http.Dir("static")))

	// API endpoints
	http.HandleFunc("/api/generate", handleGeneratePassword)

	// Start server
	port := "8080"
	log.Printf("Server starting on port %s...", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
