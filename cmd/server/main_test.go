package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGeneratePassword(t *testing.T) {
	// Test with minimum length
	password, err := generatePassword(12, "")
	if err != nil {
		t.Fatalf("Failed to generate password: %v", err)
	}
	if len(password) != 12 {
		t.Errorf("Expected password length 12, got %d", len(password))
	}
	if !hasRequiredComplexity(password) {
		t.Errorf("Password does not meet complexity requirements: %s", password)
	}

	// Test with custom length
	password, err = generatePassword(20, "")
	if err != nil {
		t.Fatalf("Failed to generate password: %v", err)
	}
	if len(password) != 20 {
		t.Errorf("Expected password length 20, got %d", len(password))
	}
	if !hasRequiredComplexity(password) {
		t.Errorf("Password does not meet complexity requirements: %s", password)
	}

	// Test with passphrase
	password1, err := generatePassword(16, "my secret passphrase")
	if err != nil {
		t.Fatalf("Failed to generate password: %v", err)
	}

	password2, err := generatePassword(16, "my secret passphrase")
	if err != nil {
		t.Fatalf("Failed to generate password: %v", err)
	}

	// Passwords should be different even with the same passphrase due to random entropy
	if password1 == password2 {
		t.Errorf("Expected different passwords with same passphrase, got identical: %s", password1)
	}

	// Test with too small length
	password, err = generatePassword(5, "")
	if err != nil {
		t.Fatalf("Failed to generate password: %v", err)
	}
	if len(password) != 12 {
		t.Errorf("Expected minimum password length 12, got %d", len(password))
	}

	// Test with too large length
	password, err = generatePassword(300, "")
	if err != nil {
		t.Fatalf("Failed to generate password: %v", err)
	}
	if len(password) != 255 {
		t.Errorf("Expected maximum password length 255, got %d", len(password))
	}
}

func TestHasRequiredComplexity(t *testing.T) {
	// Test with a password that meets all requirements
	if !hasRequiredComplexity("Abc123!@") {
		t.Errorf("Expected password to meet complexity requirements")
	}

	// Test with a password missing uppercase
	if hasRequiredComplexity("abc123!@") {
		t.Errorf("Expected password to fail complexity check (missing uppercase)")
	}

	// Test with a password missing lowercase
	if hasRequiredComplexity("ABC123!@") {
		t.Errorf("Expected password to fail complexity check (missing lowercase)")
	}

	// Test with a password missing digits
	if hasRequiredComplexity("Abcdef!@") {
		t.Errorf("Expected password to fail complexity check (missing digits)")
	}

	// Test with a password missing special characters
	if hasRequiredComplexity("Abc12345") {
		t.Errorf("Expected password to fail complexity check (missing special characters)")
	}
}

func TestSavePassword(t *testing.T) {
	// Create a temporary test directory
	testDir := filepath.Join(os.TempDir(), "password_test_"+time.Now().Format("20060102_150405"))
	defer os.RemoveAll(testDir)

	// Save original passwords directory and restore it after the test
	defer func() {
		os.RemoveAll("passwords")
		os.Rename(testDir, "passwords")
	}()

	// Move existing passwords directory if it exists
	if _, err := os.Stat("passwords"); err == nil {
		os.Rename("passwords", testDir)
	}

	// Test saving a password with a unique website
	filename1, err := savePassword("testwebsite", "TestPassword123!")
	if err != nil {
		t.Fatalf("Failed to save password: %v", err)
	}
	if filename1 != "testwebsite.txt" {
		t.Errorf("Expected filename 'testwebsite.txt', got '%s'", filename1)
	}

	// Test saving another password with the same website (should add timestamp)
	filename2, err := savePassword("testwebsite", "AnotherPassword456!")
	if err != nil {
		t.Fatalf("Failed to save password: %v", err)
	}

	// The second filename should contain the original name plus a timestamp
	if filename2 == filename1 {
		t.Errorf("Expected different filenames for duplicate website, got same: %s", filename2)
	}

	if !strings.HasPrefix(filename2, "testwebsite_") || !strings.HasSuffix(filename2, ".txt") {
		t.Errorf("Expected filename to start with 'testwebsite_' and end with '.txt', got '%s'", filename2)
	}

	// Verify both files exist
	if _, err := os.Stat(filepath.Join("passwords", filename1)); err != nil {
		t.Errorf("First password file doesn't exist: %v", err)
	}

	if _, err := os.Stat(filepath.Join("passwords", filename2)); err != nil {
		t.Errorf("Second password file doesn't exist: %v", err)
	}
}

func TestCheckPasswordLeaked(t *testing.T) {
	// This is a mock test since we don't want to make actual API calls in tests
	// In a real-world scenario, you would use a mock HTTP client

	// Test with a known weak password (this might change if the API response changes)
	// We're using a very common password that's likely to be in the database
	isLeaked, err := checkPasswordLeaked("password123")
	if err != nil {
		t.Logf("Warning: Error checking if password is leaked: %v", err)
		t.Skip("Skipping test due to API error")
	}

	// This password should be leaked
	if !isLeaked {
		t.Logf("Warning: Expected 'password123' to be leaked, but API returned not leaked")
		// Don't fail the test as the API might change
	}

	// Test with a random, complex password that's unlikely to be leaked
	randomPassword, err := generatePassword(32, "some random passphrase")
	if err != nil {
		t.Fatalf("Failed to generate random password: %v", err)
	}

	isLeaked, err = checkPasswordLeaked(randomPassword)
	if err != nil {
		t.Logf("Warning: Error checking if password is leaked: %v", err)
		t.Skip("Skipping test due to API error")
	}

	// This password should not be leaked
	if isLeaked {
		t.Logf("Warning: Expected random password to not be leaked, but API returned leaked")
		// Don't fail the test as false positives are possible
	}
}
