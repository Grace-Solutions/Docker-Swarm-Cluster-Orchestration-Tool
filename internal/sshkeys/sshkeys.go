package sshkeys

import (
	"bufio"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"clusterctl/internal/logging"
	"golang.org/x/crypto/ssh"
)

const (
	// DefaultKeyDir is the default directory for SSH keys (relative to binary)
	DefaultKeyDir = "sshkeys"
	// PrivateKeyFileName is the name of the private key file
	PrivateKeyFileName = "PrivateKey.ppk"
	// PublicKeyFileName is the name of the public key file
	// Uses .pubkey extension to avoid conflict with MS Publisher (.pub)
	PublicKeyFileName = "PublicKey.pubkey"
	// PasswordFileName is the name of the password file
	PasswordFileName = "PrivateKey.pwd"
)

// KeyPair represents an SSH key pair.
type KeyPair struct {
	PrivateKeyPath string
	PublicKeyPath  string
	PasswordPath   string // Path to password file (may be empty)
	Password       string // Password for private key (empty if no password)
	PublicKey      string // OpenSSH format public key
}

// generateRandomPassword generates a cryptographically secure random password.
func generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
	password := make([]byte, length)

	for i := range password {
		// Generate random index
		randomBytes := make([]byte, 1)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", fmt.Errorf("failed to generate random bytes: %w", err)
		}
		password[i] = charset[int(randomBytes[0])%len(charset)]
	}

	return string(password), nil
}

// readPasswordFile reads the password from a .pwd file.
// Returns empty string if file doesn't exist or first line is blank.
func readPasswordFile(passwordPath string) (string, error) {
	// Check if password file exists
	if _, err := os.Stat(passwordPath); os.IsNotExist(err) {
		return "", nil // No password file = no password
	}

	// Read password file
	file, err := os.Open(passwordPath)
	if err != nil {
		return "", fmt.Errorf("failed to open password file: %w", err)
	}
	defer file.Close()

	// Read first line
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		return password, nil
	}

	// Empty file or error reading
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read password file: %w", err)
	}

	return "", nil // Empty file = no password
}

// getLatestKeyFolder returns the latest key folder based on modified date descending.
// Returns empty string if no folders exist.
func getLatestKeyFolder(baseDir string) (string, error) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read key directory: %w", err)
	}

	// Filter for directories only
	var folders []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			folders = append(folders, entry)
		}
	}

	if len(folders) == 0 {
		return "", nil
	}

	// Sort by modified time descending
	sort.Slice(folders, func(i, j int) bool {
		infoI, _ := folders[i].Info()
		infoJ, _ := folders[j].Info()
		return infoI.ModTime().After(infoJ.ModTime())
	})

	return filepath.Join(baseDir, folders[0].Name()), nil
}

// EnsureKeyPair ensures an SSH key pair exists, generating it if necessary.
// Returns the key pair information.
func EnsureKeyPair(keyDir string) (*KeyPair, error) {
	log := logging.L().With("component", "sshkeys")

	// Use default key directory if not specified
	if keyDir == "" {
		// Get binary directory
		exePath, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("failed to get executable path: %w", err)
		}
		binaryDir := filepath.Dir(exePath)
		keyDir = filepath.Join(binaryDir, DefaultKeyDir)
	}

	// Ensure base key directory exists
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	// Check for latest existing key folder
	latestFolder, err := getLatestKeyFolder(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest key folder: %w", err)
	}

	if latestFolder != "" {
		// Use existing key pair from latest folder
		privateKeyPath := filepath.Join(latestFolder, PrivateKeyFileName)
		publicKeyPath := filepath.Join(latestFolder, PublicKeyFileName)
		passwordPath := filepath.Join(latestFolder, PasswordFileName)

		if _, err := os.Stat(privateKeyPath); err == nil {
			log.Infow("using existing SSH key pair", "path", privateKeyPath)

			// Read public key
			publicKeyBytes, err := os.ReadFile(publicKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read public key: %w", err)
			}

			// Read password if password file exists
			password, err := readPasswordFile(passwordPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read password file: %w", err)
			}

			if password != "" {
				log.Infow("private key password loaded from file", "passwordFile", passwordPath)
			} else {
				log.Infow("no password file found or empty, using unencrypted private key")
			}

			return &KeyPair{
				PrivateKeyPath: privateKeyPath,
				PublicKeyPath:  publicKeyPath,
				PasswordPath:   passwordPath,
				Password:       password,
				PublicKey:      string(publicKeyBytes),
			}, nil
		}
	}

	// Generate new key pair in timestamped folder
	timestamp := time.Now().Format("2006.01.02.1504")
	timestampedDir := filepath.Join(keyDir, timestamp)

	if err := os.MkdirAll(timestampedDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create timestamped key directory: %w", err)
	}

	privateKeyPath := filepath.Join(timestampedDir, PrivateKeyFileName)
	publicKeyPath := filepath.Join(timestampedDir, PublicKeyFileName)
	passwordPath := filepath.Join(timestampedDir, PasswordFileName)

	log.Infow("generating new SSH key pair", "path", privateKeyPath)

	// Generate random password for private key encryption
	password, err := generateRandomPassword(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate password: %w", err)
	}

	// Generate ED25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Marshal private key to OpenSSH format with password encryption
	// ssh.MarshalPrivateKeyWithPassphrase encrypts the key with the given passphrase
	// The second parameter is a comment (empty here), third is the passphrase
	privateKeyPEM, err := ssh.MarshalPrivateKeyWithPassphrase(crypto.PrivateKey(privateKey), "", []byte(password))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key with passphrase: %w", err)
	}

	// Encode the PEM block to bytes
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)
	if privateKeyBytes == nil {
		return nil, fmt.Errorf("failed to encode private key to PEM format")
	}

	// Write private key in OpenSSH PEM format (encrypted with password)
	if err := os.WriteFile(privateKeyPath, privateKeyBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}

	// Write password to .pwd file
	if err := os.WriteFile(passwordPath, []byte(password+"\n"), 0600); err != nil {
		return nil, fmt.Errorf("failed to write password file: %w", err)
	}

	// Generate OpenSSH format public key
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH public key: %w", err)
	}
	publicKeyStr := string(ssh.MarshalAuthorizedKey(sshPublicKey))

	// Write public key
	if err := os.WriteFile(publicKeyPath, []byte(publicKeyStr), 0644); err != nil {
		return nil, fmt.Errorf("failed to write public key: %w", err)
	}

	log.Infow("SSH key pair generated successfully",
		"privateKey", privateKeyPath,
		"publicKey", publicKeyPath,
		"passwordFile", passwordPath,
		"encrypted", true,
	)

	return &KeyPair{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		PasswordPath:   passwordPath,
		Password:       password,
		PublicKey:      publicKeyStr,
	}, nil
}

// marshalED25519PrivateKey marshals an ED25519 private key to OpenSSH format.
func marshalED25519PrivateKey(key ed25519.PrivateKey) []byte {
	// OpenSSH ED25519 private key format
	// This is a simplified version - for production use, consider using
	// golang.org/x/crypto/ssh's MarshalPrivateKey or similar
	return []byte(key)
}

// Note: We no longer remove key pairs from disk.
// Keys are kept in timestamped folders for future use.

