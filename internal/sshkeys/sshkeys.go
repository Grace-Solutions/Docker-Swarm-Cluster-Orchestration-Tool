package sshkeys

import (
	"bufio"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"clusterctl/internal/logging"
	"github.com/google/uuid"
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

	// KeyTypeED25519 is the ED25519 key type (default, recommended)
	KeyTypeED25519 = "ed25519"
	// KeyTypeRSA is the RSA key type (for compatibility with older systems)
	KeyTypeRSA = "rsa"
	// DefaultKeyType is the default key type to use
	DefaultKeyType = KeyTypeED25519
	// RSAKeyBits is the number of bits for RSA keys (4096 for security)
	RSAKeyBits = 4096
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

// isUUIDFolder checks if a folder name matches the UUID format (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
func isUUIDFolder(name string) bool {
	// UUID format: 8-4-4-4-12 hex chars with dashes
	// Example: a1b2c3d4-e5f6-7890-abcd-ef1234567890
	if len(name) != 36 {
		return false
	}
	// Check dash positions
	if name[8] != '-' || name[13] != '-' || name[18] != '-' || name[23] != '-' {
		return false
	}
	// Check that all other chars are hex
	for i, c := range name {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue // skip dashes
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// getLatestKeyFolder returns the latest UUID key folder based on modified date descending.
// Only considers folders matching UUID format (ignores old date-based folders).
// Returns empty string if no UUID folders exist.
func getLatestKeyFolder(baseDir string) (string, error) {
	log := logging.L().With("component", "sshkeys")

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read key directory: %w", err)
	}

	// Filter for directories matching UUID format only
	var uuidFolders []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() && isUUIDFolder(entry.Name()) {
			uuidFolders = append(uuidFolders, entry)
		} else if entry.IsDir() {
			log.Debugw("ignoring non-UUID folder", "folder", entry.Name())
		}
	}

	if len(uuidFolders) == 0 {
		return "", nil
	}

	// Sort by modified time descending
	sort.Slice(uuidFolders, func(i, j int) bool {
		infoI, _ := uuidFolders[i].Info()
		infoJ, _ := uuidFolders[j].Info()
		return infoI.ModTime().After(infoJ.ModTime())
	})

	return filepath.Join(baseDir, uuidFolders[0].Name()), nil
}

// EnsureKeyPair ensures an SSH key pair exists, generating it if necessary.
// keyType specifies the type of key to generate: "ed25519" (default) or "rsa".
// Returns the key pair information.
func EnsureKeyPair(keyDir string, keyType string) (*KeyPair, error) {
	log := logging.L().With("component", "sshkeys")

	// Normalize and validate key type
	if keyType == "" {
		keyType = DefaultKeyType
	}
	keyType = strings.ToLower(keyType)
	if keyType != KeyTypeED25519 && keyType != KeyTypeRSA {
		return nil, fmt.Errorf("invalid key type %q: must be %q or %q", keyType, KeyTypeED25519, KeyTypeRSA)
	}

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

	// Generate new key pair in UUID folder (lowercase)
	keyUUID := strings.ToLower(uuid.New().String())
	uuidDir := filepath.Join(keyDir, keyUUID)

	if err := os.MkdirAll(uuidDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create UUID key directory: %w", err)
	}

	privateKeyPath := filepath.Join(uuidDir, PrivateKeyFileName)
	publicKeyPath := filepath.Join(uuidDir, PublicKeyFileName)
	passwordPath := filepath.Join(uuidDir, PasswordFileName)

	log.Infow("generating new SSH key pair", "path", privateKeyPath, "uuid", keyUUID, "keyType", keyType)

	// Generate random password for private key encryption
	password, err := generateRandomPassword(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate password: %w", err)
	}

	// Generate key pair based on type
	var privateKey crypto.PrivateKey
	var sshPublicKey ssh.PublicKey

	switch keyType {
	case KeyTypeRSA:
		// Generate RSA key pair (4096 bits for security)
		rsaKey, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
		}
		privateKey = rsaKey
		sshPublicKey, err = ssh.NewPublicKey(&rsaKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create SSH public key from RSA: %w", err)
		}
	case KeyTypeED25519:
		fallthrough
	default:
		// Generate ED25519 key pair (default)
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ED25519 key pair: %w", err)
		}
		privateKey = privKey
		sshPublicKey, err = ssh.NewPublicKey(pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create SSH public key from ED25519: %w", err)
		}
	}

	// Marshal private key to OpenSSH format with password encryption
	// The second parameter is a comment with ssh-<uuid> identifier, third is the passphrase
	keyComment := fmt.Sprintf("ssh-%s", keyUUID)
	privateKeyPEM, err := ssh.MarshalPrivateKeyWithPassphrase(privateKey, keyComment, []byte(password))
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

	// Generate OpenSSH format public key with ssh-<uuid> comment
	// MarshalAuthorizedKey returns "ssh-ed25519 AAAA...\n" or "ssh-rsa AAAA...\n"
	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPublicKey)
	publicKeyStr := strings.TrimSpace(string(pubKeyBytes)) + " " + keyComment + "\n"

	// Write public key
	if err := os.WriteFile(publicKeyPath, []byte(publicKeyStr), 0644); err != nil {
		return nil, fmt.Errorf("failed to write public key: %w", err)
	}

	log.Infow("SSH key pair generated successfully",
		"privateKey", privateKeyPath,
		"publicKey", publicKeyPath,
		"passwordFile", passwordPath,
		"keyType", keyType,
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

