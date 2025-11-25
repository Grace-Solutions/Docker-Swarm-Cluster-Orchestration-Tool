package sshkeys

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"clusterctl/internal/logging"
	"golang.org/x/crypto/ssh"
)

const (
	// DefaultKeyDir is the default directory for SSH keys (relative to binary)
	DefaultKeyDir = "sshkeys"
	// PrivateKeyFileName is the name of the private key file
	PrivateKeyFileName = "PrivateKey"
	// PublicKeyFileName is the name of the public key file
	PublicKeyFileName = "PublicKey"
)

// KeyPair represents an SSH key pair.
type KeyPair struct {
	PrivateKeyPath string
	PublicKeyPath  string
	PublicKey      string // OpenSSH format public key
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

		if _, err := os.Stat(privateKeyPath); err == nil {
			log.Infow("using existing SSH key pair", "path", privateKeyPath)

			// Read public key
			publicKeyBytes, err := os.ReadFile(publicKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read public key: %w", err)
			}

			return &KeyPair{
				PrivateKeyPath: privateKeyPath,
				PublicKeyPath:  publicKeyPath,
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

	log.Infow("generating new SSH key pair", "path", privateKeyPath)

	// Generate ED25519 key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Marshal private key to OpenSSH format
	// ssh.MarshalPrivateKey returns a *pem.Block with the private key in OpenSSH format
	privateKeyPEM, err := ssh.MarshalPrivateKey(crypto.PrivateKey(privateKey), "")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Encode the PEM block to bytes
	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)
	if privateKeyBytes == nil {
		return nil, fmt.Errorf("failed to encode private key to PEM format")
	}

	// Write private key in OpenSSH PEM format
	if err := os.WriteFile(privateKeyPath, privateKeyBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
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
	)

	return &KeyPair{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
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

