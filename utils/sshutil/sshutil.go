package sshutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"strings"
	"time"

	"github.com/mikesmitty/edkey"
)

type (
	// Config represents the args used to generate the key pairs in GeneratePEMKeyPair
	Config struct {
		KeyType string
		RSABits int
	}

	// KeyPairPEM represents a key pair in PEM fomat
	KeyPairPEM struct {
		PublicKey  string
		PrivateKey string
	}
)

// helper function return a ssh client connection
func Dial(server, username, password, privatekey string, timeout time.Duration) (*ssh.Client, error) {
	if !strings.HasSuffix(server, ":22") {
		server = server + ":22"
	}

	config := &ssh.ClientConfig{
		User:            username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	if privatekey != "" {
		pem := []byte(privatekey)
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return nil, err
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	}

	if password != "" {
		config.Auth = append(config.Auth, ssh.Password(password))
	}

	return ssh.Dial("tcp", server, config)
}

// helper function returns a new key pair
func GeneratePEMKeyPair(config *Config) (*KeyPairPEM, error) {
	var authorizedKey []byte
	var pemPrivateKey []byte

	if config.KeyType == "" {
		config.KeyType = "ed25519"
	}

	switch config.KeyType {
	case "rsa":
		if config.RSABits < 2048 {
			config.RSABits = 2048
		}

		privateKey, err := rsa.GenerateKey(rand.Reader, config.RSABits)
		if err != nil {
			return nil, err
		}

		publicKey, err := ssh.NewPublicKey(privateKey.Public())
		if err != nil {
			return nil, err
		}

		marshalledPrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)

		pemBlockPrivateKey := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: marshalledPrivateKey,
		}

		pemPrivateKey = pem.EncodeToMemory(pemBlockPrivateKey)
		authorizedKey = ssh.MarshalAuthorizedKey(publicKey)
	case "ed25519":
		tmpPublicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		publicKey, err := ssh.NewPublicKey(tmpPublicKey)
		if err != nil {
			return nil, err
		}

		pemBlockPrivateKey := &pem.Block{
			Type:  "OPENSSH PRIVATE KEY",
			Bytes: edkey.MarshalED25519PrivateKey(privateKey),
		}

		pemPrivateKey = pem.EncodeToMemory(pemBlockPrivateKey)
		authorizedKey = ssh.MarshalAuthorizedKey(publicKey)
	default:
		return nil, fmt.Errorf("unsupported key type %s", config.KeyType)
	}

	return &KeyPairPEM{
		PublicKey:  string(authorizedKey),
		PrivateKey: string(pemPrivateKey),
	}, nil
}

// helper function genereated the public ssh key from the
// private ssh key.
func GenerateAuthorizedKeyKeyFromPEMPrivateKey(privatekey string) (string, error) {
	privateKey, err := ssh.ParseRawPrivateKey([]byte(privatekey))
	if err != nil {
		return "", err
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return "", err
	}

	return string(ssh.MarshalAuthorizedKey(signer.PublicKey())), nil
}

// helper function calculates and returns the fingerprint (default to md5)
// of the public ssh key.
func CalculateFingerprint(authorizedKey, hash string) (string, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "", err
	}

	var f string
	if strings.ToLower(hash) == "sha256" {
		f = ssh.FingerprintSHA256(key)
		f = strings.Replace(f, "SHA256:", "", 1)
	} else if strings.ToLower(hash) == "sha1" {
		sha1sum := sha1.Sum(key.Marshal())
		f = base64.RawStdEncoding.EncodeToString(sha1sum[:])
	} else {
		f = ssh.FingerprintLegacyMD5(key)
		f = strings.Replace(f, "MD5:", "", 1)
	}

	return f, nil
}
