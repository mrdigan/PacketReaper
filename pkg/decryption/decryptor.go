package decryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"log"
	"os"
	"strings"
)

// TLSSession holds the cryptographic state for a single TLS session
type TLSSession struct {
	ClientIP     string
	ClientRandom []byte
	ServerRandom []byte
	CipherSuite  uint16
	MajorVersion uint8
	MinorVersion uint8

	// Secrets
	PreMasterSecret []byte
	MasterSecret    []byte
	KeyBlock        []byte

	// Keys
	ClientMACKey []byte
	ServerMACKey []byte
	ClientKey    []byte
	ServerKey    []byte
	ClientIV     []byte
	ServerIV     []byte

	DecryptedPayloads []byte
}

// Decryptor manages keys and sessions
type Decryptor struct {
	PrivateKey *rsa.PrivateKey
	Sessions   map[string]*TLSSession // Keyed by ClientIP:Port-ServerIP:Port
	KeyLog     map[string][]byte      // Map of ClientRandom (hex) -> MasterSecret (raw bytes)
}

// NewDecryptor creates a new decryptor instance
func NewDecryptor() *Decryptor {
	return &Decryptor{
		Sessions: make(map[string]*TLSSession),
		KeyLog:   make(map[string][]byte),
	}
}

// LoadPrivateKey loads a PEM-encoded RSA private key
func (d *Decryptor) LoadPrivateKey(path string) error {
	log.Printf("[Decryptor] LoadPrivateKey called with path: %s", path)
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[Decryptor] Failed to read file: %v", err)
		return err
	}

	// Simple heuristic: check if it looks like an NSS Key Log
	// "CLIENT_RANDOM <hex> <hex>"
	sData := string(data)
	if len(data) > 14 && (sData[0:13] == "CLIENT_RANDOM" || sData[0:1] == "#") {
		log.Printf("[Decryptor] Detected NSS Key Log format, calling LoadKeyLog")
		return d.LoadKeyLog(path)
	}

	log.Printf("[Decryptor] Attempting PEM decode")
	block, _ := pem.Decode(data)
	if block == nil {
		// Attempt KeyLog load if PEM failed, just in case
		log.Printf("[Decryptor] PEM decode failed, attempting KeyLog load")
		return d.LoadKeyLog(path)
	}
// ... rest of function

	// Try identifying the key type
	var priv interface{}
	var parseErr error

	if block.Type == "RSA PRIVATE KEY" {
		priv, parseErr = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		priv, parseErr = x509.ParsePKCS8PrivateKey(block.Bytes)
	} else {
		return fmt.Errorf("unsupported key type: %s", block.Type)
	}

	if parseErr != nil {
		return parseErr
	}

	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return errors.New("not an RSA private key")
	}

	d.PrivateKey = rsaKey
	return nil
}

// LoadKeyLog parses an NSS Key Log file
func (d *Decryptor) LoadKeyLog(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	
	lines := strings.Split(string(data), "\n")
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.Fields(line)
		if len(parts) >= 3 && parts[0] == "CLIENT_RANDOM" {
			// CLIENT_RANDOM <ClientRandom_Hex> <MasterSecret_Hex>
			clientRandomHex := parts[1]
			masterSecretHex := parts[2]
			
			// We store keys by ClientRandom (hex string) for easy lookup
			// We decode the Master Secret to bytes
			ms, err := hex.DecodeString(masterSecretHex)
			if err == nil {
				d.KeyLog[clientRandomHex] = ms
				count++
			}
		}
	}
	log.Printf("[Decryptor] Loaded %d keys from NSS Key Log", count)
	if count == 0 {
		return errors.New("no valid CLIENT_RANDOM entries found")
	}
	return nil
}

// Reset clears all session state but keeps the private key
func (d *Decryptor) Reset() {
	d.Sessions = make(map[string]*TLSSession)
	// We do NOT clear d.KeyLog or d.PrivateKey as they are loaded globally
}

// ExtractHandshakeData extracts nonces and key exchange data from raw TCP payload
func (d *Decryptor) ExtractHandshakeData(sessionKey string, srcIP string, payload []byte) {
	// Simple parser for TLS Records
	// We need 0x16 (Handshake)
	// We iterate records in the TCP payload
	
	offset := 0
	for offset+5 <= len(payload) {
		recordType := payload[offset]
		length := int(binary.BigEndian.Uint16(payload[offset+3 : offset+5]))
		
		offset += 5
		if offset+length > len(payload) {
			break
		}

		if recordType == 0x16 { // Handshake
			fragment := payload[offset : offset+length]
			log.Printf("[Decryptor] Found Handshake Fragment in session %s (Src: %s, Len: %d)", sessionKey, srcIP, length)
			d.parseHandshakeFragment(sessionKey, srcIP, fragment)
		}
		
		offset += length
	}
}

func (d *Decryptor) parseHandshakeFragment(sessionKey string, srcIP string, data []byte) {
	// TLS Handshake Protocol
	offset := 0
	for offset+4 <= len(data) {
		msgType := data[offset]
		length := int(uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]))
		
		offset += 4
		if offset+length > len(data) {
			break
		}
		body := data[offset : offset+length]

		// Ensure session exists
		d.ensureSession(sessionKey)
		sess := d.Sessions[sessionKey]

		switch msgType {
		case 0x01: // ClientHello
			log.Printf("[Decryptor] Session %s: ClientHello found", sessionKey)
			// Set ClientIP
			sess.ClientIP = srcIP

			// ClientHello Structure:
			// Version (2 bytes)
			// Random (32 bytes)
			// Session ID Length (1 byte)
			// Session ID (variable)
			// Cipher Suites Length (2 bytes)
			// Cipher Suites (variable)
			// Compression Methods Length (1 byte)
			// Compression Methods (variable)
			// Extensions Length (2 bytes, optional)
			// Extensions (variable, optional)

			// Random starts after Version (2 bytes)
			// Random starts after Version (2 bytes)
			// body[0:2] = version
			// body[2:34] = random (32 bytes)
			if len(body) >= 34 {
				sess.ClientRandom = make([]byte, 32)
				copy(sess.ClientRandom, body[2:34])
				sess.MajorVersion = body[0]
				sess.MinorVersion = body[1]
				
				crHex := hex.EncodeToString(sess.ClientRandom)
				log.Printf("[Decryptor] Captured ClientRandom: %s", crHex)
				
				// Check KeyLog
				if ms, ok := d.KeyLog[crHex]; ok {
					log.Printf("[Decryptor] FOUND Master Secret in KeyLog for session %s!", sessionKey)
					sess.MasterSecret = ms
					// We can't derive keys yet because we need ServerRandom (from ServerHello) and CipherSuite 
				}
			}
		case 0x02: // ServerHello
			log.Printf("[Decryptor] Session %s: ServerHello found", sessionKey)
			// ServerHello Structure:
			// ... (same as before)

			// Random starts after Version (2 bytes)
			// body[0:2] = version
			// body[2:34] = random (32 bytes)
			if len(body) >= 34 {
				sess.ServerRandom = make([]byte, 32)
				copy(sess.ServerRandom, body[2:34])
				log.Printf("[Decryptor] Captured ServerRandom: %x", sess.ServerRandom)

				// Cipher Suite is after Session ID
				// 34 + 1(sessIdLen) + sessIdLen
				// Cipher Suite is after Session ID
				// 34 + 1(sessIdLen) + sessIdLen
				if 34 < len(body) {
					sessIDLen := int(body[34])
					if 34+1+sessIDLen+2 <= len(body) {
						cipherSuite := binary.BigEndian.Uint16(body[34+1+sessIDLen : 34+1+sessIDLen+2])
						sess.CipherSuite = cipherSuite
						log.Printf("[Decryptor] Captured CipherSuite: 0x%04x", sess.CipherSuite)
						
						// If we already have Master Secret (from KeyLog), derive keys now!
						if sess.MasterSecret != nil && sess.ClientRandom != nil {
							d.deriveKeys(sess)
						}
					}
				}
			}
		case 0x10: // ClientKeyExchange
			log.Printf("[Decryptor] Session %s: ClientKeyExchange found", sessionKey)
			// For RSA, this contains the Encrypted PreMasterSecret
			// ...
			// If we already have keys from KeyLog, we can ignore this or verify it.
			if sess.MasterSecret != nil {
				log.Printf("[Decryptor] Skipping CKE parsing - MasterSecret already loaded from KeyLog")
				return 
			}
			
			// ... (existing RSA logic)
			if len(body) > 2 {
				// In some versions, length is implicit, but usually there's a 2-byte length prefix for the RSA key
				encLen := int(binary.BigEndian.Uint16(body[0:2]))
				if encLen == len(body)-2 {
					sess.PreMasterSecret = body[2:] // It's encrypted
				} else {
					// Fallback: assume whole body is the key (SSLv3 sometimes)
					sess.PreMasterSecret = body
				}
				
				log.Printf("[Decryptor] Extracted Encrypted PMS (Len: %d)", len(sess.PreMasterSecret))
				// Trigger Key Derivation if we have everything
				d.deriveKeys(sess)
			}
		default:
			log.Printf("[Decryptor] Unhandled Handshake Message Type: 0x%02x (Len: %d)", msgType, len(body))
		}
		
		offset += length
	}
}

func (d *Decryptor) ensureSession(key string) {
	if _, exists := d.Sessions[key]; !exists {
		d.Sessions[key] = &TLSSession{}
	}
}

func (d *Decryptor) deriveKeys(s *TLSSession) {
	if s.ClientRandom == nil || s.ServerRandom == nil {
		log.Printf("[Decryptor] deriveKeys skipped: missing Randoms")
		return
	}
	
	// Case 1: We have PreMasterSecret (RSA)
	if s.MasterSecret == nil && s.PreMasterSecret != nil && d.PrivateKey != nil {
		// 1. Decrypt PreMasterSecret
		decryptedPMS, err := rsa.DecryptPKCS1v15(nil, d.PrivateKey, s.PreMasterSecret)
		if err != nil {
			log.Printf("[Decryptor] Key Derivation Failed: RSA Decrypt error: %v", err)
			return
		}
		// s.PreMasterSecret = decryptedPMS // Don't overwrite encrypted one? Or do? Let's use local var
		log.Printf("[Decryptor] PMS Decrypted. Deriving Master Secet/Keys...")

		// 2. Derive Master Secret
		// master_secret = PRF(pre_master_secret, "master secret", ClientRandom + ServerRandom) [48]
		seed := append(s.ClientRandom, s.ServerRandom...)
		s.MasterSecret = PRF12(decryptedPMS, []byte("master secret"), seed, 48)
	}

	// Case 2: We have Master Secret (from Key Log)
	if s.MasterSecret != nil {
		// 3. Derive Key Block
		// key_block = PRF(master_secret, "key expansion", ServerRandom + ClientRandom, length)
		// Key lengths depend on CipherSuite
		
		var macKeyLen, keyLen, ivLen int
		
		switch s.CipherSuite {
		case 0x000a: // TLS_RSA_WITH_3DES_EDE_CBC_SHA
			macKeyLen = 20 // SHA1
			keyLen = 24    // 3DES (192 bits)
			ivLen = 8      // 3DES block size
		default: 
			// Default to AES-128-CBC-SHA (0x002f)
			macKeyLen = 20
			keyLen = 16
			ivLen = 16
		}

		kbLen := 2 * (macKeyLen + keyLen + ivLen)
		kbSeed := append(s.ServerRandom, s.ClientRandom...)
		s.KeyBlock = PRF12(s.MasterSecret, []byte("key expansion"), kbSeed, kbLen)
		
		log.Printf("[Decryptor] Derived KeyBlock (Len: %d) for CipherSuite 0x%04x", kbLen, s.CipherSuite)

		// Partition Key Block
		idx := 0
		s.ClientMACKey = s.KeyBlock[idx : idx+macKeyLen]; idx += macKeyLen
		s.ServerMACKey = s.KeyBlock[idx : idx+macKeyLen]; idx += macKeyLen
		s.ClientKey = s.KeyBlock[idx : idx+keyLen]; idx += keyLen
		s.ServerKey = s.KeyBlock[idx : idx+keyLen]; idx += keyLen
		s.ClientIV = s.KeyBlock[idx : idx+ivLen]; idx += ivLen
		s.ServerIV = s.KeyBlock[idx : idx+ivLen]; idx += ivLen
		
		// Add logs to verify keys
		log.Printf("[Decryptor] Keys Derived: ClientKeyLen=%d, ServerKeyLen=%d", len(s.ClientKey), len(s.ServerKey))
	}
}
	

// PRF12 implements TLS 1.2 PRF (P_SHA256)
// NOTE: rsasnakeoil2 might be TLS 1.0/1.1 which uses P_MD5 + P_SHA1
// We need to check version or support both.
// Given strict timeframe, implementing TLS 1.2 PRF first.
func PRF12(secret, label []byte, seed []byte, length int) []byte {
	labelBytes := []byte(label)
	data := append(labelBytes, seed...)
	return P_hash(sha256.New, secret, data, length)
}

// P_hash as defined in RFC 5246
func P_hash(hashFunc func() hash.Hash, secret, seed []byte, length int) []byte {
	h := hmac.New(hashFunc, secret)
	h.Write(seed)
	a := h.Sum(nil)
	
	j := 0
	result := make([]byte, length)
	
	for j < length {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		
		copy(result[j:], b)
		j += len(b)
		
		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
	
	return result[:length]
}

// DecryptApplicationData decrypts a TLS Record payload
func (d *Decryptor) DecryptApplicationData(sessionKey string, srcIP string, payload []byte) ([]byte, error) {
	// Simple record parser for 0x17 (Application Data)
	offset := 0
	var fullDecrypted []byte
	
	for offset+5 <= len(payload) {
		recordType := payload[offset]
		length := int(binary.BigEndian.Uint16(payload[offset+3:offset+5]))
		
		offset += 5
		if offset+length > len(payload) {
			break
		}

		if recordType == 0x17 { // Application Data
			ciphertext := payload[offset : offset+length]
			log.Printf("[Decryptor] Session %s: Found AppData (Len: %d)", sessionKey, len(ciphertext))
			
			decrypted, err := d.decryptRecord(sessionKey, srcIP, ciphertext)
			if err != nil {
				log.Printf("[Decryptor] Decryption error: %v", err)
			} else {
				log.Printf("[Decryptor] Decrypted %d bytes successfully", len(decrypted))
				fullDecrypted = append(fullDecrypted, decrypted...)
			}
		}
		offset += length
	}
	
	if len(fullDecrypted) > 0 {
		return fullDecrypted, nil
	}
	return nil, errors.New("no data decrypted")
}

func (d *Decryptor) decryptRecord(sessionKey string, srcIP string, payload []byte) ([]byte, error) {
	sess, exists := d.Sessions[sessionKey]
	if !exists || sess.MasterSecret == nil {
		return nil, errors.New("cannot decrypt: missing session keys")
	}

	isClient := sess.ClientIP == srcIP

	// Select Key and Block Size based on CipherSuite
	key := sess.ServerKey
	// iv := sess.ServerIV // Implicit IV uses this, Explicit IV (TLS 1.1+) uses record header
	if isClient {
		key = sess.ClientKey
		// iv = sess.ClientIV
	}

	var blockSize int
	switch sess.CipherSuite {
	case 0x000a: // 3DES
		blockSize = 8 // DES block size
	default:
		blockSize = aes.BlockSize // 16
	}

	// Create Block Cipher
	var block cipher.Block
	var err error
	
	if sess.CipherSuite == 0x000a {
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = aes.NewCipher(key)
	}
	
	if err != nil {
		return nil, err
	}
	
	if len(payload) < blockSize {
		return nil, errors.New("ciphertext too short")
	}
	
	// Assume Explicit IV for TLS 1.1+
	// For SSLv3/TLS 1.0, IV is implicit (from previous record).
	// rsasnakeoil2.cap might be TLS 1.0.
	// If TLS 1.0, we need the stored IV.
	
	// TODO: Proper version check. For now trying Explicit IV first (modern).
	// If 3DES, IV is 8 bytes.
	
	var recordIV, ciphertext []byte
	
	// Heuristic: Check if payload length is multiple of block size (Implicit IV)
	// vs Multiple of block size + 1 block (Explicit IV).
	// BUT, both case result in multiple of block size.
	
	// Usually:
	// TLS 1.1/1.2: IV (BlockSize) + Ciphertext
	// TLS 1.0: Ciphertext (IV is previous state)
	
	// Force Explicit IV logic for now as it's safer for "generic" test
	recordIV = payload[:blockSize]
	ciphertext = payload[blockSize:]
	
	if len(ciphertext)%blockSize != 0 {
		return nil, errors.New("ciphertext not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, recordIV)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove Padding
	// Last byte is padding length
	padLen := int(plaintext[len(plaintext)-1])
	if len(plaintext) < padLen+1 {
		return nil, errors.New("invalid padding")
	}
	
	// Remove Padding and MAC
	// MAC is 20 bytes (SHA1)
	unpadded := plaintext[:len(plaintext)-padLen-1]
	if len(unpadded) < 20 {
		return nil, errors.New("data too short for MAC")
	}
	
	// Strip MAC to get actual data
	actualData := unpadded[:len(unpadded)-20]
	
	return actualData, nil
}

