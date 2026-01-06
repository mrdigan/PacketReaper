package ja3

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ComputeJA3 calculates the JA3 fingerprint from a TLS Client Hello payload.
// Returns the JA3 string and its MD5 hash.
// Returns empty strings if not a valid Client Hello.
func ComputeJA3(payload []byte) (string, string) {
	// TLS Record Header: Type(1) + Ver(2) + Len(2) = 5 bytes
	if len(payload) < 5 {
		return "", ""
	}

	// 0x16 = Handshake
	if payload[0] != 0x16 {
		return "", ""
	}

	// TLS Record Length
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return "", ""
	}

	// Handshake Header: Type(1) + Len(3) = 4 bytes
	handshake := payload[5:]
	if len(handshake) < 4 {
		return "", ""
	}

	// 0x01 = Client Hello
	if handshake[0] != 0x01 {
		return "", ""
	}

	// Handshake Length
	handshakeLen := int(uint32(handshake[1])<<16 | uint32(handshake[2])<<8 | uint32(handshake[3]))
	if len(handshake) < 4+handshakeLen {
		return "", ""
	}

	// Client Hello Body starts at offset 4
	body := handshake[4:]
	if len(body) < 34 { // Version(2) + Random(32)
		return "", ""
	}

	offset := 0

	// 1. SSL Version (bytes 0-1)
	sslVersion := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2

	// Skip Random (32 bytes)
	offset += 32

	// Session ID (1 byte len + data)
	if offset+1 > len(body) {
		return "", ""
	}
	sessIDLen := int(body[offset])
	offset += 1 + sessIDLen

	// Cipher Suites (2 byte len + data)
	if offset+2 > len(body) {
		return "", ""
	}
	cipherLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2

	if offset+cipherLen > len(body) {
		return "", ""
	}
	ciphers := body[offset : offset+cipherLen]
	offset += cipherLen

	// Collect Cipher Suites
	var cipherList []string
	for i := 0; i < len(ciphers); i += 2 {
		val := int(binary.BigEndian.Uint16(ciphers[i : i+2]))
		// JA3 excludes GREASE values (0x?a?a)
		if !isGrease(val) {
			cipherList = append(cipherList, strconv.Itoa(val))
		}
	}

	// Compression Methods (1 byte len + data)
	if offset+1 > len(body) {
		return "", ""
	}
	compLen := int(body[offset])
	offset += 1

	if offset+compLen > len(body) {
		return "", ""
	}
	// JA3 doesn't use compression methods for the hash (usually just 0), but let's check spec.
	// Wait, JA3 spec: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
	// Compression IS NOT in JA3!
	offset += compLen

	// Extensions
	// If no extensions, we are done
	if offset >= len(body) {
		return buildJA3(sslVersion, cipherList, nil, nil, nil)
	}

	// Extensions Length (2 bytes)
	if offset+2 > len(body) {
		return buildJA3(sslVersion, cipherList, nil, nil, nil)
	}
	extTotalLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2

	if offset+extTotalLen > len(body) {
		return buildJA3(sslVersion, cipherList, nil, nil, nil)
	}
	extensionsData := body[offset : offset+extTotalLen]

	var extList []string
	var curvesList []string
	var pointFormatsList []string

	extOffset := 0
	for extOffset+4 <= len(extensionsData) {
		extType := int(binary.BigEndian.Uint16(extensionsData[extOffset : extOffset+2]))
		extLen := int(binary.BigEndian.Uint16(extensionsData[extOffset+2 : extOffset+4]))
		extOffset += 4

		if extOffset+extLen > len(extensionsData) {
			break
		}
		extVal := extensionsData[extOffset : extOffset+extLen]

		// Exclude GREASE extensions
		if !isGrease(extType) {
			extList = append(extList, strconv.Itoa(extType))
		}

		// Parse specific extensions for JA3
		// 0x000a = Supported Groups (Elliptic Curves)
		// 0x000b = EC Point Formats
		if extType == 0x000a && len(extVal) >= 2 {
			// Supported Groups List Length (2 bytes)
			// JA3 Spec: "The Elliptic Curve Extension is 0x000a... we want the values"
			// Format: List Length (2 bytes) + Values (2 bytes each)
			listLen := int(binary.BigEndian.Uint16(extVal[0:2]))
			if listLen+2 <= len(extVal) {
				vals := extVal[2 : 2+listLen]
				for k := 0; k < len(vals); k += 2 {
					curve := int(binary.BigEndian.Uint16(vals[k : k+2]))
					if !isGrease(curve) {
						curvesList = append(curvesList, strconv.Itoa(curve))
					}
				}
			}
		} else if extType == 0x000b && len(extVal) >= 1 {
			// EC Point Formats Length (1 byte) + Values (1 byte each)
			listLen := int(extVal[0])
			if listLen+1 <= len(extVal) {
				vals := extVal[1 : 1+listLen]
				for _, pf := range vals {
					pointFormatsList = append(pointFormatsList, strconv.Itoa(int(pf)))
				}
			}
		}

		extOffset += extLen
	}

	return buildJA3(sslVersion, cipherList, extList, curvesList, pointFormatsList)
}

func buildJA3(version int, ciphers, extensions, curves, points []string) (string, string) {
	ja3String := fmt.Sprintf("%d,%s,%s,%s,%s",
		version,
		strings.Join(ciphers, "-"),
		strings.Join(extensions, "-"),
		strings.Join(curves, "-"),
		strings.Join(points, "-"),
	)

	hash := md5.Sum([]byte(ja3String))
	return ja3String, hex.EncodeToString(hash[:])
}

// isGrease checks for GREASE (Generate Random Extensions And Sustain Extensibility) values
// Reserved values: 0x0a0a, 0x1a1a, ..., 0xfafa
func isGrease(v int) bool {
	return (v & 0x0f0f) == 0x0a0a
}
