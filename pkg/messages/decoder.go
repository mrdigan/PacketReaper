package messages

import (
	"encoding/base64"
	"mime"
	"mime/quotedprintable"
	"strings"
	"io"
)

// DecodeBase64 decodes a Base64-encoded string
func DecodeBase64(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// DecodeQuotedPrintable decodes a Quoted-Printable encoded string
func DecodeQuotedPrintable(encoded string) (string, error) {
	reader := quotedprintable.NewReader(strings.NewReader(encoded))
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// ParseMIME extracts the main body and attachments from MIME content
func ParseMIME(contentType, body string) (mainBody string, attachments []Attachment, err error) {
	// Parse Content-Type header
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		// If parsing fails, return body as-is
		return body, nil, nil
	}

	// Check if multipart
	if !strings.HasPrefix(mediaType, "multipart/") {
		return body, nil, nil
	}

	boundary := params["boundary"]
	if boundary == "" {
		return body, nil, nil
	}

	// Split by boundary
	parts := strings.Split(body, "--"+boundary)
	
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "--" {
			continue
		}

		// Split headers from content
		headerEnd := strings.Index(part, "\r\n\r\n")
		if headerEnd == -1 {
			headerEnd = strings.Index(part, "\n\n")
		}
		if headerEnd == -1 {
			continue
		}

		headers := part[:headerEnd]
		content := part[headerEnd+2:]

		// Extract Content-Disposition (for attachments)
		if strings.Contains(headers, "Content-Disposition:") {
			lines := strings.Split(headers, "\n")
			for _, line := range lines {
				if strings.HasPrefix(strings.TrimSpace(line), "Content-Disposition:") {
					// This is likely an attachment
					filename := ""
					contentType := ""
					
					// Extract filename
					if idx := strings.Index(line, "filename="); idx != -1 {
						rest := line[idx+9:]
						rest = strings.Trim(rest, `"' `)
						if semiIdx := strings.Index(rest, ";"); semiIdx != -1 {
							filename = rest[:semiIdx]
						} else {
							filename = strings.TrimSpace(rest)
						}
					}

					// Extract content-type from headers
					for _, hline := range lines {
						if strings.HasPrefix(strings.TrimSpace(hline), "Content-Type:") {
							contentType = strings.TrimSpace(strings.TrimPrefix(hline, "Content-Type:"))
							if semiIdx := strings.Index(contentType, ";"); semiIdx != -1 {
								contentType = contentType[:semiIdx]
							}
						}
					}

					if filename != "" {
						attachments = append(attachments, Attachment{
							Filename:    filename,
							ContentType: contentType,
							Size:        len(content),
						})
					}
				}
			}
		} else if strings.Contains(headers, "text/plain") || strings.Contains(headers, "text/html") {
			// This is the main body
			mainBody = content
		}
	}

	return mainBody, attachments, nil
}
