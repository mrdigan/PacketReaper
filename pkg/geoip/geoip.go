package geoip

import (
	_ "embed"
	"fmt"
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

//go:embed GeoLite2-City.mmdb
var cityDBBytes []byte

//go:embed GeoLite2-ASN.mmdb
var asnDBBytes []byte

// GeoIPInfo contains geographic and network ownership information for an IP
type GeoIPInfo struct {
	IP           string  `json:"ip"`
	Country      string  `json:"country"`
	CountryISO   string  `json:"countryISO"`
	City         string  `json:"city"`
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	ASN          uint    `json:"asn"`
	Organization string  `json:"organization"`
}

// GeoIPService handles GeoIP and ASN lookups with caching
type GeoIPService struct {
	cityDB *geoip2.Reader
	asnDB  *geoip2.Reader
	cache  map[string]*GeoIPInfo
	mu     sync.RWMutex
}

// NewGeoIPService creates a new GeoIP service with embedded databases
func NewGeoIPService() (*GeoIPService, error) {
	// Load City database from embedded bytes
	cityDB, err := geoip2.FromBytes(cityDBBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load City database: %w", err)
	}

	// Load ASN database from embedded bytes
	asnDB, err := geoip2.FromBytes(asnDBBytes)
	if err != nil {
		cityDB.Close()
		return nil, fmt.Errorf("failed to load ASN database: %w", err)
	}

	return &GeoIPService{
		cityDB: cityDB,
		asnDB:  asnDB,
		cache:  make(map[string]*GeoIPInfo),
	}, nil
}

// Lookup performs a GeoIP and ASN lookup for the given IP address
// Results are cached to prevent redundant lookups
func (g *GeoIPService) Lookup(ipStr string) (*GeoIPInfo, error) {
	// Check cache first (read lock)
	g.mu.RLock()
	cached, exists := g.cache[ipStr]
	g.mu.RUnlock()

	if exists {
		return cached, nil
	}

	// Parse IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Skip private/local IPs
	if isPrivateIP(ip) {
		info := &GeoIPInfo{
			IP:           ipStr,
			Country:      "Private",
			CountryISO:   "",
			City:         "",
			Organization: "Private Network",
		}
		g.mu.Lock()
		g.cache[ipStr] = info
		g.mu.Unlock()
		return info, nil
	}

	info := &GeoIPInfo{IP: ipStr}

	// Lookup City/Country info
	if cityRecord, err := g.cityDB.City(ip); err == nil {
		if cityRecord.Country.Names != nil {
			info.Country = cityRecord.Country.Names["en"]
			info.CountryISO = cityRecord.Country.IsoCode
		}
		if cityRecord.City.Names != nil {
			info.City = cityRecord.City.Names["en"]
		}
		if cityRecord.Location.Latitude != 0 || cityRecord.Location.Longitude != 0 {
			info.Latitude = cityRecord.Location.Latitude
			info.Longitude = cityRecord.Location.Longitude
		}
	}

	// Lookup ASN/Organization info
	if asnRecord, err := g.asnDB.ASN(ip); err == nil {
		info.ASN = asnRecord.AutonomousSystemNumber
		info.Organization = asnRecord.AutonomousSystemOrganization
	}

	// Cache result (write lock)
	g.mu.Lock()
	g.cache[ipStr] = info
	g.mu.Unlock()

	return info, nil
}

// Close closes the database readers
func (g *GeoIPService) Close() error {
	if g.cityDB != nil {
		g.cityDB.Close()
	}
	if g.asnDB != nil {
		g.asnDB.Close()
	}
	return nil
}

// isPrivateIP checks if an IP is in a private/local range
func isPrivateIP(ip net.IP) bool {
	// IPv4 private ranges
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	}

	for _, cidr := range private {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet != nil && subnet.Contains(ip) {
			return true
		}
	}
	return false
}

// GetCacheStats returns statistics about the cache
func (g *GeoIPService) GetCacheStats() (size int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.cache)
}
