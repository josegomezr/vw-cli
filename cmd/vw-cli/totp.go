package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"time"
)

func totpHashAlgo(name string) (func() hash.Hash, error) {
	switch name {
	case "":
		fallthrough
	case "sha1":
		return sha1.New, nil
	case "sha256":
		return sha256.New, nil
	default:
		return nil, fmt.Errorf("Unknown hashing algorithm")
	}
}

type TOTPSettings struct {
	Period    int
	Digits    int
	Secret    string
	Time      *time.Time
	Algorithm string
}

func parseIntOrZero(in string) int {
	v, err := strconv.Atoi(in)
	if err != nil {
		return 0
	}
	return v
}

func NewTOTPSettingsFromURL(qs url.Values) TOTPSettings {
	return TOTPSettings{
		Secret: qs.Get("secret"),
		Period: parseIntOrZero(qs.Get("period")),
		Digits: parseIntOrZero(qs.Get("digits")),
	}
}

func totpgen(settings TOTPSettings) (code string, err error) {
	hashalgo, err := totpHashAlgo(settings.Algorithm)
	if err != nil {
		return
	}
	secretBytes, err := base32.StdEncoding.DecodeString(settings.Secret)
	if err != nil {
		return
	}
	p := settings.Period
	if p == 0 {
		p = 30
	}
	digits := settings.Digits
	if digits == 0 {
		digits = 6
	}

	t := settings.Time
	if t == nil {
		tmp := time.Now()
		t = &tmp
	}
	counter := uint64(math.Floor(float64(t.Unix()) / float64(p)))

	mac := hmac.New(hashalgo, secretBytes)
	binary.Write(mac, binary.BigEndian, counter)
	sum := mac.Sum(nil)

	// "Dynamic truncation" in RFC 4226
	// http://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[len(sum)-1] & 0xf
	value := int64(
		((int(sum[offset]) & 0x7f) << 24) |
			((int(sum[offset+1]) & 0xff) << 16) |
			((int(sum[offset+2]) & 0xff) << 8) |
			(int(sum[offset+3]) & 0xff))

	mod := int32(value % int64(math.Pow10(digits)))
	f := fmt.Sprintf("%%0%dd", digits)
	code = fmt.Sprintf(f, mod)
	return
}
