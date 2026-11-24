package scan

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// SEP-23 strkey framing, as it applies to the two account kinds Assay accepts
// as a holder identifier.
//
// A G… account is 56 characters: a one-byte version, the 32-byte ed25519 public
// key, and a two-byte checksum. An M… muxed account is 69 characters: the same
// version-plus-checksum framing around a 40-byte payload — the 32-byte key
// followed by the 64-bit multiplexing id in big-endian order (SEP-23, "Muxed
// ed25519 public key"; the id is a uint64 as it appears in
// MuxedAccountMed25519 XDR).
//
// The decoder is local to this package, matching the hand-rolled strkey
// decoders in internal/sac and internal/differential: the project takes no
// Stellar SDK dependency, and a small decode is cheaper to audit than a
// third-party one.
const (
	strkeyAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	strkeyVersionAccount = byte(6) << 3  // 'G'
	strkeyVersionMuxed   = byte(12) << 3 // 'M'

	// accountIDPayloadLen is the ed25519 public key every account strkey wraps.
	accountIDPayloadLen = 32
	// muxedPayloadLen is that key plus the 8-byte multiplexing id.
	muxedPayloadLen = accountIDPayloadLen + 8

	// accountIDStrkeyLen and muxedStrkeyLen are the base32 lengths of
	// (version + payload + checksum) for each kind: 35 and 43 bytes, rounded
	// up to whole 5-bit characters.
	accountIDStrkeyLen = 56
	muxedStrkeyLen     = 69
)

var strkeyBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrBadHolder reports an invalid holder account ID.
var ErrBadHolder = errors.New("scan: invalid holder account ID")

// ErrBadMuxedHolder reports an M… address that is not a well-formed SEP-23
// muxed ed25519 account. It is wrapped by ErrBadHolder, so a caller that only
// needs "the input was refused" keeps working.
var ErrBadMuxedHolder = errors.New("scan: invalid muxed holder account ID")

// ParseHolder validates a holder identifier and resolves it to the account that
// can actually be read from the ledger.
//
// A muxed account (M…) does not exist as a ledger entry: it is an off-chain
// naming convention for payments to a virtual sub-account of a real G… account
// (SEP-23). So an M… holder is resolved to its base account for the trustline
// lookup, and the multiplexing id is returned alongside it so the report can say
// which virtual account the caller asked about. A G… holder is returned
// unchanged with muxed=false.
//
// Anything else — a 56-character string that fails its checksum or carries the
// wrong version byte, a C… contract, a 69-character M… that does not decode to
// exactly 40 payload bytes, a truncated paste — is refused rather than guessed
// at. In particular the version byte and checksum are checked, because a
// corrupted address that merely looks right must not be resolved onto a
// different account: that would inspect one holder's trustline and report it
// under another's address.
func ParseHolder(id string) (base string, muxedID uint64, muxed bool, err error) {
	switch len(id) {
	case accountIDStrkeyLen:
		if _, err := decodeHolderStrkey(strkeyVersionAccount, id); err != nil {
			return "", 0, false, fmt.Errorf("%w: %q: %w", ErrBadHolder, id, err)
		}
		return id, 0, false, nil
	case muxedStrkeyLen:
		payload, err := decodeHolderStrkey(strkeyVersionMuxed, id)
		if err != nil {
			return "", 0, false, fmt.Errorf("%w: %q: %w", ErrBadHolder, id, err)
		}
		if len(payload) != muxedPayloadLen {
			return "", 0, false, fmt.Errorf(
				"%w: %q: muxed payload is %d bytes, want %d",
				ErrBadMuxedHolder, id, len(payload), muxedPayloadLen)
		}
		key := payload[:accountIDPayloadLen]
		return encodeAccountStrkey(key), binary.BigEndian.Uint64(payload[accountIDPayloadLen:]), true, nil
	default:
		return "", 0, false, fmt.Errorf(
			"%w: %q is %d characters, want %d (G…) or %d (M…)",
			ErrBadHolder, id, len(id), accountIDStrkeyLen, muxedStrkeyLen)
	}
}

// ValidateHolder checks that id is a Stellar account ID suitable for use as a
// holder identifier: a G… ed25519 account, or an M… muxed ed25519 account that
// ParseHolder can resolve to one.
func ValidateHolder(id string) error {
	_, _, _, err := ParseHolder(id)
	return err
}

// decodeHolderStrkey verifies the framing of one strkey and returns its payload
// (the bytes between the version byte and the checksum).
//
// The bit-buffer decode is deliberate: 56 and 69 characters are 280 and 345
// bits, and neither fits the intuitive "5 bits per character into an integer"
// shortcut. A truncating decode would produce a key that passes the length and
// alphabet checks while addressing a different account.
func decodeHolderStrkey(wantVersion byte, s string) ([]byte, error) {
	raw := make([]byte, 0, 1+len(s)*5/8)
	var acc uint32
	var bits uint8
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(strkeyAlphabet, s[i])
		if v < 0 {
			return nil, fmt.Errorf("character %q is outside the base32 alphabet", s[i])
		}
		acc = acc<<5 | uint32(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			raw = append(raw, byte(acc>>bits))
		}
	}
	// The trailing bits of a strkey are zero padding; a non-zero remainder
	// would mean the string encodes bytes Assay is not reading.
	if bits > 0 && acc&(1<<bits-1) != 0 {
		return nil, errors.New("non-zero padding bits")
	}
	if len(raw) < 3 {
		return nil, errors.New("too short to carry a version byte and checksum")
	}
	if raw[0] != wantVersion {
		return nil, fmt.Errorf("version byte 0x%02x is not 0x%02x", raw[0], wantVersion)
	}
	body, sum := raw[:len(raw)-2], raw[len(raw)-2:]
	want := crc16XModem(body)
	if sum[0] != byte(want&0xff) || sum[1] != byte(want>>8) {
		return nil, errors.New("checksum mismatch")
	}
	return body[1:], nil
}

// encodeAccountStrkey renders a 32-byte ed25519 public key as its G… form. It is
// used only to hand the resolved base account back to the caller; the input to
// it always came out of a verified M… strkey.
func encodeAccountStrkey(key []byte) string {
	raw := make([]byte, 0, 1+len(key)+2)
	raw = append(raw, strkeyVersionAccount)
	raw = append(raw, key...)
	sum := crc16XModem(raw)
	raw = append(raw, byte(sum&0xff), byte(sum>>8))
	return strkeyBase32.EncodeToString(raw)
}

// crc16XModem is the checksum Stellar appends to every strkey: the
// non-reflected CCITT polynomial 0x1021 with initial value 0, no final
// complement, appended little-endian (SEP-23, "CRC16-XModem").
func crc16XModem(data []byte) uint16 {
	var crc uint16
	for _, b := range data {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
