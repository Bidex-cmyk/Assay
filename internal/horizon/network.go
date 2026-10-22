package horizon

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Network identifies a Stellar network by its protocol passphrase.
type Network string

const (
	PublicNet Network = "Public Global Stellar Network ; September 2015"
	TestNet   Network = "Test SDF Network ; September 2015"
)

var ErrUnknownNetwork = errors.New("horizon: unknown network")

// NetworkFor identifies the network only for the canonical Horizon hosts.
func NetworkFor(rawURL string) (Network, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("%w: %q", ErrUnknownNetwork, rawURL)
	}

	switch strings.ToLower(u.Hostname()) {
	case "horizon.stellar.org":
		return PublicNet, nil
	case "horizon-testnet.stellar.org":
		return TestNet, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownNetwork, rawURL)
	}
}

// Network reports the network for this client's Horizon endpoint.
func (c *Client) Network() (Network, error) {
	return NetworkFor(c.BaseURL)
}