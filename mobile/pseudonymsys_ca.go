package mobile

import (
	"fmt"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/pseudonymsys"
	"math/big"
)

type PseudonymsysCAClientWrapper struct {
	client *client.PseudonymsysCAClient
}

func NewPseudonymsysCAClientWrapper(endpoint string) (*PseudonymsysCAClientWrapper, error) {
	c, err := client.NewPseudonymsysCAClient(endpoint)
	if err != nil {
		return nil, err
	}
	return &PseudonymsysCAClientWrapper{
		client: c,
	}, nil
}

func (c *PseudonymsysCAClientWrapper) ObtainCertificate(userSecret, pseudonymA,
	pseudonymB string) (*CACertificate, error) {
	secret, _ := new(big.Int).SetString(userSecret, 10)
	a, _ := new(big.Int).SetString(pseudonymA, 10)
	b, _ := new(big.Int).SetString(pseudonymB, 10)
	if secret == nil || a == nil || b == nil {
		return nil, fmt.Errorf("Error converting string arguments to big.Int")
	}

	pseudonym := pseudonymsys.NewPseudonym(a, b)
	cert, err := c.client.ObtainCertificate(secret, pseudonym)
	if err != nil {
		return nil, err
	}

	return NewCACertificate(
		cert.BlindedA.String(),
		cert.BlindedB.String(),
		cert.R.String(),
		cert.S.String()), nil
}
