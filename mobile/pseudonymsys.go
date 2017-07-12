package mobile

import (
	"fmt"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/pseudonymsys"
	"math/big"
)

type PseudonymsysClientWrapper struct {
	client *client.PseudonymsysClient
}

func NewPseudonymsysClientWrapper(endpoint string) (*PseudonymsysClientWrapper, error) {
	c, err := client.NewPseudonymsysClient(endpoint)
	if err != nil {
		return nil, err
	}
	return &PseudonymsysClientWrapper{
		client: c,
	}, nil
}

func (c *PseudonymsysClientWrapper) GenerateNym(userSecret string,
	cert *CACertificate) (*Pseudonym, error) {
	secret, _ := new(big.Int).SetString(userSecret, 10)
	blindedA, _ := new(big.Int).SetString(cert.BlindedA, 10)
	blindedB, _ := new(big.Int).SetString(cert.BlindedB, 10)
	r, _ := new(big.Int).SetString(cert.R, 10)
	s, _ := new(big.Int).SetString(cert.S, 10)
	if secret == nil || blindedA == nil || blindedB == nil || r == nil || s == nil {
		return nil, fmt.Errorf("Error converting string arguments to big.Int")
	}

	certificate := pseudonymsys.NewCACertificate(blindedA, blindedB, r, s)
	nym, err := c.client.GenerateNym(secret, certificate)
	if err != nil {
		return nil, err
	}

	return NewPseudonym(nym.A.String(), nym.B.String()), nil
}

func (c *PseudonymsysClientWrapper) ObtainCredential(userSecret string,
	nymStr *Pseudonym, pubKeys *OrgPubKeys) (*Credential, error) {
	secret, _ := new(big.Int).SetString(userSecret, 10)
	a, _ := new(big.Int).SetString(nymStr.A, 10)
	b, _ := new(big.Int).SetString(nymStr.B, 10)
	h1, _ := new(big.Int).SetString(pubKeys.H1, 10)
	h2, _ := new(big.Int).SetString(pubKeys.H2, 10)
	if secret == nil || a == nil || b == nil || h1 == nil || h2 == nil {
		return nil, fmt.Errorf("Error converting string arguments to big.Int")
	}

	pseudonym := pseudonymsys.NewPseudonym(a, b)
	orgPubKeys := pseudonymsys.NewOrgPubKeys(h1, h2)
	credential, err := c.client.ObtainCredential(secret, pseudonym, orgPubKeys)
	if err != nil {
		return nil, err
	}

	n := len(credential.T1)
	t1 := make([]string, n)
	t2 := make([]string, n)
	for i, v := range credential.T1 {
		t1[i] = v.String()
		t2[i] = v.String()
	}

	return NewCredential(
		credential.SmallAToGamma.String(),
		credential.SmallBToGamma.String(),
		credential.AToGamma.String(),
		credential.BToGamma.String(),
		t1,
		t2), nil
}

func (c *PseudonymsysClientWrapper) TransferCredential(orgName, userSecret string,
	nymStr *Pseudonym, credentialStr *Credential) (bool, error) {
	secret, _ := new(big.Int).SetString(userSecret, 10)
	a, _ := new(big.Int).SetString(nymStr.A, 10)
	b, _ := new(big.Int).SetString(nymStr.B, 10)
	atG, _ := new(big.Int).SetString(credentialStr.SmallAToGamma, 10)
	btG, _ := new(big.Int).SetString(credentialStr.SmallBToGamma, 10)
	AtG, _ := new(big.Int).SetString(credentialStr.AToGamma, 10)
	BtG, _ := new(big.Int).SetString(credentialStr.BToGamma, 10)
	if secret == nil || a == nil || b == nil || atG == nil || btG == nil ||
		AtG == nil || BtG == nil {
		return false, fmt.Errorf("Error converting string arguments to big.Int")
	}

	n := len(credentialStr.T1)
	t1 := make([]*big.Int, n)
	t2 := make([]*big.Int, n)
	for i, v := range credentialStr.T1 {
		t1[i], _ = new(big.Int).SetString(v, 10)
		t2[i], _ = new(big.Int).SetString(v, 10)
	}

	pseudonym := pseudonymsys.NewPseudonym(a, b)
	credential := pseudonymsys.NewCredential(atG, btG, AtG, BtG, t1, t2)
	authenticated, err := c.client.TransferCredential(orgName, secret, pseudonym, credential)
	if err != nil {
		return false, err
	}

	return authenticated, nil
}
