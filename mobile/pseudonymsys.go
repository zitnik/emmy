package mobile

import (
	"fmt"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/crypto/zkp/primitives/dlogproofs"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	"math/big"
)

type PseudonymsysClient struct {
	client *client.PseudonymsysClient
}

func NewPseudonymsysClient(endpoint string) (*PseudonymsysClient, error) {
	conn, err := client.GetConnection(endpoint, "", true)
	if err != nil {
		return nil, err
	}

	c, err := client.NewPseudonymsysClient(conn)
	if err != nil {
		return nil, err
	}

	return &PseudonymsysClient{
		client: c,
	}, nil
}

func (c *PseudonymsysClient) GenerateNym(userSecret string,
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

func (c *PseudonymsysClient) ObtainCredential(userSecret string,
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

	t1 := NewTranscript(
		credential.T1.A.String(),
		credential.T1.B.String(),
		credential.T1.Hash.String(),
		credential.T1.ZAlpha.String())

	t2 := NewTranscript(
		credential.T2.A.String(),
		credential.T2.B.String(),
		credential.T2.Hash.String(),
		credential.T2.ZAlpha.String())

	return NewCredential(
		credential.SmallAToGamma.String(),
		credential.SmallBToGamma.String(),
		credential.AToGamma.String(),
		credential.BToGamma.String(),
		t1,
		t2), nil
}

func (c *PseudonymsysClient) TransferCredential(orgName, userSecret string,
	nymStr *Pseudonym, credential *Credential) (bool, error) {
	secret, _ := new(big.Int).SetString(userSecret, 10)
	a, _ := new(big.Int).SetString(nymStr.A, 10)
	b, _ := new(big.Int).SetString(nymStr.B, 10)
	atG, _ := new(big.Int).SetString(credential.SmallAToGamma, 10)
	btG, _ := new(big.Int).SetString(credential.SmallBToGamma, 10)
	AtG, _ := new(big.Int).SetString(credential.AToGamma, 10)
	BtG, _ := new(big.Int).SetString(credential.BToGamma, 10)
	if secret == nil || a == nil || b == nil || atG == nil || btG == nil ||
		AtG == nil || BtG == nil {
		return false, fmt.Errorf("Error converting string arguments to big.Int")
	}

	t1_a, _ := new(big.Int).SetString(credential.T1.A, 10)
	t1_b, _ := new(big.Int).SetString(credential.T1.B, 10)
	t1_hash, _ := new(big.Int).SetString(credential.T1.Hash, 10)
	t1_zAlpha, _ := new(big.Int).SetString(credential.T1.ZAlpha, 10)
	if t1_a == nil || t1_b == nil || t1_hash == nil || t1_zAlpha == nil {
		return false, fmt.Errorf("Transcript 1; Error converting string arguments to big.Int")
	}
	t1 := dlogproofs.NewTranscript(t1_a, t1_b, t1_hash, t1_zAlpha)

	t2_a, _ := new(big.Int).SetString(credential.T2.A, 10)
	t2_b, _ := new(big.Int).SetString(credential.T2.B, 10)
	t2_hash, _ := new(big.Int).SetString(credential.T2.Hash, 10)
	t2_zAlpha, _ := new(big.Int).SetString(credential.T2.ZAlpha, 10)
	if t2_a == nil || t2_b == nil || t2_hash == nil || t2_zAlpha == nil {
		return false, fmt.Errorf("Transcript 2; Error converting string arguments to big.Int")
	}
	t2 := dlogproofs.NewTranscript(t2_a, t2_b, t2_hash, t2_zAlpha)

	pseudonym := pseudonymsys.NewPseudonym(a, b)
	cred := pseudonymsys.NewCredential(atG, btG, AtG, BtG, t1, t2)
	authenticated, err := c.client.TransferCredential(orgName, secret, pseudonym, cred)
	if err != nil {
		return false, err
	}

	return authenticated, nil
}
