package mobile

import (
	"fmt"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	"google.golang.org/grpc"
	"math/big"
)

type PseudonymsysCAClient struct {
	client *client.PseudonymsysCAClient
	conn   *grpc.ClientConn
}

func NewPseudonymsysCAClient(endpoint string) (*PseudonymsysCAClient, error) {
	conn, err := client.GetConnection(endpoint, "", true)
	if err != nil {
		return nil, err
	}

	c, err := client.NewPseudonymsysCAClient(conn)
	if err != nil {
		return nil, err
	}

	return &PseudonymsysCAClient{
		client: c,
		conn:   conn,
	}, nil
}

func (c *PseudonymsysCAClient) ObtainCertificate(userSecret, pseudonymA,
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

// Disconnect attempts to close the underlying client connection to gRPC server.
func (c *PseudonymsysCAClient) Disconnect() error {
	return c.conn.Close()
}
