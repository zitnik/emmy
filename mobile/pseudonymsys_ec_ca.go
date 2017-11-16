package mobile

import (
	"fmt"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/crypto/dlog"
	"github.com/xlab-si/emmy/crypto/zkp/schemes/pseudonymsys"
	"github.com/xlab-si/emmy/types"
	"google.golang.org/grpc"
	"math/big"
)

type PseudonymsysCAECClient struct {
	client *client.PseudonymsysCAClientEC
	conn   *grpc.ClientConn
}

func NewPseudonymsysCAECClient(endpoint string) (*PseudonymsysCAECClient, error) {
	conn, err := client.GetConnection(endpoint, "", true)
	if err != nil {
		return nil, err
	}

	// TODO make curve configurable
	c, err := client.NewPseudonymsysCAClientEC(conn, dlog.P256)
	if err != nil {
		return nil, err
	}

	return &PseudonymsysCAECClient{
		client: c,
		conn:   conn,
	}, nil
}

func (c *PseudonymsysCAECClient) ObtainCertificate(userSecret string, pseudonym *PseudonymEC) (*CACertificateEC, error) {
	secret, _ := new(big.Int).SetString(userSecret, 10)
	ax, _ := new(big.Int).SetString(pseudonym.A.X, 10)
	ay, _ := new(big.Int).SetString(pseudonym.A.Y, 10)
	bx, _ := new(big.Int).SetString(pseudonym.B.X, 10)
	by, _ := new(big.Int).SetString(pseudonym.B.Y, 10)

	if secret == nil || ax == nil || ay == nil || bx == nil || by == nil {
		return nil, fmt.Errorf("Error converting string arguments to big.Int")
	}

	a := types.NewECGroupElement(ax, ay)
	b := types.NewECGroupElement(bx, by)
	masterNym := pseudonymsys.NewPseudonymEC(a, b)

	cert, err := c.client.ObtainCertificate(secret, masterNym)
	if err != nil {
		return nil, err
	}

	return NewCACertificateEC(
		NewECGroupElement(cert.BlindedA.X.String(), cert.BlindedA.Y.String()),
		NewECGroupElement(cert.BlindedB.X.String(), cert.BlindedB.Y.String()),
		cert.R.String(),
		cert.S.String()), nil
}

// Disconnect attempts to close the underlying client connection to gRPC server.
func (c *PseudonymsysCAECClient) Disconnect() error {
	return c.conn.Close()
}
