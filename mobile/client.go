/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package mobile

/*func newClient(endpoint string) (*enericClient, error) {
	conn, err := GetConnection(endpoint)
	if err != nil {
		return nil, err
	}

	client := pb.NewProtocolClient(conn)
	stream, err := getStream(client)
	if err != nil {
		return nil, err
	}

	rand.Seed(time.Now().UTC().UnixNano())

	genClient := genericClient{
		id:     rand.Int31(),
		conn:   conn,
		stream: stream,
	}

	return &genClient, nil
}

// NewPedersenMobileClient will create a PedersenClient instance just like the NewPedersenClient,
// however it only accepts string arguments compatible with gomobile bind.
func NewPedersenMobileClient(endpoint, variant, dlogP, dlogG, dlogO, val string) (*PedersenClient, error) {
	genericClient, err := newClient(endpoint)
	if err != nil {
		return nil, err
	}

	p, _ := new(big.Int).SetString(dlogP, 10)
	g, _ := new(big.Int).SetString(dlogG, 10)
	o, _ := new(big.Int).SetString(dlogO, 10)
	v, _ := new(big.Int).SetString(val, 10)
	if p == nil || g == nil || o == nil || v == nil {
		return nil, fmt.Errorf("Error converting string arguments to big.Int")
	}

	dlog := dlog.NewZpDLog(p, g, o)

	return &PedersenClient{
		pedersenCommonClient: pedersenCommonClient{genericClient: *genericClient},
		committer:            commitments.NewPedersenCommitter(dlog),
		val:                  v,
	}, nil
}

// NewPedersenECMobileClient will create a PedersenECClient instance just like
// NewPedersenECClient, however it only accepts string arguments compatible with gomobile bind.
func NewPedersenECMobileClient(endpoint, val string) (*PedersenECClient, error) {
	genericClient, err := newClient(endpoint)
	if err != nil {
		return nil, err
	}

	v, _ := new(big.Int).SetString(val, 10)
	if v == nil {
		return nil, fmt.Errorf("Error converting string argument to big.Int")
	}

	return &PedersenECClient{
		pedersenCommonClient: pedersenCommonClient{genericClient: *genericClient},
		committer:            commitments.NewPedersenECCommitter(),
		val:                  v,
	}, nil
}

// NewSchnorrMobileClient will create a SchnorrClient instance just like NewSchnorrClient,
// however it only accepts string arguments compatible with gomobile bind.
func NewSchnorrMobileClient(endpoint, variant, dlogP, dlogG, dlogO,
	secret string) (*SchnorrClient, error) {
	genericClient, err := newClient(endpoint)
	if err != nil {
		return nil, err
	}

	p, _ := new(big.Int).SetString(dlogP, 10)
	g, _ := new(big.Int).SetString(dlogG, 10)
	o, _ := new(big.Int).SetString(dlogO, 10)
	s, _ := new(big.Int).SetString(secret, 10)
	if p == nil || g == nil || o == nil || s == nil {
		return nil, fmt.Errorf("Error converting string arguments to big.Int")
	}

	dlog := dlog.NewZpDLog(p, g, o)
	v, err := common.FromStringToProtocolType(variant)
	if err != nil {
		return nil, err
	}

	vPb, _ := common.FromStringToPbType(variant)

	return &SchnorrClient{
		genericClient: *genericClient,
		variant:       vPb,
		prover:        dlogproofs.NewSchnorrProver(dlog, v),
		secret:        s,
		a:             dlog.G, // fix !!!
	}, nil
}

// NewSchnorrECMobileClient will create a SchnorrECClient instance just like NewSchnorrECClient,
// however it only accepts string arguments compatible with gomobile bind.
func NewSchnorrECMobileClient(endpoint, variant,
	secret string) (*SchnorrECClient, error) {
	genericClient, err := newClient(endpoint)
	if err != nil {
		return nil, err
	}

	v, err := common.FromStringToProtocolType(variant)
	if err != nil {
		return nil, err
	}
	vPb, _ := common.FromStringToPbType(variant)

	prover, err := dlogproofs.NewSchnorrECProver(v)
	if err != nil {
		return nil, fmt.Errorf("Could not create schnorr EC prover: %v", err)
	}

	s, _ := new(big.Int).SetString(secret, 10)
	if s == nil {
		return nil, fmt.Errorf("Error converting secret to big.Int")
	}

	// Note that this is only temporary, the EC type will have to be passed from outside
	ec_dlog := dlog.NewECDLog()

	return &SchnorrECClient{
		genericClient: *genericClient,
		prover:        prover,
		variant:       vPb,
		secret:        s,
		a: &common.ECGroupElement{
			X: ec_dlog.Curve.Params().Gx,
			Y: ec_dlog.Curve.Params().Gy,
		},
	}, nil
}

// NewCSPaillierMobileClient will create a CSPaillierClient instance just like NewCSPaillierClient,
// however it only accepts string arguments compatible with gomobile bind.
func NewCSPaillierMobileClient(endpoint, pubKeyPath, m, l string) (*CSPaillierClient, error) {
	genericClient, err := newClient(endpoint)
	if err != nil {
		return nil, err
	}

	logger.Debug(pubKeyPath)
	encryptor, err := encryption.NewCSPaillierFromPubKeyFile(pubKeyPath)
	if err != nil {
		return nil, err
	}

	mBig, _ := new(big.Int).SetString(m, 10)
	lBig, _ := new(big.Int).SetString(l, 10)
	if mBig == nil || lBig == nil {
		return nil, fmt.Errorf("Error converting string arguments to big.Int")
	}

	return &CSPaillierClient{
		genericClient: *genericClient,
		encryptor:     encryptor,
		m:             mBig,
		label:         lBig,
	}, nil
}
*/
