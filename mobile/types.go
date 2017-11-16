package mobile

type CACertificate struct {
	BlindedA string
	BlindedB string
	R        string
	S        string
}

func NewCACertificate(blindedA, blindedB, r, s string) *CACertificate {
	return &CACertificate{
		BlindedA: blindedA,
		BlindedB: blindedB,
		R:        r,
		S:        s,
	}
}

type CACertificateEC struct {
	BlindedA *ECGroupElement
	BlindedB *ECGroupElement
	R        string
	S        string
}

func NewCACertificateEC(bA, bB *ECGroupElement, r, s string) *CACertificateEC {
	return &CACertificateEC{
		BlindedA: bA,
		BlindedB: bB,
		R:        r,
		S:        s,
	}
}

type ECGroupElement struct {
	X string
	Y string
}

func NewECGroupElement(x, y string) *ECGroupElement {
	return &ECGroupElement{
		X: x,
		Y: y,
	}
}

type Pseudonym struct {
	A string
	B string
}

func NewPseudonym(a, b string) *Pseudonym {
	return &Pseudonym{
		A: a,
		B: b,
	}
}

type PseudonymEC struct {
	A *ECGroupElement
	B *ECGroupElement
}

func NewPseudonymEC(a, b *ECGroupElement) *PseudonymEC {
	return &PseudonymEC{
		A: a,
		B: b,
	}
}

type Credential struct {
	SmallAToGamma string
	SmallBToGamma string
	AToGamma      string
	BToGamma      string
	T1            *Transcript
	T2            *Transcript
}

func NewCredential(aToGamma, bToGamma, AToGamma, BToGamma string,
	t1, t2 *Transcript) *Credential {
	credential := &Credential{
		SmallAToGamma: aToGamma,
		SmallBToGamma: bToGamma,
		AToGamma:      AToGamma,
		BToGamma:      BToGamma,
		T1:            t1,
		T2:            t2,
	}
	return credential
}

type OrgPubKeys struct {
	H1 string
	H2 string
}

func NewOrgPubKeys(h1, h2 string) *OrgPubKeys {
	return &OrgPubKeys{
		H1: h1,
		H2: h2,
	}
}

type Transcript struct {
	A      string
	B      string
	Hash   string
	ZAlpha string
}

func NewTranscript(a, b, hash, zAlpha string) *Transcript {
	return &Transcript{
		A:      a,
		B:      b,
		Hash:   hash,
		ZAlpha: zAlpha,
	}
}

type ServiceInfo struct {
	Name        string
	Description string
	Provider    string
}

func NewServiceInfo(name, description, provider string) *ServiceInfo {
	return &ServiceInfo{
		Name:        name,
		Description: description,
		Provider:    provider,
	}
}
