package mobile

type CACertificate struct {
	BlindedA string
	BlindedB string
	R        string
	S        string
}

type Pseudonym struct {
	A string
	B string
}

type Credential struct {
	SmallAToGamma string
	SmallBToGamma string
	AToGamma      string
	BToGamma      string
	T1            []string
	T2            []string
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

func NewCredential(aToGamma, bToGamma, AToGamma, BToGamma string,
	t1, t2 []string) *Credential {
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

func NewCACertificate(blindedA, blindedB, r, s string) *CACertificate {
	return &CACertificate{
		BlindedA: blindedA,
		BlindedB: blindedB,
		R:        r,
		S:        s,
	}
}

func NewPseudonym(a, b string) *Pseudonym {
	return &Pseudonym{
		A: a,
		B: b,
	}
}
