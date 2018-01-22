// Package xmlsig supports add XML Digital Signatures to Go structs marshalled to XML.
package xmlsig

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// Signer is used to create a Signature for the provided object.
type Signer interface {
	Sign([]byte) (string, error)
	CreateSignature(interface{}) (*Signature, error)
	Algorithm() string
}

type signer struct {
	cert      string
	algorithm string
	key       crypto.Signer
}

// NewSigner creates a new Signer with the certificate.
func NewSigner(cert tls.Certificate) (Signer, error) {
	c := cert.Certificate[0]
	parsedCert, err := x509.ParseCertificate(c)
	if err != nil {
		return nil, err
	}
	var alg string
	switch parsedCert.SignatureAlgorithm {
	case x509.SHA1WithRSA:
		fallthrough
	case x509.SHA256WithRSA:
		fallthrough
	case x509.SHA384WithRSA:
		fallthrough
	case x509.SHA512WithRSA:
		alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
		break
	case x509.DSAWithSHA1:
		fallthrough
	case x509.DSAWithSHA256:
		alg = "http://www.w3.org/2009/xmldsig11#dsa-sha256"
		break
	default:
		return nil, fmt.Errorf("xmlsig needs some work to support %s certificates", parsedCert.SignatureAlgorithm.String())
	}
	k := cert.PrivateKey.(crypto.Signer)
	return &signer{base64.StdEncoding.EncodeToString(c), alg, k}, nil
}

func (s *signer) Algorithm() string {
	return s.algorithm
}

func (s *signer) CreateSignature(data interface{}) (*Signature, error) {
	signature := newSignature()
	signature.SignedInfo.SignatureMethod.Algorithm = s.algorithm
	// canonicalize the Item
	canonData, id, err := canonicalize(data)
	if err != nil {
		return nil, err
	}
	if id != "" {
		signature.SignedInfo.Reference.URI = "#" + id
	}
	// calculate the digest
	digest := digest(canonData)
	signature.SignedInfo.Reference.DigestValue = digest
	// canonicalize the SignedInfo
	canonData, _, err = canonicalize(signature.SignedInfo)
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(canonData)
	if err != nil {
		return nil, err
	}
	signature.SignatureValue = sig
	x509Data := &X509Data{X509Certificate: s.cert}
	signature.KeyInfo.X509Data = x509Data
	return signature, nil
}

func (s *signer) Sign(data []byte) (string, error) {
	h := sha256.New()
	h.Write(data)
	sum := h.Sum(nil)
	sig, err := s.key.Sign(rand.Reader, sum, crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

func newSignature() *Signature {
	signature := &Signature{}
	signature.SignedInfo.CanonicalizationMethod.Algorithm =
		"http://www.w3.org/2001/10/xml-exc-c14n#"
	transforms := &signature.SignedInfo.Reference.Transforms.Transform
	*transforms = append(*transforms, Algorithm{"http://www.w3.org/2000/09/xmldsig#enveloped-signature"})
	*transforms = append(*transforms, Algorithm{"http://www.w3.org/2001/10/xml-exc-c14n#"})
	signature.SignedInfo.Reference.DigestMethod.Algorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
	return signature
}

func digest(data []byte) string {
	h := sha256.New()
	h.Write(data)
	sum := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(sum)
}
