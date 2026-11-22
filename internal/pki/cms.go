package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
)

// Detached CMS (PKCS #7) signatures, the format iPXE's imgverify checks:
// SignedData over sha256 with RSA, no signed attributes, the signer's
// certificate included, content detached. It is what
//
//	openssl cms -sign -binary -noattr -outform DER -signer codesign.pem -inkey codesign.key
//
// produces. The signature is deterministic (PKCS #1 v1.5, no signing
// time), so re-signing the same bytes gives the same file.

var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue // [0] EXPLICIT SignedData, built by hand: asn1 writes FullBytes verbatim
}

type cmsEncapContent struct {
	EContentType asn1.ObjectIdentifier
}

type cmsIssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type cmsSignerInfo struct {
	Version            int
	SID                cmsIssuerAndSerial
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type cmsSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo cmsEncapContent
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	SignerInfos      []cmsSignerInfo `asn1:"set"`
}

// CodeSigner signs boot files and scripts for iPXE.
type CodeSigner struct {
	Cert  *x509.Certificate
	Key   crypto.Signer // RSA
	Chain []*x509.Certificate
}

// SignDetached returns a DER CMS signature over everything read from r.
func (s *CodeSigner) SignDetached(r io.Reader) ([]byte, error) {
	if _, ok := s.Key.Public().(*rsa.PublicKey); !ok {
		return nil, errors.New("iPXE verifies RSA signatures only")
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return nil, err
	}
	sig, err := s.Key.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
	if err != nil {
		return nil, err
	}
	var certs []byte
	for _, c := range append([]*x509.Certificate{s.Cert}, s.Chain...) {
		certs = append(certs, c.Raw...)
	}
	sha := pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	sd := cmsSignedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{sha},
		EncapContentInfo: cmsEncapContent{EContentType: oidData},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certs},
		SignerInfos: []cmsSignerInfo{{
			Version:            1,
			SID:                cmsIssuerAndSerial{Issuer: asn1.RawValue{FullBytes: s.Cert.RawIssuer}, Serial: s.Cert.SerialNumber},
			DigestAlgorithm:    sha,
			SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue},
			Signature:          sig,
		}},
	}
	inner, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(cmsContentInfo{ContentType: oidSignedData,
		Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
}

// VerifyDetached checks a signature made by SignDetached: that it covers
// content, and that its signer chains to roots with the code-signing
// usage. iPXE does the same check on the node; this one is for tests and
// for flapjack to check what it serves.
func VerifyDetached(sig, content []byte, roots *x509.CertPool) error {
	var ci cmsContentInfo
	if rest, err := asn1.Unmarshal(sig, &ci); err != nil || len(rest) > 0 || !ci.ContentType.Equal(oidSignedData) ||
		ci.Content.Class != asn1.ClassContextSpecific || ci.Content.Tag != 0 {
		return errors.New("not a CMS SignedData")
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return err
	}
	if len(sd.SignerInfos) != 1 {
		return errors.New("want exactly one signer")
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil || len(certs) == 0 {
		return errors.New("no signer certificate")
	}
	si := sd.SignerInfos[0]
	var signer *x509.Certificate
	inter := x509.NewCertPool()
	for _, c := range certs {
		if c.SerialNumber.Cmp(si.SID.Serial) == 0 && string(c.RawIssuer) == string(si.SID.Issuer.FullBytes) {
			signer = c
		} else {
			inter.AddCert(c)
		}
	}
	if signer == nil {
		return errors.New("signer certificate missing")
	}
	if _, err := signer.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}); err != nil {
		return err
	}
	pub, ok := signer.PublicKey.(*rsa.PublicKey)
	if !ok || !si.DigestAlgorithm.Algorithm.Equal(oidSHA256) {
		return errors.New("want sha256 with RSA")
	}
	d := sha256.Sum256(content)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], si.Signature)
}
