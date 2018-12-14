package jwtutils

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

/*
   Utility routines that hide some of the complexities from  main code

   The claims may be either standard or private claims

   The payload may contain both standard claims and private claims, the
   standard claims comes from
   The standard claims come from https://tools.ietf.org/html/rfc7519 and covers
   iss issuer
   sub subject
   aud Audience
   exp expiration Date
   nbf not before
   iat issued at
   jti JWT ID claims


   The private claims may be anything, they are passed in as a map
*/

// StandardClaims contains the JWT standard claims
type StandardClaims struct {
	Issuer    string
	Subject   string
	Audience  []string
	Expiry    time.Time
	NotBefore time.Time
	IssuedAt  time.Time
	ID        string
}

// NewRSAJWTFull returns a string version of the JWT
func NewRSAJWTFull(key *rsa.PrivateKey, sc *StandardClaims, pc *map[string]interface{}, ph *map[string]interface{}) (string, error) {
	return newRSAJWT(key, sc, false, pc, ph)
}

// NewRSAJWTCompact returns a string version of the JWT
func NewRSAJWTCompact(key *rsa.PrivateKey, sc *StandardClaims, pc *map[string]interface{}, ph *map[string]interface{}) (string, error) {
	return newRSAJWT(key, sc, true, pc, ph)
}

func newRSAJWT(key *rsa.PrivateKey, sc *StandardClaims, compact bool, pc *map[string]interface{}, ph *map[string]interface{}) (string, error) {

	claims := jwt.Claims{
		Issuer:   sc.Issuer,
		Subject:  sc.Subject,
		ID:       sc.ID,
		Audience: sc.Audience,
		IssuedAt: jwt.NewNumericDate(time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC)),
	}

	rsaSigner := makeSigner(jose.RS256, key)

	// FIXME add code for custom headers
	builder := jwt.Signed(rsaSigner).Claims(claims)

	if pc != nil {
		builder = builder.Claims(pc)
	}

	if !compact {
		outJWT, err := builder.FullSerialize()
		if err != nil {
			return "", err
		}
		return outJWT, nil
	} else { // compact case
		outJWT, err := builder.CompactSerialize()
		if err != nil {
			return "", err
		}
		return outJWT, nil
	}
}

// ExtractPrivateKeyFromX509PEM extract the rsa.PrivateKey from the passed in pem
func ExtractPrivateKeyFromX509PEM(keyPEM []byte) (*rsa.PrivateKey, error) {

	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the private key:%v", keyPEM)
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return rsa, nil
	default:
		return nil, fmt.Errorf("private key: unsupported key type %q", block.Type)
	}

}

func makeSigner(alg jose.SignatureAlgorithm, k interface{}) jose.Signer {

	var opts = jose.SignerOptions{}
	opts.WithHeader("custom_header", "value_1")

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: k}, (&opts).WithType("JWT"))
	if err != nil {
		panic("failed to create signer:" + err.Error())
	}

	log.Printf("---------Signer:%+v", sig)

	return sig
}
