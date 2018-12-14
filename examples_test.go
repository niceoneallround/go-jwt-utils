package jwtutils

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

//
// Examples of using the the square go-jose package
// gopkg.in/square/go-jose.v2
// gopkg.in/square/go-jose.v2/jwt

const privateClaim1 = "privateClaim1"
const privateClaim2 = "privateClaim2"
const embedStructClaim = "embedStructClaim"

var rsaPrivateKey = generateRSAKey()

// TestRSASignedJWTStdClaimsAndPrivateClaimsUsingMap this is supports the medium post
func TestRSASignedJWTStdClaimsAndPrivateClaimsUsingMap(t *testing.T) {

	assert := assert.New(t)

	//
	// Setup the key
	//
	key := jose.SigningKey{Algorithm: jose.RS256, Key: rsaPrivateKey}

	//
	// Create the RSA Signer needed for the JWT
	//
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")
	signerOpts.WithHeader("kid", "kid_1")

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		log.Fatalf("failed to create signer:%+v", err)
	}

	// create the builder
	builder := jwt.Signed(rsaSigner)

	//
	// create the standard JWT claims, using the packages Claims type
	//
	stdClaims := jwt.Claims{
		Issuer:   "issuer1",
		Subject:  "subject1",
		ID:       "id1",
		Audience: jwt.Audience{"aud1", "aud2"},
		IssuedAt: jwt.NewNumericDate(time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)),
		Expiry:   jwt.NewNumericDate(time.Date(2017, 1, 1, 0, 15, 0, 0, time.UTC)),
	}

	// add standard claims
	builder = builder.Claims(stdClaims)

	//
	// example of using a map of the private claims that should be added to the JWT,
	// one is a string, and one is an array of strings
	//
	pClaims1 := map[string]interface{}{
		privateClaim1: "val1",
		privateClaim2: []string{"val2", "val3"},
		"anyJSONObjectClaim": map[string]interface{}{
			"name": "john",
			"phones": map[string]string{
				"phone1": "123",
				"phone2": "456",
			},
		},
	}

	// add the private claims
	builder = builder.Claims(pClaims1)

	//
	// Create the full serialized and signed JWT, not compacted. outJWT is a
	// string. Note could also have used CompactSerialize() and tests would
	// have worked as is
	//
	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		log.Fatalf("failed to create JWT:%+v", err)
	}

	//fmt.Println(rawJWT)

	//-----------------------
	// Lets reverse, and now parse the JWT to check signature and read claims
	//-----------------

	//
	// Parse the raw JWT, this returns a *JSONWebSignature that can be used
	// to check the signature and access the claims.
	//
	parsedJWT, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		log.Fatalf("failed to parse JWT:%+v", err)
	}

	fmt.Printf("parseSigned result:%+v\n", *parsedJWT)
	fmt.Println(reflect.TypeOf(parsedJWT))

	//
	// Make sure keyID headers is there
	//
	hdrs := parsedJWT.Headers // []jose.Header
	//fmt.Println(reflect.TypeOf(hdrs))
	assert.Equal(1, len(hdrs), "parsedJWT.headers should be length 1")
	assert.Equal("kid_1", hdrs[0].KeyID)

	//------
	// Verify the signature by passing in the RSA public key. Note the claims
	// call can take a set of destinations for the claims in the payload.
	// ------

	outCl := jwt.Claims{}
	err1 := parsedJWT.Claims(&rsaPrivateKey.PublicKey, &outCl)
	if err1 != nil {
		log.Fatalf("failed to verify signature and extract clains from parsed JWT:%+v", err)
	}

	fmt.Printf("Extracted JUST standard claims:%+v\n", outCl)

	//
	// Copy the standard claims in a Claims type that is easier to use
	// and Copy all the claims into a map
	//
	cl := jwt.Claims{}
	allClaims1 := make(map[string]interface{})
	if err = parsedJWT.Claims(&rsaPrivateKey.PublicKey, &cl, &allClaims1); err != nil {
		t.Errorf("failed to verify signature and extract clains from parsed JWT:%+v", err)
	}

	fmt.Printf("Extracted standard claims:%+v and all claims:%+v\n", cl, allClaims1)

	//
	// check standard claims
	//
	assert.Equal(stdClaims.Issuer, cl.Issuer, "The issuers should be equal")
	assert.Equal(stdClaims.Subject, cl.Subject, "The subjects should be equal")
	assert.Equal(stdClaims.Audience, cl.Audience, "The audience should be equal")
	assert.Equal(stdClaims.IssuedAt, cl.IssuedAt, "The issued date should be equal")

	//
	// Check private claims
	//
	assert.Equal(pClaims1[privateClaim1].(string), allClaims1[privateClaim1].(string), "private claim1 should be equal")

	//
	// Copy all claims into a map
	//
	allClaims2 := make(map[string]interface{})
	err = parsedJWT.Claims(&rsaPrivateKey.PublicKey, &allClaims2)
	if err != nil {
		log.Fatalf("2-failed to verify signature and extract clains from parsed JWT:%+v", err)
	}

	fmt.Printf("Extracted all claims into: %+v\n", allClaims2)

	// note how with map ones has to typecast the issuer to string, and know that
	// the key iss, when use claim structure obviously done for you, but at cost of
	// double parse.
	assert.Equal(
		stdClaims.Issuer,
		allClaims2["iss"].(string), "issuer claims should be equal in map case")

	assert.Equal(
		pClaims1[privateClaim1].(string),
		allClaims2[privateClaim1].(string), "private claim1 should be equal in map case")

	return
}

//------
//-------
// TestRSASignedJWTStdClaimsAndPrivateClaimsUsingMap this is supports the medium post
func TestRSASignedJWTStdClaimsAndPrivateClaimsUsingStruct(t *testing.T) {

	assert := assert.New(t)

	//
	// Setup the key
	//
	key := jose.SigningKey{Algorithm: jose.RS256, Key: rsaPrivateKey}

	//
	// Create the RSA Signer needed for the JWT
	//
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		log.Fatalf("failed to create signer:%+v", err)
	}

	// create the builder
	builder := jwt.Signed(rsaSigner)

	//
	// Create the structure that contains the standard and private claims
	//
	type CustomClaims struct {
		*jwt.Claims
		PrivateClaim1      string                 `json:"privateClaim1,omitempty"`
		PrivateClaim2      []string               `json:"privateClaim2,omitEmpty"`
		AnyJSONObjectClaim map[string]interface{} `json:"anyJSONObjectClaim"`
	}

	customClaims := CustomClaims{
		Claims: &jwt.Claims{
			Issuer:   "issuer1",
			Subject:  "subject1",
			ID:       "id1",
			Audience: jwt.Audience{"aud1", "aud2"},
			IssuedAt: jwt.NewNumericDate(time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)),
			Expiry:   jwt.NewNumericDate(time.Date(2017, 1, 1, 0, 8, 0, 0, time.UTC)),
		},
		PrivateClaim1: "val1",
		PrivateClaim2: []string{"val2", "val3"},
		AnyJSONObjectClaim: map[string]interface{}{
			"name": "john",
			"phones": map[string]string{
				"phone1": "123",
				"phone2": "456",
			},
		},
	}
	//fmt.Printf("input claims %+v\n", customClaims)

	// add claims
	builder = builder.Claims(customClaims)

	//
	// Create the full serialized and signed JWT, not compacted. outJWT is a
	// string. Note could also have used CompactSerialize() and tests would
	// have worked as is
	//
	rawJWT, err := builder.CompactSerialize()
	if err != nil {
		log.Fatalf("failed to create JWT:%+v", err)
	}

	//fmt.Println(rawJWT)

	//-----------------------
	// Lets reverse, and now parse the JWT to check signature and read claims
	//-----------------

	//
	// Parse the raw JWT, this returns a *JSONWebSignature that can be used
	// to check the signature and access the claims.
	//
	parsedJWT, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		log.Fatalf("failed to parse JWT:%+v", err)
	}

	fmt.Printf("%+v\n", parsedJWT)
	fmt.Println(reflect.TypeOf(parsedJWT))

	//------
	// Verify the signature by passing in the RSA public key. Note the claims
	// call can take a set of destinations for the claims in the payload.
	// ------

	resultCl := CustomClaims{}
	err1 := parsedJWT.Claims(&rsaPrivateKey.PublicKey, &resultCl)
	if err1 != nil {
		log.Fatalf("failed to verify signature and extract clains from parsed JWT:%+v", err)
	}

	fmt.Printf("Custom:%+v\n", resultCl)
	fmt.Printf("Custom.Claims:%+v\n", *resultCl.Claims)

	//
	// check claims
	//
	assert.Equal(customClaims.Claims.Issuer, resultCl.Claims.Issuer, "The issuers should be equal")
	assert.Equal(customClaims.PrivateClaim1, resultCl.PrivateClaim1, "private claims not equal")

	// use claims verify
	err = customClaims.Claims.Validate(jwt.Expected{
		Issuer: "issuer1",
		Time:   time.Date(2016, 1, 1, 0, 10, 0, 0, time.UTC),
	})
	if err != nil {
		t.Errorf("Validate failed:%+v", err)
	}

	allClaims2 := make(map[string]interface{})
	parsedJWT.Claims(&rsaPrivateKey.PublicKey, &allClaims2)
	if err != nil {
		log.Fatalf("Failed :%+v", err)
	}

	fmt.Printf("Printed map: %+v\n", allClaims2)

}

//--------
//----------
func TestExample1RSASignedJWT(t *testing.T) {

	assert := assert.New(t)

	//
	// Setup the key
	//
	key := jose.SigningKey{Algorithm: jose.RS256, Key: rsaPrivateKey}

	//
	// Create the RSA Signer needed for the JWT
	//
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		t.Errorf("failed to create signer:%+v", err)
	}

	//
	// create the standard JWT claims, using the packages Claims type
	//
	stdClaims := jwt.Claims{
		Issuer:   "issuer1",
		Subject:  "subject1",
		ID:       "id1",
		Audience: jwt.Audience{"aud1", "aud2"},
		IssuedAt: jwt.NewNumericDate(time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)),
		Expiry:   jwt.NewNumericDate(time.Date(2017, 1, 1, 0, 15, 0, 0, time.UTC)),
	}

	//
	// example of using a map of the private claims that should be added to the JWT,
	// one is a string, and one is an array of strings
	//
	pClaims1 := map[string]interface{}{
		privateClaim1: "val1",
		privateClaim2: []string{"val2", "val3"},
	}

	//
	// example of unmarshaling a struct for private claims that want to add to the JWT.
	//
	type privateClaimsStruct struct {
		StructPrivateClaim string `json:"spclaim"`
	}

	pClaims2 := privateClaimsStruct{StructPrivateClaim: "custom claim value"}

	//
	// Embed the struct
	//
	pClaims3 := map[string]interface{}{
		embedStructClaim: privateClaimsStruct{StructPrivateClaim: "embedded custom claim"},
	}

	//
	// create a JWT builder using the rsaSigner, and add the standard claims,
	// note how claims returns the builder so can chain together
	//
	builder := jwt.Signed(rsaSigner).
		Claims(stdClaims).
		Claims(pClaims1).
		Claims(pClaims2).
		Claims(pClaims3)

	//
	// Create the full serialized and signed JWT, not compacted. outJWT is a
	// string. Note could also have used CompactSerialize() and tests would
	// have worked as is
	//
	rawJWT, err := builder.FullSerialize()
	if err != nil {
		t.Errorf("failed to create JWT:%+v", err)
	}

	//fmt.Println(rawJWT)

	//-----------------------
	// Lets reverse, and now parse the JWT to check signature and read claims
	//-----------------

	//
	// Parse the raw JWT, this returns a ptr to JSONWebToken type
	//
	parsedJWT, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		t.Errorf("failed to parse JWT:%+v", err)
	}

	//------
	// Verify the signature by passing in the RSA public key. Note the claims
	// call can take a set of destinations for the claims in the payload.
	// ------

	//
	// Copy the standard claims in a Claims type that is easier to use
	// and Copy all the claims into a map
	//
	cl := jwt.Claims{}
	allClaims1 := make(map[string]interface{})
	if err := parsedJWT.Claims(&rsaPrivateKey.PublicKey, &cl, &allClaims1); err != nil {
		t.Errorf("failed to verify signature and extract clains from parsed JWT:%+v", err)
	}

	fmt.Printf("Extracted standard claims:%+v and all claims:%+v\n", cl, allClaims1)

	//
	// check standard claims
	//
	assert.Equal(stdClaims.Issuer, cl.Issuer, "The issuers should be equal")
	assert.Equal(stdClaims.Subject, cl.Subject, "The subjects should be equal")
	assert.Equal(stdClaims.Audience, cl.Audience, "The audience should be equal")
	assert.Equal(stdClaims.IssuedAt, cl.IssuedAt, "The issued date should be equal")

	//
	// Check private claims
	//
	assert.Equal(pClaims1[privateClaim1].(string), allClaims1[privateClaim1].(string), "private claim1 should be equal")
	assert.Equal(pClaims2.StructPrivateClaim, allClaims1["spclaim"].(string), "private claim1 should be equal")

	// Ad privateclaims2 is a []string but as in map[string]interface{} need to
	// typecast to get to the value
	assert.Equal(
		pClaims1[privateClaim2].([]string)[0],
		allClaims1[privateClaim2].([]interface{})[0], "private claim1 should be equal")

	//
	// Copy all claims into a map
	//
	allClaims2 := make(map[string]interface{})
	if err := parsedJWT.Claims(&rsaPrivateKey.PublicKey, &allClaims2); err != nil {
		t.Errorf("2-failed to verify signature and extract clains from parsed JWT:%+v", err)
	}

	//fmt.Printf("Extracted all claims into a map:%+v\n", allClaims2)

	// note how with map ones has to typecast the issuer to string, and know that
	// the key iss, when use claim structure obviously done for you, but at cost of
	// double parse.
	assert.Equal(stdClaims.Issuer, allClaims2["iss"].(string), "issuer claims should be equal in map case")
	assert.Equal(pClaims1[privateClaim1].(string), allClaims2[privateClaim1].(string), "private claim1 should be equal in map case")

	//
	// Create a custom struct that has the standard and private claims
	//
	type AllClaimsStruct struct {
		*jwt.Claims
		PrivateClaim1 string   `json:"privateClaim1,omitempty"`
		PrivateClaim2 []string `json:"privateClaim2,omitEmpty"`

		// as struct was not embedded but flattened out, need to reference like this
		StructPrivateClaim string `json:"spclaim,omitEmpty"`

		// embeded struct
		EmbedStructClaim privateClaimsStruct `json:"embedStructClaim,omitEmpty"`
	}

	custom := AllClaimsStruct{}

	if err := parsedJWT.Claims(&rsaPrivateKey.PublicKey, &custom); err != nil {
		t.Errorf("failed to verify signature and extract clains from parsed JWT:%+v", err)
	}

	//fmt.Printf("Extracted all claims into custom:%+v\n", custom)
	//fmt.Printf("Extracted all claims into custom:%+v\n", *custom.Claims)

	assert.Equal(stdClaims.Issuer, custom.Claims.Issuer, "custom: The issuers should be equal")
	assert.Equal(pClaims1[privateClaim1].(string), custom.PrivateClaim1, "custom: private claim1 should be equal")
	assert.Equal(pClaims2.StructPrivateClaim, custom.StructPrivateClaim, "custom embedded flattened claim should be equal")
	assert.Equal("embedded custom claim", custom.EmbedStructClaim.StructPrivateClaim, "custom embedded claim should be equal")

	return
}

func TestExample2RSASignedJWTCustomHeaderFields(t *testing.T) {

	assert := assert.New(t)

	//
	// Setup the key
	//
	key := jose.SigningKey{Algorithm: jose.RS256, Key: rsaPrivateKey}

	//
	// Create the RSA Signer needed for the JWT
	//
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")

	// add the custom header fields
	signerOpts.WithHeader("custom_header1", "hdr1_val")
	signerOpts.WithHeader("custom_header2", "hdr2_val")

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		t.Errorf("failed to create signer:%+v", err)
	}

	//
	// create the standard JWT claims, using the packages Claims type
	//
	stdClaims := jwt.Claims{
		Issuer: "issuer2",
	}

	//
	// Create the compact serialized and signed JWT
	//
	rawJWT, err := jwt.Signed(rsaSigner).Claims(stdClaims).CompactSerialize()
	if err != nil {
		t.Errorf("failed to create JWT:%+v", err)
	}

	//fmt.Println(rawJWT)

	//-----------------------
	// Lets reverse, and now parse the JWT to check signature and read claims
	//-----------------

	//
	// Parse the raw JWT, this returns a ptr to JSONWebToken type
	//
	parsedJWT, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		t.Errorf("failed to parse JWT:%+v", err)
	}

	//fmt.Println(parsedJWT)

	//
	// Check the Header
	// []jose.Header
	hdrs := parsedJWT.Headers
	fmt.Printf("headers:%+v", hdrs)
	assert.Equal(1, len(hdrs), "Expected one header")
	assert.Equal("hdr1_val", hdrs[0].ExtraHeaders["custom_header1"], "Custom header1 field is incorrect")
	assert.Equal("hdr2_val", hdrs[0].ExtraHeaders["custom_header2"], "Custom header2 field is incorrect")

	return
}

func TestRSASignedJWTFullSerialization(t *testing.T) {

	assert := assert.New(t)

	//
	// Setup the key
	//
	key := jose.SigningKey{Algorithm: jose.RS256, Key: rsaPrivateKey}

	//
	// Create the RSA Signer needed for the JWT
	//
	var signerOpts = jose.SignerOptions{}
	signerOpts.WithType("JWT")

	rsaSigner, err := jose.NewSigner(key, &signerOpts)
	if err != nil {
		log.Fatalf("failed to create signer:%+v", err)
	}

	// create the builder
	builder := jwt.Signed(rsaSigner)

	//
	// create the standard JWT claims, using the packages Claims type
	//
	stdClaims := jwt.Claims{
		Issuer:   "issuer1",
		Subject:  "subject1",
		ID:       "id1",
		Audience: jwt.Audience{"aud1", "aud2"},
		IssuedAt: jwt.NewNumericDate(time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)),
		Expiry:   jwt.NewNumericDate(time.Date(2017, 1, 1, 0, 15, 0, 0, time.UTC)),
	}

	// add standard claims
	builder = builder.Claims(stdClaims)

	//
	// Create the full serialized and signed JWT, not compacted. outJWT is a
	// string. Note could also have used CompactSerialize() and tests would
	// have worked as is
	//
	rawJWT, err := builder.FullSerialize()
	if err != nil {
		log.Fatalf("failed to create JWT:%+v", err)
	}

	fmt.Println(rawJWT)

	//-----------------------
	// Lets reverse, and now parse the JWT to check signature and read claims
	//-----------------

	//
	// Parse the raw JWT, this returns a *JSONWebSignature that can be used
	// to check the signature and access the claims.
	//
	parsedJWT, err := jwt.ParseSigned(rawJWT)
	if err != nil {
		log.Fatalf("failed to parse JWT:%+v", err)
	}

	fmt.Printf("%+v\n", parsedJWT)
	fmt.Println(reflect.TypeOf(parsedJWT))

	//------
	// Verify the signature by passing in the RSA public key. Note the claims
	// call can take a set of destinations for the claims in the payload.
	// ------

	outCl := jwt.Claims{}
	err1 := parsedJWT.Claims(&rsaPrivateKey.PublicKey, &outCl)
	if err1 != nil {
		log.Fatalf("failed to verify signature and extract clains from parsed JWT:%+v", err)
	}

	fmt.Printf("Extracted JUST standard claims:%+v\n", outCl)

	//
	// Copy the standard claims in a Claims type that is easier to use
	// and Copy all the claims into a map
	//
	cl := jwt.Claims{}
	allClaims1 := make(map[string]interface{})
	if err = parsedJWT.Claims(&rsaPrivateKey.PublicKey, &cl, &allClaims1); err != nil {
		t.Errorf("failed to verify signature and extract clains from parsed JWT:%+v", err)
	}

	fmt.Printf("Extracted standard claims:%+v and all claims:%+v\n", cl, allClaims1)

	//
	// check standard claims
	//
	assert.Equal(stdClaims.Issuer, cl.Issuer, "The issuers should be equal")
	assert.Equal(stdClaims.Subject, cl.Subject, "The subjects should be equal")
	assert.Equal(stdClaims.Audience, cl.Audience, "The audience should be equal")
	assert.Equal(stdClaims.IssuedAt, cl.IssuedAt, "The issued date should be equal")

	return
}

//--------------------
// Utils
//--------------------

// generate a RSA key pair that can be used for signing
func generateRSAKey() *rsa.PrivateKey {

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generating random key: %v", err)
	}

	return privKey
}
