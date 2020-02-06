package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	// made some module names explicit here for clarity
	//
	// "This module lets you authenticate HTTP requests using JWT tokens
	// in your Go Programming Language applications. JWTs are typically
	// used to protect API endpoints, and are often issued using OpenID Connect."
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/codegangsta/negroni"

	// "This library supports the parsing and verification as well as the generation
	// and signing of JWTs. Current supported signing algorithms are HMAC SHA, RSA,
	// RSA-PSS, and ECDSA, though hooks are present for adding your own."
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
)

type Response struct {
	Message string `json:"message"`
}

// Jwks is a JSON Web Key Set
// https://auth0.com/docs/tokens/concepts/jwks
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Print("Error loading .env file")
	}

	// a middleware used for validating JWT tokens using a public key
	// generated from a JWK provided by auth0
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		// "The function that will return the Key to validate the JWT.
		// It can be either a shared secret or a public key.
		// Default value: nil"
		// https://github.com/auth0/go-jwt-middleware
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// get audience from .env config
			aud := os.Getenv("AUTH0_AUDIENCE")

			// use jwt module to verify that this is the correct audience
			checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
			if !checkAud {
				return token, errors.New("Invalid audience.")
			}

			// get domain from .env config, add protocol and form int URL
			iss := "https://" + os.Getenv("AUTH0_DOMAIN") + "/"

			// use jqt module to verify that this is the correct issuer
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
			if !checkIss {
				return token, errors.New("Invalid issuer.")
			}

			// create a pem certificate from the JWK matching
			// this token
			cert, err := getPemCert(token)
			if err != nil {
				panic(err.Error())
			}

			// https://godoc.org/github.com/dgrijalva/jwt-go#ParseRSAPublicKeyFromPEM
			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		},
		// "When set, the middleware verifies that tokens are signed with the specific signing algorithm
		// If the signing method is not constant the ValidationKeyGetter callback can be used to implement additional checks
		// Important to avoid security issues described here: https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/"
		// https://github.com/auth0/go-jwt-middleware
		SigningMethod: jwt.SigningMethodRS256,
	})

	// set up CORS and allow the Authorization header
	// https://www.moesif.com/blog/technical/cors/Authoritative-Guide-to-CORS-Cross-Origin-Resource-Sharing-for-REST-APIs/#example-flow
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization"},
	})

	r := mux.NewRouter()

	// This route is always accessible
	r.Handle("/api/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		message := "Hello from a public endpoint! You don't need to be authenticated to see this."
		responseJSON(message, w, http.StatusOK)
	}))

	// This route is only accessible if the user has a valid access_token
	// We are chaining the jwtmiddleware middleware into the negroni handler function which will check
	// for a valid token.
	r.Handle("/api/private", negroni.New(
		negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			message := "Hello from a private endpoint! You need to be authenticated to see this."
			responseJSON(message, w, http.StatusOK)
		}))))

	// This route is only accessible if the user has a valid access_token with the read:messages scope
	// We are chaining the jwtmiddleware middleware into the negroni handler function which will check
	// for a valid token and scope.
	r.Handle("/api/private-scoped", negroni.New(
		negroni.HandlerFunc(jwtMiddleware.HandlerWithNext),
		negroni.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeaderParts := strings.Split(r.Header.Get("Authorization"), " ")
			token := authHeaderParts[1]

			hasScope := checkScope("read:messages", token)

			if !hasScope {
				message := "Insufficient scope."
				responseJSON(message, w, http.StatusForbidden)
				return
			}
			message := "Hello from a private endpoint! You need to be authenticated to see this."
			responseJSON(message, w, http.StatusOK)
		}))))

	handler := c.Handler(r)
	http.Handle("/", r)
	fmt.Println("Listening on http://localhost:3010")
	http.ListenAndServe("0.0.0.0:3010", handler)
}

type CustomClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
	// https://godoc.org/github.com/dgrijalva/jwt-go#StandardClaims
	// Audience  string `json:"aud,omitempty"`
	// ExpiresAt int64  `json:"exp,omitempty"`
	// Id        string `json:"jti,omitempty"`
	// IssuedAt  int64  `json:"iat,omitempty"`
	// Issuer    string `json:"iss,omitempty"`
	// NotBefore int64  `json:"nbf,omitempty"`
	// Subject   string `json:"sub,omitempty"`
}

func checkScope(scope string, tokenString string) bool {
	token, _ := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		cert, err := getPemCert(token)
		if err != nil {
			return nil, err
		}
		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		return result, nil
	})

	claims, ok := token.Claims.(*CustomClaims)

	hasScope := false
	if ok && token.Valid {
		result := strings.Split(claims.Scope, " ")
		for i := range result {
			if result[i] == scope {
				hasScope = true
			}
		}
	}

	return hasScope
}

// getPemCert will retrieve the JSON web keys from the auth server
// and use it to create a pem certificate
// https://geeklah.com/working_with_pem_files.html
func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	// get the JSON Web Keys file from auth0
	resp, err := http.Get("https://" + os.Getenv("AUTH0_DOMAIN") + "/.well-known/jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	// unmarshall jwks into Jwks struct
	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	// iterate through keys until a matching key is found
	for k, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			// create a pem certificate from the matching key from the x5c JWK property
			// "The x.509 certificate chain. The first entry in the array is the certificate
			// to use for token verification; the other certificates can be used to verify
			// this first certificate."
			// https://auth0.com/docs/tokens/references/jwks-properties
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("Unable to find appropriate key.")
		return cert, err
	}

	return cert, nil
}

func responseJSON(message string, w http.ResponseWriter, statusCode int) {
	response := Response{message}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(jsonResponse)
}
