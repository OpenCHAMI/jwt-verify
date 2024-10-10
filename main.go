package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"
)

// Function to create an HTTP client with an optional custom root certificate from an environment variable
func createHTTPClientWithCustomCert() (*http.Client, error) {
	// Start with the system's certificate pool
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system cert pool: %v", err)
	}

	// Check for the environment variable containing the custom root certificate path
	certFile := os.Getenv("CUSTOM_ROOT_CERT")
	if certFile != "" {
		// Read the custom root certificate
		rootCert, err := os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read root certificate file: %v", err)
		}

		// Append the custom root certificate to the certificate pool
		if ok := certPool.AppendCertsFromPEM(rootCert); !ok {
			return nil, fmt.Errorf("failed to append custom root certificate")
		}
	}

	// Create a custom TLS configuration using the updated certificate pool
	tlsConfig := &tls.Config{
		RootCAs: certPool,
	}

	// Create an HTTP transport that uses this TLS configuration
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Return an HTTP client using this custom transport
	return &http.Client{
		Transport: transport,
	}, nil
}

// Function to parse and validate JWT
func parseAndValidateJWT(tokenStr string, jwksURL string) (*jwt.Token, jwt.MapClaims, error) {
	var token *jwt.Token
	var err error

	if jwksURL != "" {
		// Create an HTTP client with a custom root certificate if provided
		// Create the HTTP client, potentially including a custom root certificate
		client, err := createHTTPClientWithCustomCert()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create HTTP client: %v", err)
		}
		// Load the JWKS from the provided URL using net/http and encoding/json
		resp, err := client.Get(jwksURL)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get JWKS: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("failed to get JWKS: received status code %d", resp.StatusCode)
		}

		// Read the response body into a byte slice
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read JWKS response body: %v", err)
		}

		// Create the keyfunc from the JWKS
		jwksKeyfunc, err := keyfunc.NewJWKSetJSON(json.RawMessage(body))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create keyfunc: %v", err)
		}
		// Parse and validate the JWT using the JWKS key function
		token, err = jwt.Parse(tokenStr, jwt.Keyfunc(jwksKeyfunc.Keyfunc))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse JWT with validation: %v", err)
		}
	} else {
		// Parse the JWT without validating the signature using ParseUnverified
		// Create a Parser object with the default parser configuration
		defaultParser := jwt.Parser{}
		// Parse the token without validating the signature
		token, _, err = defaultParser.ParseUnverified(tokenStr, jwt.MapClaims{})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse JWT without validation: %v", err)
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("invalid token claims")
	}

	return token, claims, nil
}

// Helper function to print time information
func printTimeInfo(title string, timestamp interface{}) {
	validColor := color.New(color.FgGreen)
	expiredColor := color.New(color.FgRed)
	pendingColor := color.New(color.FgYellow)
	now := time.Now()

	if float64Time, ok := timestamp.(float64); ok {
		tm := time.Unix(int64(float64Time), 0)
		durationSince := now.Sub(tm)
		durationUntil := tm.Sub(now)

		if tm.Before(now) {
			if title == "Expiration" && durationSince > 0 {
				// Expired token
				expiredColor.Printf("❌ %s: %v (expired %v ago)\n", title, tm, durationSince)
			} else {
				// Valid date in the past
				validColor.Printf("✅ %s: %v (since: %v)\n", title, tm, durationSince)
			}
		} else {
			// Future date, not yet valid
			pendingColor.Printf("⏳ %s: %v (in %v)\n", title, tm, durationUntil)
		}
	} else {
		expiredColor.Printf("❌ %s: invalid date\n", title)
	}
}

func main() {
	var jwksURL string

	var rootCmd = &cobra.Command{
		Use:   "jwt-examine",
		Short: "Decode and validate a JWT",
		Run: func(cmd *cobra.Command, args []string) {
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("Paste your JWT, then press Enter:")
			tokenStr, _ := reader.ReadString('\n')

			tokenStr = tokenStr[:len(tokenStr)-1] // Remove newline character

			token, claims, err := parseAndValidateJWT(tokenStr, jwksURL)
			if err != nil {
				color.Red("Error: %v", err)
				return
			}

			// Print the decoded JWT claims
			prettyClaims, _ := json.MarshalIndent(claims, "", "  ")
			color.Cyan("🔓 Decoded JWT Claims:\n%s", string(prettyClaims))

			// Print important time-related claims
			if exp, ok := claims["exp"]; ok {
				printTimeInfo("Expiration", exp)
			}
			if iat, ok := claims["iat"]; ok {
				printTimeInfo("Issued At", iat)
			}
			if nbf, ok := claims["nbf"]; ok {
				printTimeInfo("Not Before", nbf)
			}

			// Print validation result if JWKS URL is provided
			if jwksURL != "" {
				if token.Valid {
					color.Green("✅ JWT signature is valid!")
				} else {
					color.Red("❌ JWT signature is invalid!")
				}
			}
		},
	}

	rootCmd.Flags().StringVarP(&jwksURL, "jwks-url", "j", "", "URL of the JWKS for signature validation")
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
