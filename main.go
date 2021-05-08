package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
	"golang.org/x/crypto/pkcs12"
)

type AzureKeyVaultCertificate struct {
	Ctx           context.Context
	VaultName     string
	Client        keyvault.BaseClient
	authenticated bool
	vaultBaseURL  string
}

func (akv *AzureKeyVaultCertificate) GetKeyVaultClient() (err error) {
	akv.Client = keyvault.New()
	authorizer, err := auth.NewAuthorizerFromEnvironment()
	if err != nil {
		return err
	}

	akv.Client.Authorizer = authorizer
	akv.authenticated = true

	akv.vaultBaseURL = fmt.Sprintf("https://%s.%s", akv.VaultName, azure.PublicCloud.KeyVaultDNSSuffix)

	return nil
}

func (akv *AzureKeyVaultCertificate) requestCertificateVersion(certificateName string) (version string, err error) {
	fmt.Println(akv.vaultBaseURL)
	list, err := akv.Client.GetCertificateVersionsComplete(akv.Ctx, akv.vaultBaseURL, certificateName, nil)
	if err != nil {
		return "", err
	}

	var lastItemDate time.Time
	var lastItemVersion string
	for list.NotDone() {
		item := list.Value()
		if *item.Attributes.Enabled {
			updateTime := time.Time(*item.Attributes.Updated)
			if lastItemDate.IsZero() || updateTime.After(lastItemDate) {
				lastItemDate = updateTime

				parts := strings.Split(*item.ID, "/")
				lastItemVersion = parts[len(parts)-1]
			}
		}

		list.Next()
	}

	return lastItemVersion, nil
}

func (akv *AzureKeyVaultCertificate) requestCertificatePFX(certificateName string, certificateVersion string) (key interface{}, cert *x509.Certificate, err error) {
	pfx, err := akv.Client.GetSecret(akv.Ctx, akv.vaultBaseURL, certificateName, certificateVersion)
	if err != nil {
		return nil, nil, err
	}

	pfxBytes, err := base64.StdEncoding.DecodeString(*pfx.Value)
	if err != nil {
		return nil, nil, err
	}
	return pkcs12.Decode(pfxBytes, "")
}

func (akv *AzureKeyVaultCertificate) GetCertificate(certificateName string) (err error) {
	if !akv.authenticated {
		return errors.New("Need to invoke GetKeyVaultClient() first")
	}

	fmt.Printf("Getting certificate version for %s\n", certificateName)
	certificateVersion, err := akv.requestCertificateVersion(certificateName)
	if err != nil {
		return err
	}

	fmt.Printf("Getting PFX for %s\n", certificateName)
	pfxKey, pfxCert, err := akv.requestCertificatePFX(certificateName, certificateVersion)
	keyX509, err := x509.MarshalPKCS8PrivateKey(pfxKey)
	if err != nil {
		return nil
	}

	fmt.Println(pfxCert)
	fmt.Println(keyX509)

	return nil
}

func main() {
	vaultName := os.Getenv("VAULT_NAME")
	certificateName := os.Getenv("CERTIFICATE_NAME")

	ctx := context.Background()

	certificate := AzureKeyVaultCertificate{
		Ctx:       ctx,
		VaultName: vaultName,
	}

	if err := certificate.GetKeyVaultClient(); err != nil {
		fmt.Println("Error", err)
		return
	}

	if err := certificate.GetCertificate(certificateName); err != nil {
		fmt.Println("Error", err)
		return
	}

}
