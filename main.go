package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/auth"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
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

func (akv *AzureKeyVaultCertificate) GetCertificate(certificateName string) (err error) {
	if !akv.authenticated {
		return errors.New("Need to invoke GetKeyVaultClient() first")
	}

	fmt.Printf("Getting certificate version for %s\n", certificateName)
	certificateVersion, err := akv.requestCertificateVersion(certificateName)
	if err != nil {
		return err
	}

	fmt.Println(certificateVersion)
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
