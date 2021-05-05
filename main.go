package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/auth"
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

func main() {
	vaultName := os.Getenv("VAULT_NAME")
	// certificateName := os.Getenv("CERTIFICATE_NAME")

	ctx := context.Background()

	certificate := AzureKeyVaultCertificate{
		Ctx:       ctx,
		VaultName: vaultName,
	}

	if err := certificate.GetKeyVaultClient(); err != nil {
		fmt.Println("Error", err)
		return
	}

	fmt.Println(certificate.authenticated)
}
