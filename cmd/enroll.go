package cmd

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/models"
	"github.com/spf13/cobra"
)

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enrolls a MASQUE private key and switches mode",
	Long: "Enrolls a MASQUE private key and switches mode. Useful for ZeroTier where IPv6 address can change." +
		" Or if you just want to deploy a new key.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		configPath, err := cmd.Flags().GetString("config")
		if err != nil {
			log.Fatalf("Failed to get config path: %v", err)
		}
		if configPath == "" {
			log.Fatalf("Config path is required")
		}

		deviceName, err := cmd.Flags().GetString("name")
		if err != nil {
			log.Fatalf("Failed to get device name: %v", err)
		}

		regenKey, err := cmd.Flags().GetBool("regen-key")
		if err != nil {
			log.Fatalf("Failed to get regen-key: %v", err)
		}

		log.Printf("Enrolling device key...")

		var (
			privKeyBytes []byte
			publicKey    []byte
		)

	retry:
		if regenKey {
			log.Printf("Regenerating key pair...")
			privKeyBytes, publicKey, err = internal.GenerateEcKeyPair()
			if err != nil {
				log.Fatalf("Failed to generate key pair: %v", err)
			}
		} else {
			privKey, err := config.AppConfig.GetEcPrivateKey()
			if err != nil {
				log.Fatalf("Failed to get private key: %v", err)
			}

			publicKey, err = x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			if err != nil {
				log.Fatalf("Failed to marshal public key: %v", err)
			}

			privKeyBytes, err = x509.MarshalECPrivateKey(privKey)
			if err != nil {
				log.Fatalf("Failed to marshal private key: %v", err)
			}
		}

		accountData, err := api.EnrollKey(config.AppConfig.ID, config.AppConfig.AccessToken, publicKey, deviceName)
		if err != nil {
			var apiErr *models.APIError
			if errors.As(err, &apiErr) && apiErr.HasErrorCode(models.InvalidPublicKey) {
				fmt.Print("Invalid public key detected. Regenerate key? (y/n): ")

				var response string
				if _, err := fmt.Scanln(&response); err != nil {
					log.Fatalf("Failed to read user input: %v", err)
				}

				if response == "y" {
					regenKey = true
					goto retry
				}
				log.Fatalf("Enrollment aborted by user. %v", apiErr)
			}
			log.Fatalf("Failed to enroll key: %v", err)
		}
		if len(accountData.Config.Peers) == 0 {
			log.Fatalf("Enrollment response contained no peers")
		}
		peer := accountData.Config.Peers[0]
		endpointV4, err := endpointHost(peer.Endpoint.V4)
		if err != nil {
			log.Fatalf("Failed to parse IPv4 endpoint: %v", err)
		}
		endpointV6, err := endpointHost(peer.Endpoint.V6)
		if err != nil {
			log.Fatalf("Failed to parse IPv6 endpoint: %v", err)
		}

		log.Printf("Successful registration. Saving config...")

		h2v4 := config.AppConfig.EndpointH2V4
		if h2v4 == "" {
			h2v4 = config.DefaultEndpointH2V4
		}

		config.AppConfig = config.Config{
			PrivateKey:     base64.StdEncoding.EncodeToString(privKeyBytes),
			EndpointV4:     endpointV4,
			EndpointV6:     endpointV6,
			EndpointH2V4:   h2v4,
			EndpointH2V6:   config.AppConfig.EndpointH2V6,
			EndpointPubKey: peer.PublicKey,
			ID:             accountData.ID,
			AccessToken:    config.AppConfig.AccessToken,
			IPv4:           accountData.Config.Interface.Addresses.V4,
			IPv6:           accountData.Config.Interface.Addresses.V6,
		}

		if err := config.AppConfig.SaveConfig(configPath); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}

		log.Printf("Config saved to %s", configPath)
	},
}

func init() {
	enrollCmd.Flags().StringP("name", "n", "", "Rename device a given name")
	enrollCmd.Flags().BoolP("regen-key", "r", false, "Regenerate the key pair")
	rootCmd.AddCommand(enrollCmd)
}
