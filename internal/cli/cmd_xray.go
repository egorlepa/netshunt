package cli

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/guras256/keenetic-split-tunnel/internal/config"
	"github.com/guras256/keenetic-split-tunnel/internal/daemon"
	"github.com/guras256/keenetic-split-tunnel/internal/deploy"
	"github.com/guras256/keenetic-split-tunnel/internal/group"
	"github.com/guras256/keenetic-split-tunnel/internal/platform"
	"github.com/guras256/keenetic-split-tunnel/internal/service"
)

func newXrayCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "xray",
		Short: "Manage Xray VLESS+Reality proxy",
	}

	cmd.AddCommand(
		newXrayStatusCmd(),
		newXrayKeygenCmd(),
		newXrayResetCmd(),
		newXrayWriteConfigCmd(),
	)

	return cmd
}

func newXrayStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show Xray status and configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			ctx := cmd.Context()
			installed := service.Xray.IsInstalled()
			running := false
			if installed {
				running = service.Xray.IsRunning(ctx)
			}

			fmt.Println("Xray:")
			fmt.Printf("  Installed:   %v\n", installed)
			fmt.Printf("  Running:     %v\n", running)
			fmt.Printf("  Server:      %s:%d\n", cfg.Xray.Server, cfg.Xray.ServerPort)
			fmt.Printf("  Local port:  %d\n", cfg.Xray.LocalPort)
			fmt.Printf("  UUID:        %s\n", cfg.Xray.UUID)
			fmt.Printf("  Flow:        %s\n", cfg.Xray.Flow)
			fmt.Printf("  SNI:         %s\n", cfg.Xray.SNI)
			fmt.Printf("  Fingerprint: %s\n", cfg.Xray.Fingerprint)
			fmt.Printf("  Public key:  %s\n", cfg.Xray.PublicKey)
			fmt.Printf("  Short ID:    %s\n", cfg.Xray.ShortID)
			return nil
		},
	}
}

func newXrayKeygenCmd() *cobra.Command {
	var save bool
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate X25519 key pair and short ID for Reality",
		Long: `Generates a fresh X25519 key pair and a random short ID.
Use the public key and short ID in both the server xray config and KST config.
The private key goes on the SERVER only.

With --save, writes public key and short ID to KST config (not the private key).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			privKey, pubKey, err := generateX25519Keys()
			if err != nil {
				return fmt.Errorf("generate keys: %w", err)
			}

			shortID, err := generateShortID()
			if err != nil {
				return fmt.Errorf("generate short ID: %w", err)
			}

			fmt.Println("X25519 key pair (for Xray Reality):")
			fmt.Printf("  Private key: %s\n", privKey)
			fmt.Printf("  Public key:  %s\n", pubKey)
			fmt.Printf("  Short ID:    %s\n", shortID)
			fmt.Println()
			fmt.Println("Server config (privateKey + shortIds):")
			fmt.Printf("  \"privateKey\": \"%s\",\n", privKey)
			fmt.Printf("  \"shortIds\": [\"%s\"]\n", shortID)

			if save {
				cfg, err := config.Load()
				if err != nil {
					return err
				}
				cfg.Xray.PublicKey = pubKey
				cfg.Xray.ShortID = shortID
				if err := config.Save(cfg); err != nil {
					return err
				}
				fmt.Println()
				fmt.Println("Public key and short ID saved to KST config.")
			}

			return nil
		},
	}
	cmd.Flags().BoolVar(&save, "save", false, "Save public key and short ID to KST config")
	return cmd
}

func newXrayResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset",
		Short: "Reset Xray iptables rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			logger := platform.NewLogger(cfg.Daemon.LogLevel)
			groups := group.NewDefaultStore()
			r := daemon.NewReconciler(cfg, groups, logger)

			ctx := cmd.Context()
			if err := r.Mode.TeardownRules(ctx); err != nil {
				return fmt.Errorf("teardown: %w", err)
			}
			if err := r.Mode.SetupRules(ctx); err != nil {
				return fmt.Errorf("setup: %w", err)
			}

			fmt.Println("Xray iptables rules reset.")
			return nil
		},
	}
}

func newXrayWriteConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "write-config",
		Short: "Write xray config.json from KST config",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			if err := deploy.WriteXrayConfig(cfg); err != nil {
				return fmt.Errorf("write xray config: %w", err)
			}
			fmt.Printf("Written to %s\n", platform.XrayConfigFile)

			ctx := cmd.Context()
			if err := service.Xray.EnsureRunning(ctx); err != nil {
				fmt.Printf("Warning: %v\n", err)
			} else {
				fmt.Println("xray is running.")
			}
			return nil
		},
	}
}

// generateX25519Keys returns a base64url-encoded (no padding) private and public key.
func generateX25519Keys() (privateKey, publicKey string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	priv := base64.RawURLEncoding.EncodeToString(key.Bytes())
	pub := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	return priv, pub, nil
}

// generateShortID returns a random 8-byte hex string (16 hex chars).
func generateShortID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
