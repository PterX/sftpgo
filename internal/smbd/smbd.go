package smbd

import (
	"fmt"

	"github.com/drakkan/sftpgo/v2/internal/common"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/macos-fuse-t/go-smb2/config"
	smb2 "github.com/macos-fuse-t/go-smb2/server"
	"github.com/macos-fuse-t/go-smb2/vfs"
)

const (
	logSender = "smbd"
)

var (
	serviceStatus ServiceStatus
	serverList    []*smb2.Server
)

type Binding struct {
	// The address to listen on. A blank value means listen on all available network interfaces.
	Address string `json:"address" mapstructure:"address"`
	// The port used for serving requests
	Port int `json:"port" mapstructure:"port"`
}

func (b *Binding) IsValid() bool {
	return b.Port > 0
}

type ServiceStatus struct {
	IsActive bool      `json:"is_active"`
	Bindings []Binding `json:"bindings"`
}

type Configuration struct {
	// Addresses and ports to bind to
	Bindings []Binding `json:"bindings" mapstructure:"bindings"`
}

func (c *Configuration) ShouldBind() bool {
	for _, binding := range c.Bindings {
		if binding.IsValid() {
			return true
		}
	}
	return false
}

func (c *Configuration) loadFromProvider() error {
	configs, err := dataprovider.GetConfigs()
	if err != nil {
		return fmt.Errorf("unable to load config from provider: %w", err)
	}
	configs.SetNilsToEmpty()
	return nil
}

// 用户信息变更回调
func (c *Configuration) NotifyPasswdChange(username string, password string) error {
	for _, svr := range serverList {
		svr.ChangePasswd(username, password)
	}
	return nil
}

// Initialize configures and starts the SMB server
func (c *Configuration) Initialize(configDir string) error {
	if err := c.loadFromProvider(); err != nil {
		return err
	}
	logger.Info(logSender, "", "initializing SMB server with config %+v", *c)
	if !c.ShouldBind() {
		return common.ErrNoBinding
	}
	serviceStatus = ServiceStatus{
		Bindings: nil,
	}

	exitChannel := make(chan error, 1)

	// get user list for ntlm auth
	users, _ := dataprovider.GetUsers(-1, 0, "", "")
	user_list := map[string]string{}
	for _, user := range users {
		user_list[user.Username] = user.Password
	}
	dataprovider.RegistUserChange(c)

	for _, binding := range c.Bindings {
		if !binding.IsValid() {
			continue
		}

		go func(b *Binding) {
			cfg := config.NewConfig([]string{})
			cfg.Hostname = "NAS"
			cfg.AllowGuest = false
			srv := smb2.NewServer(
				&smb2.ServerConfig{
					AllowGuest:  cfg.AllowGuest,
					MaxIOReads:  cfg.MaxIOReads,
					MaxIOWrites: cfg.MaxIOWrites,
					Xatrrs:      cfg.Xatrrs,
				},
				&smb2.NTLMAuthenticator{
					TargetSPN:    "",
					NbDomain:     cfg.Hostname,
					NbName:       cfg.Hostname,
					DnsName:      cfg.Hostname + ".local",
					DnsDomain:    ".local",
					UserPassword: user_list,
					AllowGuest:   cfg.AllowGuest,
				},
				map[string]vfs.VFSFileSystem{cfg.ShareName: NewPassthroughFS(cfg.MountDir)},
			)
			serverList = append(serverList, srv)

			logger.Info(logSender, "Starting server at %s", binding.Address)
			exitChannel <- srv.Serve(cfg.ListenAddr)
		}(&binding)

		serviceStatus.Bindings = append(serviceStatus.Bindings, binding)
	}

	serviceStatus.IsActive = true
	return <-exitChannel
}
