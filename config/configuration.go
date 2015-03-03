package config

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
)

var configFile string

func init() {
	// Check for a command line argument referencing the configuration file.
	flag.StringVar(&configFile, "config", "config.json", "path to configuration file")
}

func LoadConfiguration() (*Configuration, error) {
	file, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	var config Configuration
	err = decoder.Decode(&config)
	if err != nil {
		return nil, err
	}
	// Convert all of the configuration file paths to absolute paths
	configAbs, err := filepath.Abs(configFile)
	if err != nil {
		return nil, err
	}
	configDir := filepath.Dir(configAbs)
	resolvePath := func(path *string) {
		// If the path is absolute, leave itt alone
		if filepath.IsAbs(*path) {
			return
		}
		relPath := filepath.Join(configDir, *path)
		// If we can't make the file absolute, leave it alone
		absPath, err := filepath.Abs(relPath)
		if err != nil {
			return
		}
		*path = absPath
	}
	resolvePath(&config.AttributeProviders.JsonStore.File)
	resolvePath(&config.Certificate)
	resolvePath(&config.Key)
	// Password form fixes
	form := config.Authenticator.Fallback.Form
	if form != nil {
		resolvePath(&form.Directory)
		form.Form = filepath.Join(form.Directory, form.Form)
		form.Error = filepath.Join(form.Directory, form.Error)
	}
	resolvePath(&config.Authenticator.Fallback.Form.Directory)

	return &config, nil
}

type Configuration struct {
	EntityId           string
	Address            string
	BaseURL            string
	Certificate        string
	Key                string
	Log                string
	Redis              Redis
	Services           Services
	Authenticator      *Authenticator
	AttributeProviders *AttributeProviders
}

type Authenticator struct {
	Type     string
	Fallback *PasswordAuthenticator
}

type PasswordAuthenticator struct {
	Form *Form
}

type Form struct {
	Directory string
	Form      string
	Error     string
	Context   string
	Action    string
}

type AttributeProviders struct {
	JsonStore *JsonStore
}

type JsonStore struct {
	File string
}

type Redis struct {
	Address string
}

type Services struct {
	Authentication     string
	ArtifactResolution string
	AttributeQuery     string
	Metadata           string
}
