package server
import ("flag"
    "encoding/json"
    "os"
    "path/filepath")

var configFile string
func init() {
    // Check for a command line argument referencing the configuration file.
    flag.StringVar(&configFile, "config", "config.json", "path to configuration file")
}

func loadConfiguration() (*Configuration, error) {
    file, err := os.Open(configFile)
    if err!=nil {
        return nil, err
    }
    defer file.Close()
    decoder := json.NewDecoder(file)
    var config Configuration
    err=decoder.Decode(&config)
    if err!=nil {
        return nil, err
    }
    // Convert all of the configuration file paths to absolute paths
    configAbs, err := filepath.Abs(configFile)
    if err!=nil {
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
        if err!=nil {
            return
        }
        *path = absPath
    }
    resolvePath(&config.AttributeProviders.JsonStore.File)
    resolvePath(&config.Authorities)
    resolvePath(&config.Certificate)
    resolvePath(&config.Key)
    return &config, nil
}

type Configuration struct {
    EntityId string
    Address string
    Certificate string
    Key string
    Authorities string
    Log string
    Redis Redis
    Services Services
    AttributeProviders *AttributeProviders
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
    Authentication string
    ArtifactResolution string
    AttributeQuery string
}
