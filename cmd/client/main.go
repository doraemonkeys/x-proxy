package main

import (
	"flag"
	"x-proxy/pkg/config"
	"x-proxy/pkg/logger"
	"x-proxy/pkg/obfuscator"
	"x-proxy/pkg/proxy"
)

func main() {
	var configFile string
	flag.StringVar(&configFile, "config", "config.client.json", "Path to the client configuration file")
	flag.Parse()

	logger.Infof("ConfigFile path: %s", configFile)
	cfg, err := config.LoadClientConfig(configFile)
	if err != nil {
		logger.Fatalf("Failed to load client config from %s: %v", configFile, err)
	}

	logger.SetLevel(cfg.LogLevel)

	var cipher obfuscator.Cipher
	if cfg.DisableObfuscation {
		logger.Infof("Obfuscation disabled - running in transparent mode")
		cipher = obfuscator.NewCipher("", "") // Empty key creates noop cipher
	} else {
		cipher = obfuscator.NewCipher(cfg.Obfuscator, cfg.Key)
	}

	client := proxy.NewClient(cfg, cipher)
	client.Run()
}
