package main

import (
	"encoding/base64"
	"flag"
	"github.com/ipifony/vermouth"
	"github.com/ipifony/vermouth/logger"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func main() {
	// Config can be passed in on startup or defaults to config.yml local to go executable
	var configPath string
	flag.StringVar(&configPath, "config", LookupEnvOrString("VERMOUTH_CONFIG", "config.yml"), "path to config file")
	flag.Parse()

	// Load static config from YAML
	err := vermouth.GlobalConfig.LoadConfig(filepath.Clean(configPath))
	if err != nil {
		log.Fatal("Could not load config file! Error: " + err.Error())
	}

	if vermouth.GlobalConfig.GetServerInstanceId() == "" {
		rand.Seed(time.Now().UnixNano())
		randBytes := make([]byte, 9)
		rand.Read(randBytes)
		instanceId := base64.RawURLEncoding.EncodeToString(randBytes)
		vermouth.GlobalConfig.SetServerInstanceId(instanceId)
		vermouth.GlobalConfig.Save()
	}

	// Initialize Logger
	err = logger.OurLogger.InitializeLogger(vermouth.GlobalConfig.GetServerLogInfoPath(), vermouth.GlobalConfig.GetServerLogErrPath())
	if err != nil {
		log.Fatal("Log Disaster: Could not initialize logger - " + err.Error())
	}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Vermouth: Starting " + vermouth.AppName + " version " + vermouth.AppVersion + "."}
	logger.LogChan <- &logger.LogMessage{Severity: logger.INFO, MsgStr: "Telemetry Disabled: " + strconv.FormatBool(vermouth.GlobalConfig.IsTelemetryDisabled())}
	// Pass off all duties the maintenance routine
	vermouth.BeginVermouthOperations()
}

func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}
