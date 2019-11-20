package common

import (
	"log"
	"os"
)

var logger *log.Logger

// GetLogger returns the instance for logging
func GetLogger() *log.Logger {
	if logger == nil {
		logger = log.New(os.Stdout, "", log.Ltime)
	}
	return logger
}
