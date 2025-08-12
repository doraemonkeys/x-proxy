package logger

import (
	"log"
	"strings"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarning
	LevelError
)

var currentLevel = LevelInfo

var levelMap = map[string]Level{
	"debug":   LevelDebug,
	"info":    LevelInfo,
	"warning": LevelWarning,
	"error":   LevelError,
}

func SetLevel(level string) {
	l, ok := levelMap[strings.ToLower(level)]
	if !ok {
		log.Printf("Unknown log level '%s', defaulting to 'info'", level)
		currentLevel = LevelInfo
		return
	}
	currentLevel = l
}

func Debugf(format string, v ...interface{}) {
	if currentLevel <= LevelDebug {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func Infof(format string, v ...interface{}) {
	if currentLevel <= LevelInfo {
		log.Printf("[INFO] "+format, v...)
	}
}

func Warnf(format string, v ...interface{}) {
	if currentLevel <= LevelWarning {
		log.Printf("[WARN] "+format, v...)
	}
}

func Errorf(format string, v ...interface{}) {
	if currentLevel <= LevelError {
		log.Printf("[ERROR] "+format, v...)
	}
}

func Fatalf(format string, v ...interface{}) {
	if currentLevel <= LevelError {
		log.Fatalf("[FATAL] "+format, v...)
	}
}
