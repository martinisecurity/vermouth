package logger

import (
	"fmt"
	"log"
	"os"
	"sync"
)

var LogChan chan *LogMessage
var OurLogger = &stirShakenLogger{}

type stirShakenLogger struct {
	sync.Mutex
	errorLogFile *os.File
	infoLogFile  *os.File
	errorLogger  *log.Logger
	infoLogger   *log.Logger
}

type Severity int

const (
	INFO Severity = iota
	ERROR
	FATAL // Only ever use for unrecoverable/catastrophic events
)

type LogMessage struct {
	Severity
	MsgStr string
}

func (s Severity) String() string {
	return [...]string{"[INFO]", "[ERROR]", "[FATAL]"}[s]
}

func (logger *stirShakenLogger) InitializeLogger(infoPath string, errorPath string) error {
	infoLog, err := os.OpenFile(infoPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	logger.infoLogFile = infoLog
	logger.infoLogger = log.New(infoLog, "", log.LstdFlags)

	errLog, err := os.OpenFile(errorPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	logger.errorLogFile = errLog
	logger.errorLogger = log.New(errLog, "", log.LstdFlags)

	LogChan = make(chan *LogMessage, 100)
	// Begin receiving log messages
	go func() {
		for msg := range LogChan {
			logger.handleLogMsg(msg)
		}
	}()

	return nil
}

func (logger *stirShakenLogger) RotateLogs() {
	if logger.infoLogFile == nil || logger.errorLogFile == nil {
		return
	}
	logger.handleLogMsg(&LogMessage{INFO, "Vermouth: Rotating Logs..."})
	logger.Lock()
	defer logger.Unlock()
	_ = logger.infoLogFile.Close()
	logger.infoLogFile, _ = os.OpenFile(logger.infoLogFile.Name(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	logger.infoLogger = log.New(logger.infoLogFile, "", log.LstdFlags)
	_ = logger.errorLogFile.Close()
	logger.errorLogFile, _ = os.OpenFile(logger.errorLogFile.Name(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	logger.errorLogger = log.New(logger.errorLogFile, "", log.LstdFlags)
}

func (logger *stirShakenLogger) SyncAndCloseLogs(errorCode int) {
	logger.handleLogMsg(&LogMessage{INFO, "Vermouth: Exiting program..."})
	close(LogChan)
	_ = logger.infoLogFile.Sync()
	_ = logger.infoLogFile.Close()
	_ = logger.errorLogFile.Sync()
	_ = logger.errorLogFile.Close()
	os.Exit(errorCode)
}

func (logger *stirShakenLogger) handleLogMsg(log *LogMessage) {
	logger.Lock()
	switch log.Severity {
	case INFO:
		logger.infoLogger.Println(INFO.String() + " " + log.MsgStr)
	case ERROR:
		logger.infoLogger.Println(ERROR.String() + " " + log.MsgStr)
		logger.errorLogger.Println(ERROR.String() + " " + log.MsgStr)
	case FATAL:
		logger.infoLogger.Println(FATAL.String() + " " + log.MsgStr)
		logger.errorLogger.Println(FATAL.String() + " " + log.MsgStr)
		fmt.Println(log.MsgStr)
		logger.SyncAndCloseLogs(1)
	}
	logger.Unlock()
}
