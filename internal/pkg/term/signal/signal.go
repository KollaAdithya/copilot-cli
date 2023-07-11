package signal

import (
	"context"
	"os"
	"os/signal"

	"github.com/aws/copilot-cli/internal/pkg/deploy"
)

type cfnClient interface {
	DeleteWorkload(in deploy.DeleteWorkloadInput) error
	DeleteEnvironment(appName, envName, cfnExecRoleARN string)
}

type Signal struct {
	cfnClient     cfnClient
	signalChannel chan os.Signal
	signals       []os.Signal
	cancelFunc    context.CancelFunc
}

func NewSignal(cfnClient cfnClient, signal os.Signal) Signal {
	return Signal{
		cfnClient:     cfnClient,
		signalChannel: make(chan os.Signal),
	}
}

func (s *Signal) NotifySignals() {
	signal.Notify(s.signalChannel, s.signals...)
}

// func (s *Signal) HandleInterruptForWorkload()

func (s *Signal) closeSigChannel() {
	close(s.signalChannel)
}

func (s *Signal) stopCatchSignals() {
	signal.Stop(s.signalChannel)
}
