package main

import (
	"context"

	"golang.org/x/sys/windows/svc"
)

type service struct {
	start func(context.Context) error
	err error
}

func platformRun(start func(context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil { return err }
	if !isService { return consoleRun(start) }
	s := &service{start: start}
	if err := svc.Run("Hookbox", s); err != nil { return err }
	return s.err
}

func (s *service) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.start(ctx) }()
	state := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	changes <- state
	for {
		select {
		case err := <-done:
			s.err = err
			if err != nil { return false, 1 }
			return false, 0
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate: changes <- state
			case svc.Stop, svc.Shutdown:
				state = svc.Status{State: svc.StopPending, WaitHint: 20000}
				changes <- state
				cancel()
			}
		}
	}
}
