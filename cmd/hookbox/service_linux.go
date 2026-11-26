package main

import "context"

func platformRun(start func(context.Context) error) error { return consoleRun(start) }
