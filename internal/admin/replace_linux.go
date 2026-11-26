package admin

import "os"

func installConfig(temp, dest string) error { return os.Rename(temp, dest) }
