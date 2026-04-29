package main

import (
	"github.com/provabl/ground/internal/config"
)

func loadConfig(path string) (*config.Config, error) {
	return config.Load(path)
}
