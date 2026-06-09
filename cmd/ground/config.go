// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/provabl/ground/internal/config"
)

func loadConfig(path string) (*config.Config, error) {
	return config.Load(path)
}
