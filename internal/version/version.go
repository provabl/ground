// SPDX-FileCopyrightText: 2026 Playground Logic LLC
// SPDX-License-Identifier: Apache-2.0

// Package version holds ground's build version — the single place it is written.
//
// It is a package rather than a variable in main because the version is not only
// printed: it is stamped into the ground:version tag on every OU and permission
// set a deploy creates, and into the generated IaC artifacts. When each of those
// carried its own literal they drifted apart, and every OU ground had ever
// deployed ended up tagged with a version that never deployed it (#42).
//
// The default is deliberately "dev" rather than a version number. A release
// injects the real value:
//
//	go build -ldflags="-X github.com/provabl/ground/internal/version.Version=v0.3.0"
//
// An un-injected build then says "dev", which is true, instead of claiming to be
// a release that shipped something else. ground:version exists to answer "which
// ground built this?" — the question you ask when a resource looks wrong and you
// need to know whether a known-bad release created it. A wrong answer is worse
// than no answer: absent prompts you to look elsewhere, wrong sends you to the
// wrong release.
package version

// Version is ground's build version, set at link time by the release workflow.
var Version = "dev"
