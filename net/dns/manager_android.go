// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package dns

import (
	"errors"
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/syspolicy/policyclient"
)

// Android's DNS resolver belongs to netd and the selected network. A root
// daemon must not hijack port 53, replace Private DNS, or alter a VPN's DNS.
type androidRootManager struct{ noopManager }

func NewOSConfigurator(logger.Logf, *health.Tracker, *eventbus.Bus, policyclient.Client, *controlknobs.Knobs, string) (OSConfigurator, error) {
	return androidRootManager{}, nil
}

func (androidRootManager) SetDNS(cfg OSConfig) error {
	if len(cfg.Nameservers) != 0 || len(cfg.SearchDomains) != 0 {
		return errors.New("Android root DNS integration is disabled; use --accept-dns=false")
	}
	return nil
}
