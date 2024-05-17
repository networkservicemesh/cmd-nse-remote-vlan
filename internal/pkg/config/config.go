
// Copyright (c) 2023 Cisco and/or its affiliates.
//
// Copyright (c) 2021-2024 Nordix Foundation.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package config provides methods to get configuration parameters from environment variables
package config

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/singlepointipam"

	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"

	"github.com/networkservicemesh/sdk/pkg/tools/cidr"
)

const (
	vlanPrefix   = "vlan:"
	labelsPrefix = "labels:"
	viaPrefix    = "via:"
	domainPrefix = "domain:"

	tcpSchema = "tcp"
)

// Config holds configuration parameters from environment variables
type Config struct {
	Name                   string          `default:"vlan-server" desc:"Name of the endpoint"`
	ConnectTo              url.URL         `default:"nsm-registry-svc:5002" desc:"url of registry service to connect to" split_words:"true"`
	MaxTokenLifetime       time.Duration   `default:"24h" desc:"maximum lifetime of tokens" split_words:"true"`
	RegistryClientPolicies []string        `default:"etc/nsm/opa/common/.*.rego,etc/nsm/opa/registry/.*.rego,etc/nsm/opa/client/.*.rego" desc:"paths to files and directories that contain registry client policies" split_words:"true"`
	CidrPrefix             []string        `default:"169.254.0.0/16" desc:"CIDR Prefix or IP range to assign IPs (IPv4 and/or IPv6) from" split_words:"true"`
	RegisterService        bool            `default:"true" desc:"if true then registers network service on startup" split_words:"true"`
	ListenOn               url.URL         `default:"tcp://:5003" desc:"tcp:// url to be listen on. It will be used as public to register NSM" split_words:"true"`
	OpenTelemetryEndpoint  string          `default:"otel-collector.observability.svc.cluster.local:4317" desc:"OpenTelemetry Collector Endpoint" split_words:"true"`
	MetricsExportInterval  time.Duration   `default:"10s" desc:"interval between metrics exports" split_words:"true"`
	LogLevel               string          `default:"INFO" desc:"Log level" split_words:"true"`
	Services               []ServiceConfig `default:"" desc:"list of supported services"`
}

// Process prints and processes env to config
func (c *Config) Process() error {
	if err := envconfig.Usage("nsm", c); err != nil {
		return errors.Wrap(err, "cannot show usage of envconfig nse")
	}
	if err := envconfig.Process("nsm", c); err != nil {
		return errors.Wrap(err, "cannot process envconfig nse")
	}
	if err := validateConfig(c); err != nil {
		return errors.Wrap(err, "configuration validation failed")
	}
	return nil
}
func validateConfig(cfg *Config) error {
	if cfg.ListenOn.Scheme != tcpSchema {
		return errors.New("only tcp schema is supported for this type of endpoint")
	}
	if _, err := ParseCidr(cfg.CidrPrefix); err != nil {
		return err
	}
	return nil
}

// ParseCidr parses array of CIDR prefixes (and/or IP ranges)
// Valid "prefix" formats are "192.168.0.0/24", "192.168.0.1-192.168.0.100/24",
// or composite "192.168.0.1-192.168.0.10/24;192.168.0.20-192.168.0.30/24".
func ParseCidr(cIDRs []string) ([]*singlepointipam.IpamNet, error) {
	if len(cIDRs) > 2 {
		return nil, errors.Errorf("one IPv4 and/or one IPv6 config allowed")
	}

	ipamNets := []*singlepointipam.IpamNet{}
	for _, cIDR := range cIDRs {
		ipamNet := singlepointipam.NewIpamNet()
		composite := strings.Split(cIDR, ";")
		for _, cidrStr := range composite {
			if r := strings.SplitN(cidrStr, "-", 2); len(r) == 2 {
				if err := parseRange(ipamNet, r); err != nil {
					return nil, err
				}
			} else {
				// IP network
				if len(composite) > 1 {
					return nil, errors.Errorf("%s composite subnet config is invalid", composite)
				}
				if err := parseNetwork(ipamNet, cidrStr); err != nil {
					return nil, err
				}
			}
		}
		ipamNets = append(ipamNets, ipamNet)
	}

	if err := validateNetworkFamily(ipamNets...); err != nil {
		return nil, err
	}

	return ipamNets, nil
}

func setNetwork(ipamNet *singlepointipam.IpamNet, ipNet *net.IPNet) error {
	if ipamNet.Network == nil {
		ipamNet.Network = ipNet
	} else {
		if !ipamNet.Network.IP.Equal(ipNet.IP) {
			return errors.Errorf("network mismatch: %v != %v", ipamNet.Network, ipNet)
		}
		ones, bits := ipNet.Mask.Size()
		iones, ibits := ipamNet.Network.Mask.Size()
		if ones != iones || bits != ibits {
			return errors.Errorf("network mask mismatch: %v != %v", ipamNet.Network.Mask, ipNet.Mask)
		}
	}
	return nil
}

func parseNetwork(ipamNet *singlepointipam.IpamNet, network string) error {
	network = strings.TrimSpace(network)
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return errors.Errorf("%s is invalid CIDR: %s", network, err)
	}
	return setNetwork(ipamNet, ipNet)
}

func parseRange(ipamNet *singlepointipam.IpamNet, r []string) error {
	r[0] = strings.TrimSpace(r[0])
	r[1] = strings.TrimSpace(r[1])
	firstip := net.ParseIP(r[0])
	if firstip == nil {
		return errors.Errorf("%s is invalid range start", r[0])
	}
	lastip, ipNet, err := net.ParseCIDR(r[1])
	if err != nil {
		return errors.Errorf("%s is invalid CIDR: %s", r[1], err)
	}
	if !ipNet.Contains(firstip) {
		return errors.Errorf("%s is invalid range start for CIDR %s", firstip, ipNet.String())
	}
	if err := setNetwork(ipamNet, ipNet); err != nil {
		return err
	}
	return ipamNet.AddRange(firstip, lastip)
}

func validateNetworkFamily(ipamNets ...*singlepointipam.IpamNet) error {
	if len(ipamNets) == 2 {
		ip1 := ipamNets[0].Network.IP.To16()
		ip2 := ipamNets[1].Network.IP.To16()
		if ip1.To4() != nil && ip2.To4() != nil || ip1.To4() == nil && ip2.To4() == nil {
			return errors.Errorf("one IPv4 and/or one IPv6 config allowed")
		}
	}
	return nil
}

// ServiceConfig is a per-service config
type ServiceConfig struct {
	Name    string
	Domain  string
	Via     string
	VLANTag int32
	Labels  map[string]string
}

// InitValues set initial values for ServiceConfig
func (s *ServiceConfig) InitValues() {
	s.Domain = ""
	s.VLANTag = 0
	s.Via = ""
}

// UnmarshalBinary expects string(bytes) to be in format:
// Name { domain: Domain; vlan: VLANTag; labels: Labels; via: Via; }
// Labels = label_1=value_1&label_2=value_2
func (s *ServiceConfig) UnmarshalBinary(bytes []byte) (err error) {
	text := string(bytes)

	split := strings.Split(text, "{")
	if len(split) < 2 {
		return errors.Errorf("invalid format: %s", text)
	}
	s.Name = strings.TrimSpace(split[0])
	s.InitValues()
	split = strings.Split(split[1], "}")
	for _, part := range strings.Split(split[0], ";") {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, vlanPrefix):
			s.VLANTag, err = parseInt32(trimPrefix(part, vlanPrefix))
		case strings.HasPrefix(part, labelsPrefix):
			s.Labels, err = parseMap(trimPrefix(part, labelsPrefix))
		case strings.HasPrefix(part, viaPrefix):
			s.Via = trimPrefix(part, viaPrefix)
		case strings.HasPrefix(part, domainPrefix):
			s.Domain = trimPrefix(part, domainPrefix)
		default:
			err = errors.Errorf("invalid format: %s", text)
		}
		if err != nil {
			return err
		}
	}
	return s.validate()
}

func trimPrefix(s, prefix string) string {
	s = strings.TrimPrefix(s, prefix)
	return strings.TrimSpace(s)
}

func parseInt32(s string) (int32, error) {
	i, err := strconv.ParseInt(s, 0, 32)
	if err != nil {
		return 0, err
	}
	return int32(i), nil
}

func parseMap(s string) (map[string]string, error) {
	m := make(map[string]string)
	for _, keyValue := range strings.Split(s, "&") {
		split := strings.Split(keyValue, "=")
		if len(split) != 2 {
			return nil, errors.Errorf("invalid key-value pair: %s", keyValue)
		}
		m[split[0]] = split[1]
	}
	return m, nil
}

func (s *ServiceConfig) validate() error {
	if s.Name == "" {
		return errors.New("name is empty")
	}
	if s.Via == "" {
		return errors.New("via is empty")
	}
	if s.VLANTag < 0 || s.VLANTag > 4095 {
		return errors.New("Invalid VLAN ID")
	}
	return nil
}
