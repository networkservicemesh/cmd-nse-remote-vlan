// Copyright (c) 2021-2022 Nordix Foundation.
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
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
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
	Name                  string          `default:"vlan-server" desc:"Name of the endpoint"`
	ConnectTo             url.URL         `default:"nsm-registry-svc:5002" desc:"url of registry service to connect to" split_words:"true"`
	MaxTokenLifetime      time.Duration   `default:"24h" desc:"maximum lifetime of tokens" split_words:"true"`
	CidrPrefix            string          `default:"169.254.0.0/16" desc:"CIDR Prefix to assign IPs from" split_words:"true"`
	Ipv6Prefix            string          `default:"" desc:"Ipv6 Prefix for dual-stack" split_words:"true"`
	RegisterService       bool            `default:"true" desc:"if true then registers network service on startup" split_words:"true"`
	ListenOn              url.URL         `default:"tcp://:5003" desc:"tcp:// url to be listen on. It will be used as public to register NSM" split_words:"true"`
	OpenTelemetryEndpoint string          `default:"otel-collector.observability.svc.cluster.local:4317" desc:"OpenTelemetry Collector Endpoint"`
	LogLevel              string          `default:"INFO" desc:"Log level" split_words:"true"`
	Services              []ServiceConfig `default:"" desc:"list of supported services"`
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
