// Copyright (c) 2021-2023 Nordix Foundation.
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

package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/networkservicemesh/cmd-nse-remote-vlan/internal/pkg/config"
)

var TestCidrPrefixTests = []struct {
	cidrs []string
}{
	{
		[]string{
			"192.168.0.0/16",
			"dead:beaf::/64",
		},
	},
	{
		[]string{
			"192.168.0.1/32",
			"dead:beaf::1/128",
		},
	},
	{
		[]string{
			"192.168.100.0/24",
		},
	},
	{
		[]string{
			"192.168.0.1-192.168.0.100/24",
			"fe80:1000:2000::/64",
		},
	},
	{
		[]string{
			"192.168.0.1-192.168.0.100/24",
			"2dea:ffff:ffff:ffff:ffff:ffff:0000:0000-2dea:ffff:ffff:ffff:ffff:ffff:abcd:0000/96",
		},
	},
	{
		[]string{
			"192.168.0.0-192.168.0.0/16;192.168.1.1-192.168.1.1/16;192.168.100.100-192.168.200.200/16",
			"1000::a:2-1000::a:ffff/64;1000::d:2-1000::e:ffff/64;1000::f:f:2-1000::f:f:2/64",
		},
	},
	{
		[]string{
			"2000::1-2000::2000/64",
		},
	},
}

var TestCidrPrefixInvalidTests = []struct {
	cidrs []string
}{
	{
		[]string{
			"192.168.0.1-192.168.0.100/24",
			"10.0.0.1-10.0.200/16",
			"100::1-100::ffff/64",
		},
	},
	{
		[]string{
			"192.168.0.1-192.168.0.100/24",
			"10.0.0.1-10.0.200/16",
		},
	},
	{
		[]string{
			"100::1-100::ffff/64",
			"2dea::1-2dea::ffff/64",
		},
	},
	{
		[]string{
			"192.168.0.1-192.168.0.100/24;192.168.32.1-192.168.32.100/25",
		},
	},
	{
		[]string{
			"2dea::af0-2dea::aff/96;2dea::ef0-2dea::eff/64;2dea::cf0-2dea::cff/96",
		},
	},
	{
		[]string{
			"192.168.0.1-192.168.0.100/24;192.168.0.0/24",
		},
	},
	{
		[]string{
			"192.168.0.64/28",
			"2000::/64;2000::1-2000::2000/64",
		},
	},
	{
		[]string{
			"192.168.0.0/28-192.168.0.2/28",
		},
	},
	{
		[]string{
			"2000::2000-2000::1/64",
		},
	},
	{
		[]string{
			"192.168.0.0-192.168.0.2/36",
		},
	},
	{
		[]string{
			"abba::baba/140",
		},
	},
	{
		[]string{
			"192.168.11.0-192.168.10.2/30",
		},
	},
	{
		[]string{
			"2000:b::1-2000:a::2000/64",
		},
	},
}

func TestServiceConfig_UnmarshalBinary(t *testing.T) {
	cfg := new(config.ServiceConfig)

	err := cfg.UnmarshalBinary([]byte("finance-bridge { domain: service-domain.2; vlan: 100; via: gw-1 }"))
	require.NoError(t, err)

	require.Equal(t, &config.ServiceConfig{
		Name:    "finance-bridge",
		Domain:  "service-domain.2",
		Via:     "gw-1",
		VLANTag: 100,
	}, cfg)

	err = cfg.UnmarshalBinary([]byte("finance-bridge { vlan: 200; via: service-domain.1 }"))
	require.NoError(t, err)

	require.Equal(t, &config.ServiceConfig{
		Name:    "finance-bridge",
		Via:     "service-domain.1",
		VLANTag: 200,
	}, cfg)
}

func TestCidrPrefix(t *testing.T) {
	for _, ct := range TestCidrPrefixTests {
		_, err := config.ParseCidr(ct.cidrs)
		require.NoError(t, err, ct.cidrs)
	}
}

func TestCidrPrefixInvalid(t *testing.T) {
	for _, ct := range TestCidrPrefixInvalidTests {
		_, err := config.ParseCidr(ct.cidrs)
		require.Error(t, err, ct.cidrs)
	}
}
