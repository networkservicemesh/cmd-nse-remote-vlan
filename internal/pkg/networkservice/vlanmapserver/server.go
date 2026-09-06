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

// Package vlanmapserver provides chain element implementing `network service -> { BASEIF, VLAN }` mapping
package vlanmapserver

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/pkg/errors"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vlan"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"

	"github.com/networkservicemesh/cmd-nse-remote-vlan/internal/pkg/config"
)

const (
	viaLabel = "via"
)

// TODO: add support for multiple services
type vlanMapServer struct {
	entries map[string]*entry
}
type entry struct {
	vlanTag uint32
	via     string
	mtu     uint32
}

// NewServer - creates a NetworkServiceServer that requests a vlan interface and populates the netns inode
func NewServer(cfg *config.Config) networkservice.NetworkServiceServer {
	v := &vlanMapServer{
		entries: make(map[string]*entry, len(cfg.Services)),
	}

	for i := range cfg.Services {
		service := &cfg.Services[i]
		v.entries[service.Name] = &entry{
			vlanTag: service.VLANTag,
			via:     service.Via,
			mtu:     service.MTU,
		}
	}
	return v
}

func (v *vlanMapServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	conn := request.GetConnection()
	entry, ok := v.entries[conn.GetNetworkService()]

	if !ok {
		return nil, errors.Errorf("network service is not supported: %s", conn.GetNetworkService())
	}

	if mechanism := vlan.ToMechanism(conn.GetMechanism()); mechanism != nil {
		mechanism.SetVlanID(entry.vlanTag)

		conn.Labels = make(map[string]string, 1)
		conn.Labels[viaLabel] = entry.via
	}
	if request.GetConnection().GetContext() == nil {
		request.GetConnection().Context = &networkservice.ConnectionContext{}
	}
	request.GetConnection().GetContext().MTU = entry.mtu

	return next.Server(ctx).Request(ctx, request)
}

func (v *vlanMapServer) Close(ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	return next.Server(ctx).Close(ctx, conn)
}
