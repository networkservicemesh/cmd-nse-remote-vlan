// Copyright (c) 2021-2022 Doc.ai and/or its affiliates.
//
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

//go:build !windows

package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/grpcfd"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	vlanmech "github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vlan"
	"github.com/networkservicemesh/api/pkg/api/networkservice/payload"
	registryapi "github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/recvfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/groupipam"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/singlepointipam"
	registryclient "github.com/networkservicemesh/sdk/pkg/registry/chains/client"
	registryauthorize "github.com/networkservicemesh/sdk/pkg/registry/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/registry/common/clientinfo"
	registrysendfd "github.com/networkservicemesh/sdk/pkg/registry/common/sendfd"
	"github.com/networkservicemesh/sdk/pkg/tools/debug"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/listenonurl"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/opentelemetry"
	"github.com/networkservicemesh/sdk/pkg/tools/pprofutils"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
	"github.com/networkservicemesh/sdk/pkg/tools/token"
	"github.com/networkservicemesh/sdk/pkg/tools/tracing"

	"github.com/networkservicemesh/cmd-nse-remote-vlan/internal/pkg/config"
	"github.com/networkservicemesh/cmd-nse-remote-vlan/internal/pkg/networkservice/vlanmapserver"
)

func main() {
	// ********************************************************************************
	// setup context to catch signals
	// ********************************************************************************
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		// More Linux signals here
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	// ********************************************************************************
	// setup logging
	// ********************************************************************************
	log.EnableTracing(true)
	logrus.SetFormatter(&nested.Formatter{})
	ctx = log.WithLog(ctx, logruslogger.New(ctx, map[string]interface{}{"cmd": os.Args[0]}))

	if err := debug.Self(); err != nil {
		log.FromContext(ctx).Infof("%s", err)
	}
	logger := log.FromContext(ctx)

	// enumerating phases
	logger.Infof("there are 6 phases which will be executed followed by a success message:")
	logger.Infof("the phases include:")
	logger.Infof("1: get config from environment")
	logger.Infof("2: retrieve spiffe svid")
	logger.Infof("3: create network service endpoint")
	logger.Infof("4: create grpc server and register the server")
	logger.Infof("5: register nse with nsm")
	logger.Infof("a final success message with start time duration")
	starttime := time.Now()

	// ********************************************************************************
	logger.Infof("executing phase 1: get config from environment")
	// ********************************************************************************
	cfg := new(config.Config)
	if err := cfg.Process(); err != nil {
		logrus.Fatal(err.Error())
	}

	l, errLog := logrus.ParseLevel(cfg.LogLevel)
	if errLog != nil {
		logrus.Fatalf("invalid log level %s", cfg.LogLevel)
	}
	logrus.SetLevel(l)
	logruslogger.SetupLevelChangeOnSignal(ctx, map[os.Signal]logrus.Level{
		syscall.SIGUSR1: logrus.TraceLevel,
		syscall.SIGUSR2: l,
	})

	logger.Infof("Config: %#v", cfg)

	// ********************************************************************************
	// Configure Open Telemetry
	// ********************************************************************************
	if opentelemetry.IsEnabled() {
		collectorAddress := cfg.OpenTelemetryEndpoint
		spanExporter := opentelemetry.InitSpanExporter(ctx, collectorAddress)
		metricExporter := opentelemetry.InitOPTLMetricExporter(ctx, collectorAddress, cfg.MetricsExportInterval)
		o := opentelemetry.Init(ctx, spanExporter, metricExporter, cfg.Name)
		defer func() {
			if err := o.Close(); err != nil {
				log.FromContext(ctx).Error(err.Error())
			}
		}()
	}

	// ********************************************************************************
	// Configure pprof
	// ********************************************************************************
	if cfg.PprofEnabled {
		go pprofutils.ListenAndServe(ctx, cfg.PprofListenOn)
	}

	// ********************************************************************************
	logger.Infof("executing phase 2: retrieving svid, check spire agent logs if this is the last line you see")
	// ********************************************************************************
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		logger.Fatalf("error getting x509 source: %v", err.Error())
	}
	svid, err := source.GetX509SVID()
	if err != nil {
		logger.Fatalf("error getting x509 svid: %v", err.Error())
	}
	logger.Infof("sVID: %q", svid.ID)

	tlsClientConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	tlsClientConfig.MinVersion = tls.VersionTLS12
	tlsServerConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())
	tlsServerConfig.MinVersion = tls.VersionTLS12

	// ********************************************************************************
	logger.Infof("executing phase 3: create network service endpoint")
	// ********************************************************************************
	responderEndpoint := endpoint.NewServer(ctx,
		spiffejwt.TokenGeneratorFunc(source, cfg.MaxTokenLifetime),
		endpoint.WithName(cfg.Name),
		endpoint.WithAuthorizeServer(authorize.NewServer()),
		endpoint.WithAdditionalFunctionality(
			groupipam.NewServer(cfg.CidrPrefix, groupipam.WithCustomIPAMServer(singlepointipam.NewServer)),
			recvfd.NewServer(),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				vlanmech.MECHANISM: vlanmapserver.NewServer(cfg),
			}),
			sendfd.NewServer()))

	// ********************************************************************************
	logger.Infof("executing phase 4: create grpc server and register the server")
	// ********************************************************************************
	serverCreds := grpc.Creds(
		grpcfd.TransportCredentials(
			credentials.NewTLS(
				tlsServerConfig,
			),
		),
	)

	options := append(
		tracing.WithTracing(),
		serverCreds)
	server := grpc.NewServer(options...)
	responderEndpoint.Register(server)

	listenOn := &cfg.ListenOn
	srvErrCh := grpcutils.ListenAndServe(ctx, listenOn, server)
	exitOnErr(ctx, cancel, srvErrCh)

	logger.Infof("grpc server started")

	// ********************************************************************************
	logger.Infof("executing phase 5: register nse with nsm")
	// ********************************************************************************

	clientOptions := append(
		tracing.WithTracingDial(),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(
			grpc.WaitForReady(true),
			grpc.PerRPCCredentials(token.NewPerRPCCredentials(spiffejwt.TokenGeneratorFunc(source, cfg.MaxTokenLifetime)))),
		grpc.WithTransportCredentials(
			grpcfd.TransportCredentials(
				credentials.NewTLS(
					tlsClientConfig,
				),
			),
		),
		grpcfd.WithChainStreamInterceptor(),
		grpcfd.WithChainUnaryInterceptor(),
	)

	if cfg.RegisterService {
		nsRegistryClient := registryclient.NewNetworkServiceRegistryClient(ctx,
			registryclient.WithClientURL(&cfg.ConnectTo),
			registryclient.WithDialOptions(clientOptions...),
			registryclient.WithAuthorizeNSRegistryClient(registryauthorize.NewNetworkServiceRegistryClient(
				registryauthorize.WithPolicies(cfg.RegistryClientPolicies...))))
		for i := range cfg.Services {
			nsName := cfg.Services[i].Name
			nsPayload := payload.Ethernet
			if _, err = nsRegistryClient.Register(ctx, &registryapi.NetworkService{
				Name:    nsName,
				Payload: nsPayload,
			}); err != nil {
				log.FromContext(ctx).Fatalf("failed to register ns(%s) %s", nsName, err.Error())
			}
		}
	}

	nseRegistryClient := registryclient.NewNetworkServiceEndpointRegistryClient(
		ctx,
		registryclient.WithClientURL(&cfg.ConnectTo),
		registryclient.WithDialOptions(clientOptions...),
		registryclient.WithNSEAdditionalFunctionality(
			clientinfo.NewNetworkServiceEndpointRegistryClient(),
			registrysendfd.NewNetworkServiceEndpointRegistryClient(),
		),
		registryclient.WithAuthorizeNSERegistryClient(registryauthorize.NewNetworkServiceEndpointRegistryClient(
			registryauthorize.WithPolicies(cfg.RegistryClientPolicies...))),
	)
	nse := getNseEndpoint(listenOn, cfg, logger)

	nse, err = nseRegistryClient.Register(ctx, nse)
	logrus.Infof("nse: %+v", nse)

	if err != nil {
		log.FromContext(ctx).Fatalf("unable to register nse %+v", err)
	}

	// ********************************************************************************
	logger.Infof("startup completed in %v", time.Since(starttime))
	// ********************************************************************************
	// wait for server to exit
	<-ctx.Done()
}

func exitOnErr(ctx context.Context, cancel context.CancelFunc, errCh <-chan error) {
	// If we already have an error, log it and exit
	select {
	case err := <-errCh:
		log.FromContext(ctx).Fatal(err)
	default:
	}
	// Otherwise wait for an error in the background to log and cancel
	go func(ctx context.Context, errCh <-chan error) {
		err := <-errCh
		log.FromContext(ctx).Error(err)
		cancel()
	}(ctx, errCh)
}

func getNseEndpoint(listenOn *url.URL, cfg *config.Config, logger log.Logger) *registryapi.NetworkServiceEndpoint {
	expireTime := timestamppb.New(time.Now().Add(cfg.MaxTokenLifetime))

	pubURL := genPublishableURL(listenOn, logger)
	nse := &registryapi.NetworkServiceEndpoint{
		Name:                 cfg.Name,
		NetworkServiceNames:  make([]string, len(cfg.Services)),
		NetworkServiceLabels: make(map[string]*registryapi.NetworkServiceLabels, len(cfg.Services)),
		Url:                  pubURL.String(),
		ExpirationTime:       expireTime,
	}

	for i := range cfg.Services {
		service := &cfg.Services[i]

		labels := service.Labels
		if labels == nil {
			labels = make(map[string]string, 1)
		}
		nse.NetworkServiceNames[i] = service.Name
		nse.NetworkServiceLabels[service.Name] = &registryapi.NetworkServiceLabels{
			Labels: labels,
		}
	}
	return nse
}
func genPublishableURL(listenOn *url.URL, logger log.Logger) *url.URL {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		logger.Warn(err.Error())
		return listenOn
	}
	return listenonurl.GetPublicURL(addrs, listenOn)
}
