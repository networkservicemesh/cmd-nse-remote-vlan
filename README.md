#

## Intro

This repo contains 'nse-remote-vlan' an NSE application for Network Service Mesh. It provides ipam and vlan configuration context for registered Network Services.

## Usage

`nse-remote-vlan` accept following environment variables:

* NSM_NAME                  Name of the endpoint
* NSM_CONNECT_TO            An URL of registry service to connect to
* NSM_MAX_TOKEN_LIFETIME    Maximum lifetime of tokens
* NSM_CIDR_PREFIX           CIDR Prefix to assign IPs from
* NSM_IPV6_PREFIX           Ipv6 Prefix for dual-stack
* NSM_REGISTER_SERVICE      if true then registers network service on startup
* NSM_LISTEN_ON             tcp:// url to be listen on. It will be used as public to register NSM
* NSM_SERVICES              List of supported services

## Build

### Build cmd binary locally

You can build the locally by executing

```bash
go build ./...
```

### Build Docker container

You can build the docker container by running:

```bash
docker build .
```

## Testing

### Testing Docker container

Testing is run via a Docker container.  To run testing run:

```bash
docker run --privileged --rm $(docker build -q --target test .)
```

## Debugging

### Debugging the tests

If you wish to debug the test code itself, that can be acheived by running:

```bash
docker run --privileged --rm -p 40000:40000 $(docker build -q --target debug .)
```

This will result in the tests running under dlv.  Connecting your debugger to localhost:40000 will allow you to debug.

```bash
-p 40000:40000
```

forwards port 40000 in the container to localhost:40000 where you can attach with your debugger.

```bash
--target debug
```

Runs the debug target, which is just like the test target, but starts tests with dlv listening on port 40000 inside the container.

### Debugging the cmd

When you run 'cmd' you will see an early line of output that tells you:

```Setting env variable DLV_LISTEN_FORWARDER to a valid dlv '--listen' value will cause the dlv debugger to execute this binary and listen as directed.```

If you follow those instructions when running the Docker container:

```bash
docker run --privileged -e DLV_LISTEN_FORWARDER=:50000 -p 50000:50000 --rm $(docker build -q --target test .)
```

```-e DLV_LISTEN_FORWARDER=:50000``` tells docker to set the environment variable DLV_LISTEN_FORWARDER to :50000 telling
dlv to listen on port 50000.

```-p 50000:50000``` tells docker to forward port 50000 in the container to port 50000 in the host.  From there, you can
just connect dlv using your favorite IDE and debug cmd.

### Debugging the tests and the cmd

```bash
docker run --privileged -e DLV_LISTEN_FORWARDER=:50000 -p 40000:40000 -p 50000:50000 --rm $(docker build -q --target debug .)
```

Please note, the tests **start** the cmd, so until you connect to port 40000 with your debugger and walk the tests
through to the point of running cmd, you will not be able to attach a debugger on port 50000 to the cmd.