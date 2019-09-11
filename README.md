# socks5_frontend

This is a rust library which makes it easier to write custom, synchronous SOCKS5 proxy servers.

It's primarily built for writing tor pluggable transports in Rust, and currently only supports the absolute minimum of features to achieve that.

## Supported features

### Authentication

    [X] No authentication

    [ ] Username/Password authentication

    [ ] GSSAPI authentication

    [ ] Custom authentication plugins

### Data transfer

    [X] TCP `CONNECT`

    [ ] TCP `BIND`

    [ ] UDP

### Code quality

    [ ] Integration tests

    [ ] Documentation

    [ ] Error handling

## How to use

A simple example server which simply forwards all TCP traffic is provided under `examples/simple_forward.rs`.