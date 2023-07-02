use portpicker;
use reqwest;
use socks5_frontend;

use std::io;
use std::net;
use std::thread;

mod common;
use common::*;

/// Starts the actual proxy server
fn start_proxy_server() -> net::SocketAddr {
    let host = "127.0.0.1";
    let port: u16 = portpicker::pick_unused_port().expect("No ports free");
    let addr = net::SocketAddr::from((host.parse::<net::Ipv4Addr>().unwrap(), port));
    let server = socks5_frontend::Server::init(
        addr,
        None,
        vec![socks5_frontend::AuthMethod::NoAuth],
        None,
        None,
    )
    .unwrap();
    thread::spawn(move || {
        // Start a simple connection forwarder
        for connection in server {
            let conn = connection.unwrap();

            let remote_addr = conn.get_destination_address_string();

            match net::TcpStream::connect(remote_addr.clone()) {
                Ok(remote_stream) => {
                    let ready_conn = conn.report_success();

                    // Start relaying data between the two streams
                    let mut client_stream_1 = ready_conn.unwrap().get_stream();
                    let mut client_stream_2 = client_stream_1.try_clone().unwrap();
                    let mut server_stream_1 = remote_stream;
                    let mut server_stream_2 = server_stream_1.try_clone().unwrap();
                    // Client => Server
                    thread::spawn(move || io::copy(&mut client_stream_1, &mut server_stream_1));
                    // Server => Client
                    thread::spawn(move || io::copy(&mut server_stream_2, &mut client_stream_2));
                }
                Err(err) => {
                    match err.kind() {
                        io::ErrorKind::ConnectionRefused => {
                            conn.report_connection_refused().unwrap()
                        }
                        io::ErrorKind::NotFound => conn.report_destination_unreachable().unwrap(),
                        io::ErrorKind::UnexpectedEof => {
                            conn.report_destination_unreachable().unwrap()
                        }
                        _ => conn.report_destination_unreachable().unwrap(),
                    }
                    panic!("Failed to connect to remote {}: {}", remote_addr, err);
                }
            };
        }
    });

    return addr;
}

#[test]
fn test_no_auth() {
    let proxy_addr = start_proxy_server();
    let (port_v4, port_v6) = start_dest_server();

    // Try to retrieve data via the proxy
    let proxy_uri = format!("socks5://{}", proxy_addr);
    let proxy = reqwest::Proxy::all(&proxy_uri).expect("Failed to convert proxy address");
    let client = reqwest::blocking::ClientBuilder::new()
        .proxy(proxy)
        .build()
        .unwrap();

    // Test IPv4, IPv6 and DNS addresses
    let dest_url = format!("http://127.0.0.1:{}", port_v4);
    let resp = client.get(&dest_url).send().unwrap();
    assert_eq!(resp.text().unwrap(), "Hello");

    let dest_url = format!("http://localhost:{}", port_v6);
    let resp = client.get(&dest_url).send().unwrap();
    assert_eq!(resp.text().unwrap(), "Hello");

    /* FIXME: v6 address support seems to have regressed in reqwest. */
    /*
    let dest_url = format!("http://[::1]:{}", port_v6);
    let resp = client.get(&dest_url).send().unwrap();
    assert_eq!(resp.text().unwrap(), "Hello");
    */
}
