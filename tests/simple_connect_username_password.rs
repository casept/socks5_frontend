use portpicker;
use reqwest;
use simple_server;
use socks5_frontend;

use std::io;
use std::net;
use std::thread;

/// Starts a small HTTP server as a target server to connect to.
fn start_dest_server() -> u16 {
    let port: u16 = portpicker::pick_unused_port().expect("No ports free");

    // V4 listener
    thread::spawn(move || {
        let server = simple_server::Server::new(|_request, mut response| {
            Ok(response.body("Hello".as_bytes().to_vec())?)
        });
        server.listen("127.0.0.1", &port.to_string());
    });

    // V6 listener
    thread::spawn(move || {
        let server = simple_server::Server::new(|_request, mut response| {
            Ok(response.body("Hello".as_bytes().to_vec())?)
        });
        server.listen("::1", &port.to_string());
    });

    return port;
}

/// Starts the actual proxy server
fn start_proxy_server() -> net::SocketAddr {
    let host = "127.0.0.1";
    let port: u16 = portpicker::pick_unused_port().expect("No ports free");
    let addr = net::SocketAddr::from((host.parse::<net::Ipv4Addr>().unwrap(), port));
    let server = socks5_frontend::Server::init(
        addr,
        None,
        vec![socks5_frontend::AuthMethod::UsernamePassword],
        Some("randall".to_string()),
        Some("CorrectHorseBatteryStaple".to_string()),
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
                        io::ErrorKind::ConnectionRefused => conn.report_connection_refused().unwrap(),
                        io::ErrorKind::NotFound => conn.report_destination_unreachable().unwrap(),
                        io::ErrorKind::UnexpectedEof => conn.report_destination_unreachable().unwrap(),
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
fn test_username_password_auth_no_creds() {
    let proxy_addr = start_proxy_server();
    let dest_port = start_dest_server();

    // This should fail
    let result = std::panic::catch_unwind(move || {
        // Try to retrieve data via the proxy
        let proxy_uri = format!("socks5://{}", proxy_addr);
        let proxy = reqwest::Proxy::all(&proxy_uri).expect("Failed to convert proxy address");
        let client = reqwest::ClientBuilder::new().proxy(proxy).build().unwrap();
        let dest_url = format!("http://127.0.0.1:{}", dest_port);
        let mut resp = client.get(&dest_url).send().unwrap();
        assert_eq!(resp.text().unwrap(), "Hello");
    });
    assert!(result.is_err());
}

#[test]
fn test_username_password_auth_wrong_username() {
    let proxy_addr = start_proxy_server();
    let dest_port = start_dest_server();

    // This should fail
    let result = std::panic::catch_unwind(move || {
        // Try to retrieve data via the proxy
        let proxy_uri = format!("socks5://user:CorrectHorseBatteryStaple@{}", proxy_addr);
        let proxy = reqwest::Proxy::all(&proxy_uri).expect("Failed to convert proxy address");
        let client = reqwest::ClientBuilder::new().proxy(proxy).build().unwrap();
        let dest_url = format!("http://127.0.0.1:{}", dest_port);
        let mut resp = client.get(&dest_url).send().unwrap();
        assert_eq!(resp.text().unwrap(), "Hello");
    });
    assert!(result.is_err());
}

#[test]
fn test_username_password_auth_wrong_password() {
    let proxy_addr = start_proxy_server();
    let dest_port = start_dest_server();

    // This should fail
    let result = std::panic::catch_unwind(move || {
        // Try to retrieve data via the proxy
        let proxy_uri = format!("socks5://randall:Correct@{}", proxy_addr);
        let proxy = reqwest::Proxy::all(&proxy_uri).expect("Failed to convert proxy address");
        let client = reqwest::ClientBuilder::new().proxy(proxy).build().unwrap();
        let dest_url = format!("http://127.0.0.1:{}", dest_port);
        let mut resp = client.get(&dest_url).send().unwrap();
        assert_eq!(resp.text().unwrap(), "Hello");
    });
    assert!(result.is_err());
}

#[test]
fn test_username_password_auth() {
    let proxy_addr = start_proxy_server();
    let dest_port = start_dest_server();

    // Try to retrieve data via the proxy
    let proxy_uri = format!("socks5://randall:CorrectHorseBatteryStaple@{}", proxy_addr);
    let proxy = reqwest::Proxy::all(&proxy_uri).expect("Failed to convert proxy address");
    let client = reqwest::ClientBuilder::new().proxy(proxy).build().unwrap();

    // Test IPv4, IPv6 and DNS addresses
    let dest_url = format!("http://127.0.0.1:{}", dest_port);
    let mut resp = client.get(&dest_url).send().unwrap();
    assert_eq!(resp.text().unwrap(), "Hello");

    let dest_url = format!("http://localhost:{}", dest_port);
    let mut resp = client.get(&dest_url).send().unwrap();
    assert_eq!(resp.text().unwrap(), "Hello");

    let dest_url = format!("http://[::1]:{}", dest_port);
    let mut resp = client.get(&dest_url).send().unwrap();
    assert_eq!(resp.text().unwrap(), "Hello");
}
