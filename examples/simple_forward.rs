use socks5_frontend;
use std::io;
use std::net;
use std::thread;
use std::time;

use ignore_result::Ignore;

fn main() {
    // Start a new server bound to localhost
    let server = socks5_frontend::Server::init(
        "127.0.0.1:1080".parse().unwrap(),
        Some(time::Duration::from_secs(1)),
        vec![socks5_frontend::AuthMethod::NoAuth],
        None,
        None
    )
    .unwrap();
    // The library handles accepting new clients and authenticating them for you.
    // You will receive a struct representing each connection made by a client, and your job is to use this struct
    // to (optionally) process and pass along data in the TCP stream,
    // as well as doing the same in reverse and passing along received
    // (and, optionally, processed) data back to the client.
    // This example only handles outgoing TCP connections (no incoming TCP or UDP).

    // Process each connection
    for connection in server {
        let conn;
        match connection {
            Ok(val) => conn = val,
            Err(e) => {
                eprintln!("Failed to handle client connection: {}", e);
                continue;
            }
        }

        // Start a new thread to process the connection
        thread::spawn(move || {
                // If you want to disallow certain connections, perform the filtering here, then
                // call conn.report_connection_not_allowed() to tell the client about a violation.

                // Try to dial the requested host

                let remote_addr = conn.get_destination_address_string();
                println!(
                    "Connecting to {} on behalf of proxy client {}",
                    remote_addr,
                    conn.get_client_address()
                );

                match net::TcpStream::connect(remote_addr) {
                    Ok(remote_stream) => {
                        // Set a timeout for the remote end as well
                        remote_stream
                            .set_read_timeout(Some(time::Duration::from_secs(1)))
                            .unwrap();
                        remote_stream
                            .set_write_timeout(Some(time::Duration::from_secs(1)))
                            .unwrap();
                        // If successful, tell the client to expect data to start being relayed
                        let ready_conn = conn.report_success().unwrap();

                        // Start relaying data between the two streams
                        println!("Starting to proxy data!");
                        // Spawn 2 threads to continuously copy on both directions
                        // This is not very efficient, but good enough for a demo.
                        // We need to clone the stream here because both the reading and writing threads need a mutable handle
                        let mut client_stream_1 = ready_conn.get_stream();
                        let mut client_stream_2 = client_stream_1.try_clone().unwrap();
                        let mut server_stream_1 = remote_stream;
                        let mut server_stream_2 = server_stream_1.try_clone().unwrap();
                        // Client => Server
                        let _ = thread::Builder::new()
                            .stack_size(10 * 1024)
                            .spawn(move || io::copy(&mut client_stream_1, &mut server_stream_1).ignore());
                        // Server => Client
                        let _ = thread::Builder::new()
                            .stack_size(10 * 1024)
                            .spawn(move || io::copy(&mut server_stream_2, &mut client_stream_2).ignore());
                    }
                    // If that fails, tell the client
                    // Note that in a real-world program you should look at the error closely
                    // and invoke the most appropriate error reporting method.
                    Err(err) => {
                        eprintln!("Failed to reach destination: {}", err);
                        match err.kind() {
                            io::ErrorKind::ConnectionRefused => conn.report_connection_refused().ignore(),
                            io::ErrorKind::NotFound => conn.report_destination_unreachable().ignore(),
                            io::ErrorKind::UnexpectedEof => conn.report_destination_unreachable().ignore(),
                            _ => conn.report_destination_unreachable().ignore(),
                        }
                    }
                };
            });
    }
}
