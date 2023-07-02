use std::thread;
use tiny_http;

/// Starts a small HTTP server as a target server to connect to.
pub fn start_dest_server() -> (u16, u16) {
    // V4 listener
    let port_v4: u16 = portpicker::pick_unused_port().expect("No ports free");
    let server = tiny_http::Server::http(format!("0.0.0.0:{}", port_v4)).unwrap();
    thread::spawn(move || {
        for request in server.incoming_requests() {
            let response = tiny_http::Response::from_string("Hello".to_string());
            request.respond(response).unwrap();
        }
    });

    // V6 listener
    let port_v6: u16 = portpicker::pick_unused_port().expect("No ports free");
    let server = tiny_http::Server::http(format!("[::]:{}", port_v6)).unwrap();
    thread::spawn(move || {
        for request in server.incoming_requests() {
            let response = tiny_http::Response::from_string("Hello".to_string());
            request.respond(response).unwrap();
        }
    });

    return (port_v4, port_v6);
}
