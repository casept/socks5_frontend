#[derive(PartialEq, Debug, Clone)]
pub enum AuthMethod {
    NoAuth,
    UsernamePassword,
    Unknown(u8),
}

impl AuthMethod {
    pub(crate) fn from_byte(b: u8) -> AuthMethod {
        match b {
            0x00 => return AuthMethod::NoAuth,
            0x02 => return AuthMethod::UsernamePassword,
            _ => return AuthMethod::Unknown(b),
        }
    }

    pub(crate) fn to_byte(&self) -> u8 {
        match self {
            AuthMethod::NoAuth => return 0x00,
            AuthMethod::UsernamePassword => return 0x02,
            AuthMethod::Unknown(b) => return *b,
        }
    }
}

pub(crate) mod user_pass_auth {
    use crate::socks_error::SOCKSError;
    use std::io::{Read, Write};
    use std::net;

    pub(crate) fn negotiate_stream(
        correct_username: String,
        correct_password: String,
        stream: &mut net::TcpStream,
    ) -> Option<SOCKSError> {
        // We expect the client to use version 1 of the subnegotiation protocol
        let mut ver_buf: [u8; 1] = [0];
        stream.read_exact(&mut ver_buf).unwrap();
        if ver_buf[0] != 1 {
            return Some(SOCKSError::UnknownAuthMethodSubnegotiationVersionError(
                stream.peer_addr().unwrap(),
                ver_buf[0],
                1,
            ));
        }

        // Read the length of the username that follows
        let mut username_len_buf: [u8; 1] = [0];
        stream.read_exact(&mut username_len_buf).unwrap();

        // Read the username
        let username: String;
        if username_len_buf[0] > 0 {
            let mut username_buf = vec![0; username_len_buf[0].into()];
            stream.read_exact(&mut username_buf).unwrap();
            username = String::from_utf8_lossy(&username_buf).to_string();
        } else {
            username = "".to_string();
        }

        // Read the length of the password that follows
        let mut password_len_buf: [u8; 1] = [0];
        stream.read_exact(&mut password_len_buf).unwrap();

        // Read the password
        let password: String;
        if password_len_buf[0] > 0 {
            let mut password_buf = vec![0; password_len_buf[0].into()];
            stream.read_exact(&mut password_buf).unwrap();
            password = String::from_utf8_lossy(&password_buf).to_string();
        } else {
            password = "".to_string();
        }

        // Check for correctness
        if username == correct_username && password == correct_password {
            let creds_correct_buf: [u8; 2] = [1, 0];
            stream.write(&creds_correct_buf).unwrap();
            return None;
        } else {
            let creds_incorrect_buf: [u8; 2] = [1, 1];
            stream.write(&creds_incorrect_buf).unwrap();
            // Close the connection, as mandated by the spec
            stream.shutdown(net::Shutdown::Both).unwrap();
            return Some(SOCKSError::WrongCredentialsError(
                stream.peer_addr().unwrap(),
            ));
        }
    }
}
