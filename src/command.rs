#[derive(PartialEq)]
pub(crate) enum Command {
    Unknown, // Placeholder value
    Connect, // 0x01
    Bind, // 0x02
    UDPAssociate, // 0x03
}

impl Command {
    pub(crate) fn from_byte(b: u8) -> Command {
        match b {
            0x01 => return Command::Connect,
            0x02 => return Command::Bind,
            0x03 => return Command::UDPAssociate,
            _ => return Command::Unknown,
        }
    }
}