// Generated from resources/application-protocol-catalog/catalog.tsv.

pub const APPLICATION_PROTOCOL_CATALOG_VERSION: u32 = 1;

pub const APPLICATION_PROTOCOL_ID_RESERVED_1000: u32 = 1000;
pub const APPLICATION_PROTOCOL_ID_DNS: u32 = 1001;
pub const APPLICATION_PROTOCOL_ID_HTTP: u32 = 1002;
pub const APPLICATION_PROTOCOL_ID_TLS: u32 = 1003;
pub const APPLICATION_PROTOCOL_ID_QUIC: u32 = 1004;
pub const APPLICATION_PROTOCOL_ID_SSH: u32 = 1005;
pub const APPLICATION_PROTOCOL_ID_MDNS: u32 = 1006;
pub const APPLICATION_PROTOCOL_ID_SMTP: u32 = 1007;
pub const APPLICATION_PROTOCOL_ID_FTP_CONTROL: u32 = 1008;
pub const APPLICATION_PROTOCOL_ID_FTP_DATA: u32 = 1009;
pub const APPLICATION_PROTOCOL_ID_FTPS: u32 = 1010;
pub const APPLICATION_PROTOCOL_ID_OPENVPN: u32 = 1011;
pub const APPLICATION_PROTOCOL_ID_WIREGUARD: u32 = 1012;
pub const APPLICATION_PROTOCOL_ID_SOCKS4: u32 = 1013;
pub const APPLICATION_PROTOCOL_ID_SOCKS5: u32 = 1014;
pub const APPLICATION_PROTOCOL_ID_RDP: u32 = 1015;
pub const APPLICATION_PROTOCOL_ID_STUN: u32 = 1016;
pub const APPLICATION_PROTOCOL_ID_RTP: u32 = 1017;
pub const APPLICATION_PROTOCOL_ID_RTCP: u32 = 1018;
pub const APPLICATION_PROTOCOL_ID_SIP: u32 = 1019;
pub const APPLICATION_PROTOCOL_ID_DTLS: u32 = 1020;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationProtocolEntry {
    pub id: u32,
    pub key: &'static str,
    pub status: &'static str,
    pub category: &'static str,
}

pub const APPLICATION_PROTOCOL_CATALOG: &[ApplicationProtocolEntry] = &[
    ApplicationProtocolEntry { id: 1000, key: "reserved-1000", status: "reserved", category: "" },
    ApplicationProtocolEntry { id: 1001, key: "dns", status: "active", category: "infrastructure" },
    ApplicationProtocolEntry { id: 1002, key: "http", status: "active", category: "web" },
    ApplicationProtocolEntry { id: 1003, key: "tls", status: "active", category: "web" },
    ApplicationProtocolEntry { id: 1004, key: "quic", status: "active", category: "web" },
    ApplicationProtocolEntry { id: 1005, key: "ssh", status: "active", category: "remote-access" },
    ApplicationProtocolEntry { id: 1006, key: "mdns", status: "active", category: "infrastructure" },
    ApplicationProtocolEntry { id: 1007, key: "smtp", status: "active", category: "mail" },
    ApplicationProtocolEntry { id: 1008, key: "ftp-control", status: "active", category: "file-transfer" },
    ApplicationProtocolEntry { id: 1009, key: "ftp-data", status: "active", category: "file-transfer" },
    ApplicationProtocolEntry { id: 1010, key: "ftps", status: "active", category: "file-transfer" },
    ApplicationProtocolEntry { id: 1011, key: "openvpn", status: "active", category: "vpn" },
    ApplicationProtocolEntry { id: 1012, key: "wireguard", status: "active", category: "vpn" },
    ApplicationProtocolEntry { id: 1013, key: "socks4", status: "active", category: "proxy" },
    ApplicationProtocolEntry { id: 1014, key: "socks5", status: "active", category: "proxy" },
    ApplicationProtocolEntry { id: 1015, key: "rdp", status: "active", category: "remote-access" },
    ApplicationProtocolEntry { id: 1016, key: "stun", status: "active", category: "realtime" },
    ApplicationProtocolEntry { id: 1017, key: "rtp", status: "active", category: "realtime" },
    ApplicationProtocolEntry { id: 1018, key: "rtcp", status: "active", category: "realtime" },
    ApplicationProtocolEntry { id: 1019, key: "sip", status: "active", category: "realtime" },
    ApplicationProtocolEntry { id: 1020, key: "dtls", status: "active", category: "realtime" },
];
