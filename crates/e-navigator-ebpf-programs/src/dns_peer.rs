#[inline(always)]
pub(crate) const fn is_dns_ipv4_peer(family: u16, server_port_be: u16) -> bool {
    family == 2 && u16::from_be(server_port_be) == 53
}
