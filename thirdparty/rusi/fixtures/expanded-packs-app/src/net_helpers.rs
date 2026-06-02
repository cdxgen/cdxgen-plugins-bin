pub fn connect_to(addr: String) {
    let _ = std::net::TcpStream::connect(addr);
}
