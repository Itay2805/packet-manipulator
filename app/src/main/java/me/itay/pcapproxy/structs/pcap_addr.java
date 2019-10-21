package me.itay.pcapproxy.structs;

import me.itay.pcapproxy.DataStream;

public class pcap_addr {

    public sockaddr addr;
    public sockaddr netmask;
    public sockaddr broadaddr;
    public sockaddr dstaddr;

    public pcap_addr(DataStream stream) {
        addr = new sockaddr(stream);
        netmask = new sockaddr(stream);
        broadaddr = new sockaddr(stream);
        dstaddr = new sockaddr(stream);
    }

}
