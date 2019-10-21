package me.itay.pcapproxy.structs;

import me.itay.pcapproxy.DataStream;

public class sockaddr_in6 {

    public short sin6_family;
    public short sin6_port;
    public int sin6_flowinfo;
    public in6_addr sin6_addr;
    public int sin6_scope_id;

    public sockaddr_in6(sockaddr sa) {
        sin6_family = sa.sa_family;

        DataStream stream = sa.getSaData();
        sin6_port = stream.readShort();
        sin6_flowinfo = stream.readInt();
        stream.readBytes(sin6_addr.s6_addr);
        sin6_scope_id = stream.readInt();
    }

}
