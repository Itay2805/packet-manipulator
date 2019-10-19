package me.itay.pcapproxy.structs;

import me.itay.pcapproxy.DataStream;

public class sockaddr_in {

    public short sin_family;
    public short sin_port;
    public in_addr sin_addr;
    public byte[] sin_zero = new byte[8];

    public sockaddr_in(sockaddr addr) {
        this.sin_family = addr.sa_family;

        DataStream stream = addr.getSaData();
        sin_port = stream.readShort();
        sin_addr.s_addr = stream.readInt();
        stream.readBytes(sin_zero);
    }

}
