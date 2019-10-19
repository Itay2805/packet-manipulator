package me.itay.pcapproxy.structs;

import java.nio.ByteOrder;

import me.itay.pcapproxy.DataStream;

public class sockaddr_ll {

    public short sll_family;
    public short sll_protocol;
    public short sll_ifindex;
    public short sll_hatype;
    public short sll_pkttype;
    public short sll_halen;
    public byte[] sll_addr = new byte[8];

    public sockaddr_ll(sockaddr sockaddr) {
        this.sll_family = sockaddr.sa_family;

        DataStream stream = sockaddr.getSaData();
        sll_protocol = stream.readShort();
        sll_ifindex = stream.readShort();
        sll_hatype = stream.readShort();
        sll_pkttype = stream.readShort();
        sll_halen = stream.readShort();
        stream.readBytes(sll_addr);
    }

    public short getSaFamily() {
        if (ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN)) {
            return (short) (0xFF & sll_family);
        } else {
            return (short) (0xFF & (sll_family >> 8));
        }
    }

}
