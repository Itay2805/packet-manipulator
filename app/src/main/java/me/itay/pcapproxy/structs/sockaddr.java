package me.itay.pcapproxy.structs;

import java.io.ByteArrayInputStream;
import java.nio.ByteOrder;

import me.itay.pcapproxy.DataStream;

public class sockaddr {

    public short sa_family;
    public byte[] sa_data = new byte[14];

    public sockaddr(DataStream stream) {
        sa_family = stream.readShort();
        stream.readBytes(sa_data);
    }

    public DataStream getSaData() {
        return new DataStream(new ByteArrayInputStream(sa_data), null);
    }

    public short getSaFamily() {
        if (ByteOrder.nativeOrder().equals(ByteOrder.BIG_ENDIAN)) {
            return (short) (0xFF & sa_family);
        } else {
            return (short) (0xFF & (sa_family >> 8));
        }
    }

}
