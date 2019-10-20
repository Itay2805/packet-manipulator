package me.itay.pcapproxy.structs;

import me.itay.pcapproxy.DataStream;

public class pcap_pkthdr {

    public timeval ts;
    public int caplen;
    public int len;
    public byte[] data;

    public pcap_pkthdr(DataStream stream) {
        ts = new timeval(stream);
        this.caplen = stream.readInt();
        this.len = stream.readInt();
        data = new byte[caplen];
        stream.readBytes(data);
    }

    public pcap_pkthdr() {

    }

    public void write(DataStream stream) {
        this.ts.write(stream);
        stream.writeInt(this.caplen);
        stream.writeInt(this.len);
        stream.readBytes(this.data);
    }

}
