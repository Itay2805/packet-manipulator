package me.itay.pcapproxy.structs;

import me.itay.pcapproxy.DataStream;

public class pcap_stat {

    public int ps_recv;
    public int ps_drop;
    public int ps_ifdrop;

    public pcap_stat(DataStream stream) {
        this.ps_recv = stream.readInt();
        this.ps_drop = stream.readInt();
        this.ps_ifdrop = stream.readInt();
    }

}
