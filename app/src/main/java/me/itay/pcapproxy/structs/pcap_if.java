package me.itay.pcapproxy.structs;

import java.util.ArrayList;
import java.util.List;

import me.itay.pcapproxy.DataStream;

public class pcap_if {

    public String name;
    public String description;
    public List<pcap_addr> addresses;
    public int flags;

    public pcap_if(DataStream stream) {
        name = stream.readString();
        description = stream.readString();

        addresses = new ArrayList<>();
        stream.readArray(() -> addresses.add(new pcap_addr(stream)));

        flags = stream.readInt();
    }

}
