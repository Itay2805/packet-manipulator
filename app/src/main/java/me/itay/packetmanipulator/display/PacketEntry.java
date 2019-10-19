package me.itay.packetmanipulator.display;

import org.pcap4j.packet.Packet;

public class PacketEntry {

    public Packet original;

    public String source = "";
    public String destination = "";
    public String protocol = "";
    public String length = "";
    public String info = "";

    public int backgroundColor = 0xFFFFFFFF;
    public int textColor = 0x00000000;

}
