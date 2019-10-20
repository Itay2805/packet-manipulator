package me.itay.packetmanipulator.display;

import android.graphics.Color;

import org.pcap4j.packet.Packet;

public class PacketEntry {

    public Packet original;

    public String source = "?";
    public String destination = "?";
    public String protocol = "?";
    public String info = "?";

    public int backgroundColor = Color.WHITE;
    public int textColor = Color.parseColor("#12272e");

}
