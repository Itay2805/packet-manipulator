package me.itay.packetmanipulator.display;

import org.pcap4j.packet.Packet;

public interface PacketDissector {

    public void dissect(PacketEntry entry);

}
