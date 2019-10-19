package me.itay.packetmanipulator.display;

import org.pcap4j.packet.Packet;

public interface PacketEntryTransfomer {

    public void transformEntry(Packet payload, PacketEntry entry);

}
