package me.itay.packetmanipulator.display.impl;

import android.graphics.Color;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;

import me.itay.packetmanipulator.display.PacketEntry;
import me.itay.packetmanipulator.display.PacketEntryTransfomer;

public class EthernetTransfomer implements PacketEntryTransfomer {

    @Override
    public void transformEntry(Packet payload, PacketEntry entry) {
        EthernetPacket packet = (EthernetPacket) payload;
        EthernetPacket.EthernetHeader header = packet.getHeader();

        if(header.getDstAddr().equals(MacAddress.ETHER_BROADCAST_ADDRESS)) {
            entry.destination = "Broadcast";
            entry.textColor = Color.parseColor("#BABDB6");
        }else {
            entry.destination = header.getDstAddr().toString();
            entry.textColor = Color.parseColor("#000000");
        }
        if(header.getSrcAddr().equals(MacAddress.ETHER_BROADCAST_ADDRESS)) {
            entry.source = "Broadcast";
        }else {
            entry.source = header.getSrcAddr().toString();
        }

        entry.protocol = header.getType().valueAsString();
        entry.info = header.getType().name();

        entry.backgroundColor = Color.parseColor("#FFFFFF");
    }
}
