package me.itay.packetmanipulator.display.impl;

import android.annotation.SuppressLint;

import org.pcap4j.packet.LinuxSllPacket;
import org.pcap4j.packet.Packet;

import me.itay.packetmanipulator.display.PacketEntry;
import me.itay.packetmanipulator.display.PacketEntryTransfomer;

public class LinuxSllTransfomer implements PacketEntryTransfomer {

    @SuppressLint("DefaultLocale")
    @Override
    public void transformEntry(Packet payload, PacketEntry entry) {
        LinuxSllPacket packet = (LinuxSllPacket) payload;
        LinuxSllPacket.LinuxSllHeader header = packet.getHeader();

        entry.protocol = "SLL";
        entry.info = String.format("%s (%d)", header.getPacketType().name(), header.getPacketType().value());
    }

}
