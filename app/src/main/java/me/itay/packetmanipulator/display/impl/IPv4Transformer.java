package me.itay.packetmanipulator.display.impl;

import android.annotation.SuppressLint;
import android.graphics.Color;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import me.itay.packetmanipulator.display.PacketEntry;
import me.itay.packetmanipulator.display.PacketEntryTransfomer;

public class IPv4Transformer implements PacketEntryTransfomer {


    @SuppressLint("DefaultLocale")
    @Override
    public void transformEntry(Packet payload, PacketEntry entry) {
        IpV4Packet packet = (IpV4Packet) payload;
        IpV4Packet.IpV4Header header = packet.getHeader();

        entry.source = header.getSrcAddr().toString().substring(1);
        entry.destination = header.getDstAddr().toString().substring(1);
        entry.protocol = "IPv4";
        entry.info = "";

        if(header.getMoreFragmentFlag()) {
            entry.info += String.format("Fragmented IP protocol (proto=%s %d, off=%d, ID=%04x)",
                    header.getProtocol().name(),
                    header.getProtocol().value(),
                    header.getFragmentOffset(),
                    header.getIdentification());

        }else {
            entry.info += String.format("%s (%d)",
                    header.getProtocol().name(),
                    header.getProtocol().value());
        }

        entry.textColor = Color.parseColor("#000000");
        entry.backgroundColor = Color.parseColor("#FFFFFF");
    }
}
