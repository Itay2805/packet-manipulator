package me.itay.packetmanipulator.display.impl;

import android.graphics.Color;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.MacAddress;

import java.util.Arrays;

import me.itay.packetmanipulator.display.PacketEntry;
import me.itay.packetmanipulator.display.PacketEntryTransfomer;

public class ARPTransfomer implements PacketEntryTransfomer {

    @Override
    public void transformEntry(Packet payload, PacketEntry entry) {
        ArpPacket packet = (ArpPacket) payload;
        ArpPacket.ArpHeader header = packet.getHeader();

        if(header.getOperation() == ArpOperation.REPLY_REVERSE ||
           header.getOperation() == ArpOperation.REQUEST_REVERSE) {
            entry.protocol = "RARP";
        } else if(header.getOperation() == ArpOperation.INARP_REPLY ||
                header.getOperation() == ArpOperation.INARP_REQUEST) {
            entry.protocol = "Inverse ARP";
        }else {
            entry.protocol = "ARP";
        }

        boolean is_gratuitous = header.getSrcProtocolAddr().equals(header.getDstProtocolAddr());

        // dissect request
        if(header.getOperation() == ArpOperation.REQUEST) {

            // check if a gratuitous request (src_proto == dst_proto)
            if(is_gratuitous) {

                // check if an announcement (dst_hard == 0)
                if(Arrays.equals(header.getDstHardwareAddr().getAddress(), new byte[header.getHardwareAddrLength()])) {
                    entry.info = String.format("ARP Announcement for %s", header.getDstProtocolAddr());
                }else {
                    entry.info = String.format("Gratuitous ARP for %s (Request)", header.getDstProtocolAddr());
                }

            // check if it is a probe (src_proto == 0 && dst_hard == 0)
            }else if(Arrays.equals(header.getDstHardwareAddr().getAddress(), new byte[header.getHardwareAddrLength()]) &&
                     Arrays.equals(header.getSrcProtocolAddr().getAddress(), new byte[header.getProtocolAddrLength()])) {
                entry.info = String.format("Who has %s? (ARP Probe)", header.getDstProtocolAddr().toString().substring(1));

            // normal arp request
            }else {
                entry.info = String.format("Who has %s? Tell %s", header.getDstProtocolAddr().toString().substring(1), header.getSrcProtocolAddr().toString().substring(1));
            }

        // dissect reply
        }else if(header.getOperation() == ArpOperation.REPLY) {
            if (is_gratuitous) {
                entry.info = String.format("Gratuitous ARP for %s (Reply)", header.getSrcProtocolAddr().toString().substring(1));

            } else {
                entry.info = String.format("%s is at %s", header.getSrcProtocolAddr().toString().substring(1), header.getSrcHardwareAddr());
            }

        } else if(header.getOperation() == ArpOperation.REQUEST_REVERSE ||
                  header.getOperation() == ArpOperation.INARP_REQUEST ||
                  header.getOperation() == ArpOperation.DRARP_REQUEST) {
            entry.info = String.format("Who is %s? Tell %s", header.getDstHardwareAddr().toString(), header.getSrcHardwareAddr().toString());

        } else if(header.getOperation() == ArpOperation.REPLY_REVERSE ||
                header.getOperation() == ArpOperation.DRARP_REPLY) {
            entry.info = String.format("%s is at %s", header.getDstProtocolAddr(), header.getDstHardwareAddr());

        } else if(header.getOperation() == ArpOperation.DRARP_ERROR) {
            entry.info = "DRARP Error";

        } else if(header.getOperation() == ArpOperation.INARP_REPLY) {
            entry.info = String.format("%s is at %s", header.getSrcProtocolAddr().toString().substring(1), header.getSrcHardwareAddr());

        } else if(header.getOperation() == ArpOperation.ARP_NAK) {
            entry.info = "ARP NAK";

            // TODO: All the rest

        }else {
            entry.info = String.format("Unknown ARP opcode 0x%04x", header.getOperation().value());
        }

        entry.textColor = Color.parseColor("#000000");
        entry.backgroundColor = Color.parseColor("#FAF0D7");
    }

}
