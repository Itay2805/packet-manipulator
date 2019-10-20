package me.itay.packetmanipulator;

import android.graphics.Color;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IcmpV6Type;
import org.pcap4j.util.MacAddress;

import me.itay.packetmanipulator.display.PacketEntry;

public class ColorEngine {

    // TODO: in the future adding a wireshark expression
    //       parser and executer will go a long way, since
    //       it will allow us to take the same rules wireshark
    //       has. in the meanwhile it is pretty much hard coded

    public static void color(PacketEntry entry) {
        Packet packet = entry.original;

        //////////////////
        // Broadcast
        //////////////////
        if(packet.contains(EthernetPacket.class)) {
            EthernetPacket.EthernetHeader header = packet.get(EthernetPacket.class).getHeader();
            if((header.getDstAddr().getAddress()[0] & 1) != 0 ||
               (header.getSrcAddr().getAddress()[0] & 1) != 0) {
                entry.textColor = Color.parseColor("#babdb6");
            }
        }

        //////////////////
        // UDP
        //////////////////
        if(packet.contains(UdpPacket.class)) {
            entry.backgroundColor = Color.parseColor("#daeeff");
            entry.textColor = Color.parseColor("#12272e");
        }

        if(packet.contains(TcpPacket.class)) {
            TcpPacket.TcpHeader header = packet.get(TcpPacket.class).getHeader();

            //////////////////
            // TCP RST
            //////////////////
            if(header.getRst()) {
                entry.backgroundColor = Color.parseColor("#a40000");
                entry.textColor = Color.parseColor("#fffc9c");

            //////////////////
            // TCP SYN/FIN
            //////////////////
            } else if(header.getSyn() || header.getFin()) {
                entry.backgroundColor = Color.parseColor("#a0a0a0");
                entry.textColor = Color.parseColor("#12272e");

            //////////////////
            // TCP
            //////////////////
            }else {
                entry.backgroundColor = Color.parseColor("#e7e6ff");
                entry.textColor = Color.parseColor("#12272e");
            }
        }

        //////////////////
        // ARP
        //////////////////
        if(packet.contains(ArpPacket.class)) {
            entry.backgroundColor = Color.parseColor("#faf0d7");
            entry.textColor = Color.parseColor("#12272e");
        }

        //////////////////
        // ICMP errors
        //////////////////

        if(packet.contains(IcmpV4CommonPacket.class)) {
            IcmpV4CommonPacket.IcmpV4CommonHeader header = packet.get(IcmpV4CommonPacket.class).getHeader();

            if(header.getType() == IcmpV4Type.DESTINATION_UNREACHABLE ||
               header.getType() == IcmpV4Type.SOURCE_QUENCH ||
               header.getType() == IcmpV4Type.REDIRECT ||
               header.getType() == IcmpV4Type.TIME_EXCEEDED) {
                entry.backgroundColor = Color.parseColor("#fce0ff");
                entry.textColor = Color.parseColor("#b7f774");
            }else {
                entry.backgroundColor = Color.parseColor("#fce0ff");
                entry.textColor = Color.parseColor("#12272e");
            }
        }

        if(packet.contains(IcmpV6CommonPacket.class)) {
            IcmpV6CommonPacket.IcmpV6CommonHeader header = packet.get(IcmpV6CommonPacket.class).getHeader();

            if(header.getType() == IcmpV6Type.DESTINATION_UNREACHABLE ||
               header.getType() == IcmpV6Type.PACKET_TOO_BIG ||
               header.getType() == IcmpV6Type.TIME_EXCEEDED ||
               header.getType() == IcmpV6Type.PARAMETER_PROBLEM) {
                entry.backgroundColor = Color.parseColor("#fce0ff");
                entry.textColor = Color.parseColor("#b7f774");
            }else {
                entry.backgroundColor = Color.parseColor("#fce0ff");
                entry.textColor = Color.parseColor("#12272e");
            }
        }
    }

}
