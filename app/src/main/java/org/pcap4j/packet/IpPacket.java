/*_##########################################################################
  _##
  _##  Copyright (C) 2016  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.net.InetAddress;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;

import me.itay.packetmanipulator.display.PacketDissector;
import me.itay.packetmanipulator.display.PacketEntry;

/**
 * The interface representing an IP packet.
 *
 * @author Kaito Yamada
 * @since pcap4j 1.7.0
 */
public interface IpPacket extends Packet, PacketDissector {

    @Override
    public IpHeader getHeader();

    /**
     * The interface representing an IP packet's header.
     *
     * @author Kaito Yamada
     * @since pcap4j 1.7.0
     */
    public interface IpHeader extends Header {

        /** @return version */
        public IpVersion getVersion();

        /** @return an IpNumber object which indicates the protocol of the following header. */
        public IpNumber getProtocol();

        /** @return srcAddr */
        public InetAddress getSrcAddr();

        /** @return dstAddr */
        public InetAddress getDstAddr();
    }

    default boolean dissect(PacketEntry entry) {
        IpHeader header = getHeader();
        entry.protocol = header.getVersion().name();
        entry.source = header.getSrcAddr().getHostAddress();
        entry.destination = header.getDstAddr().getHostAddress();
        entry.info = header.getProtocol().toString();
        return false;
    }
}
