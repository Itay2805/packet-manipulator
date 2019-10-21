/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2015  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import java.net.Inet4Address;

import me.itay.pcapproxy.structs.pcap_addr;
import me.itay.pcapproxy.structs.sockaddr;
import me.itay.pcapproxy.structs.sockaddr_in;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.15
 */
public final class PcapIpV4Address extends AbstractPcapAddress {

    private PcapIpV4Address(pcap_addr pcapAddr, short saFamily, String devName) {
        super(pcapAddr, saFamily, devName);
    }

    static PcapIpV4Address newInstance(pcap_addr pcapAddr, short saFamily, String devName) {
        return new PcapIpV4Address(pcapAddr, saFamily, devName);
    }

    @Override
    protected Inet4Address ntoInetAddress(sockaddr sa) {
        sockaddr_in addr = new sockaddr_in(sa);
        return Inets.ntoInetAddress(addr.sin_addr);
    }

    @Override
    public Inet4Address getAddress() {
        return (Inet4Address) super.getAddress();
    }

    @Override
    public Inet4Address getNetmask() {
        return (Inet4Address) super.getNetmask();
    }

    @Override
    public Inet4Address getBroadcastAddress() {
        return (Inet4Address) super.getBroadcastAddress();
    }

    @Override
    public Inet4Address getDestinationAddress() {
        return (Inet4Address) super.getDestinationAddress();
    }
}