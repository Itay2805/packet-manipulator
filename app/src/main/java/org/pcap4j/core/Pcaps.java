/*_##########################################################################
  _##
  _##  Copyright (C) 2011-2019  Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.core;

import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
//import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.Inet4NetworkAddress;
import org.pcap4j.util.MacAddress;

import me.itay.pcapproxy.PcapProxy;
import me.itay.pcapproxy.PcapProxyException;
import me.itay.pcapproxy.structs.pcap_if;

public class Pcaps {

    private static final String TAG = "Pcaps";

    private Pcaps() {
        throw new AssertionError();
    }

    /**
     * Gets all devices.
     *
     * @return a list of PcapNetworkInterfaces.
     * @throws PcapProxyException if an error occurs in the pcap native library.
     */
    public static List<PcapNetworkInterface> findAllDevs() throws PcapProxyException {
        List<PcapNetworkInterface> ifList = new ArrayList<>();

        for(pcap_if pif : PcapProxy.get().pcap_findalldevs()) {
            ifList.add(PcapNetworkInterface.newInstance(pif, true));
        }

        return ifList;
    }

    /**
     * Gets a device by IP address.
     *
     * @param addr addr
     * @return a PcapNetworkInterface.
     * @throws PcapProxyException if an error occurs in the pcap native library.
     */
    public static PcapNetworkInterface getDevByAddress(InetAddress addr) throws PcapProxyException {
        if (addr == null) {
            throw new NullPointerException("addr: " + addr);
        }

        List<PcapNetworkInterface> allDevs = findAllDevs();
        for (PcapNetworkInterface pif : allDevs) {
            for (PcapAddress paddr : pif.getAddresses()) {
                if (paddr.getAddress().equals(addr)) {
                    return pif;
                }
            }
        }

        return null;
    }

    /**
     * Gets a device by name.
     *
     * @param name name
     * @return a PcapNetworkInterface.
     * @throws PcapProxyException if an error occurs in the pcap native library.
     */
    public static PcapNetworkInterface getDevByName(String name) throws PcapProxyException {
        if (name == null) {
            throw new NullPointerException("name: " + name);
        }

        List<PcapNetworkInterface> allDevs = findAllDevs();
        for (PcapNetworkInterface pif : allDevs) {
            if (pif.getName().equals(name)) {
                return pif;
            }
        }

        return null;
    }

    /**
     * @return a name of a network interface.
     * @throws PcapProxyException if an error occurs in the pcap native library.
     */
    public static String lookupDev() throws PcapProxyException {
        return PcapProxy.get().pcap_lookupdev();
    }

    // TODO: lookupNet

    /**
     * @param filePath "-" means stdin
     * @return a new PcapHandle object.
     * @throws PcapProxyException if an error occurs in the pcap native library.
     */
    public static PcapHandle openOffline(String filePath) throws PcapProxyException {
        if (filePath == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("filePath: ").append(filePath);
            throw new NullPointerException(sb.toString());
        }

        long handle = PcapProxy.get().pcap_open_offline(filePath);

        return new PcapHandle(handle, TimestampPrecision.MICRO);
    }

    // TODO: openOffline(String filePath, TimestampPrecision precision)

    // TODO: openDead

    // TODO: compileFilter

    // TODO: datalinkNameToVal

    /**
     * @param error error
     * @return an error message.
     */
    public static String strError(int error) {
        return PcapProxy.get().pcap_strerror(error);
    }

    /**
     * @return a string giving information about the version of the libpcap library being used; note
     *     that it contains more information than just a version number.
     */
    public static String libVersion() {
        return PcapProxy.get().pcap_lib_version();
    }

    /**
     * @param inetAddr Inet4Address or Inet6Address
     * @return a string representation of an InetAddress for BPF.
     */
    public static String toBpfString(InetAddress inetAddr) {
        if (inetAddr == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("inetAddr: ").append(inetAddr);
            throw new NullPointerException(sb.toString());
        }

        String strAddr = inetAddr.toString();
        return strAddr.substring(strAddr.lastIndexOf("/") + 1);
    }

    /**
     * @param macAddr macAddr
     * @return a string representation of a MAC address for BPF.
     */
    public static String toBpfString(MacAddress macAddr) {
        if (macAddr == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("macAddr: ").append(macAddr);
            throw new NullPointerException(sb.toString());
        }

        StringBuilder builder = new StringBuilder();
        byte[] address = macAddr.getAddress();

        for (int i = 0; i < address.length; i++) {
            builder.append(String.format("%02x", address[i]));
            builder.append(":");
        }
        builder.deleteCharAt(builder.length() - 1);

        return builder.toString();
    }

}
