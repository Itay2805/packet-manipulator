/*_##########################################################################
  _##
  _##  Copyright (C) 2011 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.1
 */
public final class PacketPropertiesLoader {

  /** */
  public static final String PACKET_PROPERTIES_PATH_KEY =
      PacketPropertiesLoader.class.getPackage().getName() + ".properties";

  /** */
  public static final String ICMPV4_CALC_CHECKSUM_KEY =
      PacketPropertiesLoader.class.getPackage().getName() + ".icmpV4.calcChecksumAtBuild";

  /** */
  public static final String ICMPV6_CALC_CHECKSUM_KEY =
      PacketPropertiesLoader.class.getPackage().getName() + ".icmpV6.calcChecksumAtBuild";

  /** */
  public static final String IPV4_CALC_CHECKSUM_KEY =
      PacketPropertiesLoader.class.getPackage().getName() + ".ipV4.calcChecksumAtBuild";

  /** */
  public static final String TCPV4_CALC_CHECKSUM_KEY =
      PacketPropertiesLoader.class.getPackage().getName() + ".tcpV4.calcChecksumAtBuild";

  /** */
  public static final String TCPV6_CALC_CHECKSUM_KEY =
      PacketPropertiesLoader.class.getPackage().getName() + ".tcpV6.calcChecksumAtBuild";

  /** */
  public static final String UDPV4_CALC_CHECKSUM_KEY =
      PacketPropertiesLoader.class.getPackage().getName() + ".udpV4.calcChecksumAtBuild";

  /** */
  public static final String UDPV6_CALC_CHECKSUM_KEY =
      PacketPropertiesLoader.class.getPackage().getName() + ".udpV6.calcChecksumAtBuild";

  /** */
  public static final String SCTP_CALC_CHECKSUM_BY_ADLER32_KEY =
      PacketPropertiesLoader.class.getPackage().getName() + ".sctp.calcChecksumByAdler32";

  private static final PacketPropertiesLoader INSTANCE = new PacketPropertiesLoader();


  private PacketPropertiesLoader() {}

  /** @return the singleton instance of PacketPropertiesLoader. */
  public static PacketPropertiesLoader getInstance() {
    return INSTANCE;
  }

  /** @return a value of the property. */
  public boolean icmpV4CalcChecksum() {
    return true;
  }

  /** @return a value of the property. */
  public boolean icmpV6CalcChecksum() {
    return true;
  }

  /** @return a value of the property. */
  public boolean ipV4CalcChecksum() {
    return true;
  }

  /** @return a value of the property. */
  public boolean tcpV4CalcChecksum() {
    return true;
  }

  /** @return a value of the property. */
  public boolean tcpV6CalcChecksum() {
    return true;
  }

  /** @return a value of the property. */
  public boolean udpV4CalcChecksum() {
    return true;
  }

  /** @return a value of the property. */
  public boolean udpV6CalcChecksum() {
    return true;
  }

  /** @return a value of the property. */
  public boolean sctpCalcChecksumByAdler32() {
    return false;
  }
}
