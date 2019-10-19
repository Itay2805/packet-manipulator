/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2014 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet;

import java.util.Arrays;
import org.pcap4j.packet.IpV4InternetTimestampOption.IpV4InternetTimestampOptionData;
import org.pcap4j.util.ByteArrays;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.16
 */
public final class UnknownIpV4InternetTimestampOptionData
    implements IpV4InternetTimestampOptionData {

  /** */
  private static final long serialVersionUID = 2799097946096468081L;

  private final byte[] rawData;

  /**
   * A static factory method. This method validates the arguments by {@link
   * ByteArrays#validateBounds(byte[], int, int)}, which may throw exceptions undocumented here.
   *
   * @param rawData rawData
   * @param offset offset
   * @param length length
   * @return a new UnknownIpV4InternetTimestampOptionData object.
   */
  public static UnknownIpV4InternetTimestampOptionData newInstance(
      byte[] rawData, int offset, int length) {
    ByteArrays.validateBounds(rawData, offset, length);
    return new UnknownIpV4InternetTimestampOptionData(rawData, offset, length);
  }

  private UnknownIpV4InternetTimestampOptionData(byte[] rawData, int offset, int length) {
    this.rawData = new byte[length];
    System.arraycopy(rawData, offset, this.rawData, 0, length);
  }

  @Override
  public int length() {
    return rawData.length;
  }

  @Override
  public byte[] getRawData() {
    byte[] copy = new byte[rawData.length];
    System.arraycopy(rawData, 0, copy, 0, rawData.length);
    return copy;
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("[data: ").append(ByteArrays.toHexString(rawData, "")).append("]");
    return sb.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (!this.getClass().isInstance(obj)) {
      return false;
    }

    UnknownIpV4InternetTimestampOptionData other = (UnknownIpV4InternetTimestampOptionData) obj;
    return Arrays.equals(rawData, other.rawData);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(rawData);
  }
}
