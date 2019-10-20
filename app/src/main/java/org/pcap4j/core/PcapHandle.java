package org.pcap4j.core;

import android.util.Log;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.factory.PacketFactories;
import org.pcap4j.packet.namednumber.DataLinkType;

import java.io.Closeable;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import me.itay.pcapproxy.PcapProxy;
import me.itay.pcapproxy.PcapProxyException;
import me.itay.pcapproxy.structs.pcap_pkthdr;
import me.itay.pcapproxy.structs.pcap_stat;

public class PcapHandle implements Closeable {

    private static final String TAG = "PcapHandle";

    private volatile DataLinkType dlt;
    private final TimestampPrecision timestampPrecision;
    private final long handle;
    private final ThreadLocal<Timestamp> timestamps = new ThreadLocal<Timestamp>();
    private final ThreadLocal<Integer> originalLengths = new ThreadLocal<Integer>();
    private final ReentrantReadWriteLock handleLock = new ReentrantReadWriteLock(true);
    private static final Object compileLock = new Object();

    private volatile boolean open = true;
    private volatile String filteringExpression = "";

    /**
     * The netmask used for {@link #setFilter(String, BpfProgram.BpfCompileMode, Inet4Address)} or
     * {@link #compileFilter(String, BpfProgram.BpfCompileMode, Inet4Address)} when you don't know
     * what netmask you should use.
     */
    public static final Inet4Address PCAP_NETMASK_UNKNOWN;

    static {
        try {
            PCAP_NETMASK_UNKNOWN = (Inet4Address) InetAddress.getByName("255.255.255.255");
        } catch (UnknownHostException e) {
            throw new AssertionError("never get here");
        }
    }

    PcapHandle(long handle, TimestampPrecision timestampPrecision) {
        this.handle = handle;
        this.dlt = getDltByNative();
        this.timestampPrecision = timestampPrecision;
    }

    private DataLinkType getDltByNative() {
        return DataLinkType.getInstance(PcapProxy.get().pcap_datalink(handle));
    }

    /** @return the Data Link Type of this PcapHandle */
    public DataLinkType getDlt() {
        return dlt;
    }

    // TODO setDlt

    /**
     * @return true if this PcapHandle object is open (i.e. not yet closed by {@link #close()
     *     close()}); false otherwise.
     */
    public boolean isOpen() {
        return open;
    }

    /** @return the filtering expression of this PcapHandle */
    public String getFilteringExpression() {
        return filteringExpression;
    }

    /** @return Timestamp precision */
    public TimestampPrecision getTimestampPrecision() {
        return timestampPrecision;
    }

    // TODO: setDirection

    /** @return the timestamp of the last packet captured by this handle in the current thread. */
    public Timestamp getTimestamp() {
        return timestamps.get();
    }

    /**
     * @return the original length of the last packet captured by this handle in the current thread.
     */
    public Integer getOriginalLength() {
        return originalLengths.get();
    }

    // TODO: getSnapshot

    // TODO: isSwapped

    // TODO: getMajorVersion

    // TODO: getMinorVersion

    // TODO: compileFilter

    // TODO: setFilter

    /**
     * @param mode mode
     * @throws PcapProxyException if an error occurs in the pcap native library.
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public void setBlockingMode(BlockingMode mode) throws PcapProxyException, NotOpenException {
        if (mode == null) {
            StringBuilder sb = new StringBuilder();
            sb.append(" mode: ").append(mode);
            throw new NullPointerException(sb.toString());
        }
        if (!open) {
            throw new NotOpenException();
        }

        if (!handleLock.readLock().tryLock()) {
            throw new NotOpenException();
        }
        try {
            if (!open) {
                throw new NotOpenException();
            }

            PcapProxy.get().pcap_setnonblock(handle, mode.getValue());
        } finally {
            handleLock.readLock().unlock();
        }
    }

    /**
     * @return blocking mode
     * @throws PcapProxyException if an error occurs in the pcap native library.
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public BlockingMode getBlockingMode() throws PcapProxyException, NotOpenException {
        if (!open) {
            throw new NotOpenException();
        }

        int rc;
        if (!handleLock.readLock().tryLock()) {
            throw new NotOpenException();
        }
        try {
            if (!open) {
                throw new NotOpenException();
            }
            rc = PcapProxy.get().pcap_getnonblock(handle);
        } finally {
            handleLock.readLock().unlock();
        }

        if (rc == 0) {
            return BlockingMode.BLOCKING;
        } else if (rc > 0) {
            return BlockingMode.NONBLOCKING;
        } else {
            throw new PcapProxyException();
        }
    }

    /**
     * @return a Packet object created from a captured packet using the packet factory. May be null.
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public Packet getNextPacket() throws NotOpenException {
        byte[] ba = getNextRawPacket();
        if (ba == null) {
            return null;
        }

        return PacketFactories.getFactory(Packet.class, DataLinkType.class)
                .newInstance(ba, 0, ba.length, dlt);
    }

    /**
     * @return a captured packet. May be null.
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public byte[] getNextRawPacket() throws NotOpenException {
        if (!open) {
            throw new NotOpenException();
        }

        if (!handleLock.readLock().tryLock()) {
            throw new NotOpenException();
        }

        pcap_pkthdr header = null;
        try {
            if (!open) {
                throw new NotOpenException();
            }
            header = PcapProxy.get().pcap_next(handle);
        } finally {
            handleLock.readLock().unlock();
        }

        if (header != null) {
            return header.data;
        } else {
            return null;
        }
    }

    // TODO: getNextPacketEx

    // TODO: getNextRawPacketEx

    // TODO: loop

    // TODO: dispatch

    /**
     * @param filePath "-" means stdout. The dlt of the PcapHandle which captured the packets you want
     *     to dump must be the same as this dlt.
     * @return an opened PcapDumper.
     * @throws PcapProxyException if an error occurs in the pcap native library.
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public PcapDumper dumpOpen(String filePath) throws PcapProxyException, NotOpenException {
        if (filePath == null) {
            throw new NullPointerException("filePath must not be null.");
        }
        if (!open) {
            throw new NotOpenException();
        }

        long dumper;
        if (!handleLock.readLock().tryLock()) {
            throw new NotOpenException();
        }
        try {
            if (!open) {
                throw new NotOpenException();
            }

            dumper = PcapProxy.get().pcap_dump_open(handle, filePath);
            if (dumper == 0) {
                throw new PcapProxyException(getError());
            }
        } finally {
            handleLock.readLock().unlock();
        }

        return new PcapDumper(dumper, timestampPrecision);
    }

    // TODO: breakLoop

    // TODO: sendPacket

    /**
     * @return a {@link org.pcap4j.core.PcapStat PcapStat} object.
     * @throws PcapProxyException if an error occurs in the pcap native library.
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public PcapStat getStats() throws PcapProxyException, NotOpenException {
        if (!open) {
            throw new NotOpenException();
        }

        if (!handleLock.readLock().tryLock()) {
            throw new NotOpenException();
        }
        try {
            if (!open) {
                throw new NotOpenException();
            }

            pcap_stat ps = PcapProxy.get().pcap_stats(handle);
            return new PcapStat(ps);
        } finally {
            handleLock.readLock().unlock();
        }
    }

    // TODO: listDatalinks

    /**
     * @return an error message.
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public String getError() throws NotOpenException {
        if (!open) {
            throw new NotOpenException();
        }

        if (!handleLock.readLock().tryLock()) {
            throw new NotOpenException();
        }
        try {
            if (!open) {
                throw new NotOpenException();
            }
            return PcapProxy.get().pcap_geterr(handle);
        } finally {
            handleLock.readLock().unlock();
        }
    }

    @Override
    public void close() throws IOException {
        if(!open) {
            Log.w(TAG, "Already closed");
            return;
        }

        handleLock.writeLock().lock();
        try {
            if(!open) {
                Log.w(TAG, "Already closed");
                return;
            }
            open = false;
        } finally {
            handleLock.writeLock().unlock();
        }

        PcapProxy.get().pcap_close(handle);
        Log.i(TAG, "Closed.");
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(60);

        sb.append("Link type: [")
                .append(dlt)
                .append("] handle: [")
                .append(handle)
                .append("] Open: [")
                .append(open)
                .append("] Filtering Expr: [")
                .append(filteringExpression)
                .append("]");

        return sb.toString();
    }

    // TODO: SimpleExecutor

    // TODO: GotPacketFuncExecutor

    // TODO GotRawPacketFuncExecutor

    // TODO: Builder

    /**
     * @author Kaito Yamada
     * @version pcap4j 0.9.16
     */
    public static enum SwappedType {

        /** */
        NOT_SWAPPED(0),

        /** */
        SWAPPED(1),

        /** */
        MAYBE_SWAPPED(2);

        private final int value;

        private SwappedType(int value) {
            this.value = value;
        }

        /** @return value */
        public int getValue() {
            return value;
        }
    }

    /**
     * @author Kaito Yamada
     * @version pcap4j 0.9.15
     */
    public static enum BlockingMode {

        /** */
        BLOCKING(0),

        /** */
        NONBLOCKING(1);

        private final int value;

        private BlockingMode(int value) {
            this.value = value;
        }

        /** @return value */
        public int getValue() {
            return value;
        }
    }

    /**
     * @author Kaito Yamada
     * @version pcap4j 1.5.1
     */
    public static enum TimestampPrecision {

        /** use timestamps with microsecond precision, default */
        MICRO(0),

        /** use timestamps with nanosecond precision */
        NANO(1);

        private final int value;

        private TimestampPrecision(int value) {
            this.value = value;
        }

        /** @return value */
        public int getValue() {
            return value;
        }
    }

    /**
     * Direction of packets.
     *
     * <pre>
     * typedef enum {
     *   PCAP_D_INOUT = 0,
     *   PCAP_D_IN,
     *   PCAP_D_OUT
     * } pcap_direction_t;
     * </pre>
     *
     * @author Kaito Yamada
     * @version pcap4j 1.6.4
     */
    public static enum PcapDirection {

        /** Both inbound and outbound. */
        INOUT(0),

        /** Inbound only. */
        IN(1),

        /** Outbound only, */
        OUT(2);

        private final int value;

        private PcapDirection(int value) {
            this.value = value;
        }

        /** @return value */
        public int getValue() {
            return value;
        }
    }

}
