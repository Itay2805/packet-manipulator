package org.pcap4j.core;

import android.util.Log;

import org.pcap4j.packet.Packet;

import java.io.Closeable;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import me.itay.pcapproxy.PcapProxy;
import me.itay.pcapproxy.PcapProxyException;
import me.itay.pcapproxy.structs.pcap_pkthdr;
import me.itay.pcapproxy.structs.timeval;

public class PcapDumper implements Closeable {

    private static final String TAG = "PcapDumper";

    private final long dumper;
    private final PcapHandle.TimestampPrecision timestampPrecision;
    private final ReentrantReadWriteLock dumperLock = new ReentrantReadWriteLock(true);

    private volatile boolean open = true;

    PcapDumper(long dumper, PcapHandle.TimestampPrecision timestampPrecision) {
        this.timestampPrecision = timestampPrecision;
        this.dumper = dumper;
    }

    public long getDumper() {
        return dumper;
    }

    /** @return true if this PcapDumper is open; false otherwise. */
    public boolean isOpen() {
        return open;
    }

    /**
     * @param packet packet
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public void dump(Packet packet) throws NotOpenException {
        dump(packet, new Timestamp(System.currentTimeMillis()));
    }

    /**
     * @param packet packet
     * @param timestamp timestamp
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public void dump(Packet packet, Timestamp timestamp) throws NotOpenException {
        if (packet == null || timestamp == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("packet: ").append(packet).append(" ts: ").append(timestamp);
            throw new NullPointerException(sb.toString());
        }

        dumpRaw(packet.getRawData(), timestamp);
    }

    /**
     * @param packet packet
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public void dumpRaw(byte[] packet) throws NotOpenException {
        dumpRaw(packet, new Timestamp(System.currentTimeMillis()));
    }

    /**
     * @param packet packet
     * @param timestamp timestamp
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public void dumpRaw(byte[] packet, Timestamp timestamp) throws NotOpenException {
        if (packet == null || timestamp == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("packet: ").append(packet).append(" timestamp: ").append(timestamp);
            throw new NullPointerException(sb.toString());
        }

        if (!open) {
            throw new NotOpenException();
        }

        pcap_pkthdr header = new pcap_pkthdr();
        header.len = header.caplen = packet.length;
        header.ts = new timeval();
        header.ts.tv_sec = timestamp.getTime() / 1000L;
        switch (timestampPrecision) {
            case MICRO:
                header.ts.tv_usec = timestamp.getNanos() / 1000L;
                break;
            case NANO:
                header.ts.tv_usec = timestamp.getNanos();
                break;
            default:
                throw new AssertionError("Never get here.");
        }
        header.data = packet;

        if (!dumperLock.readLock().tryLock()) {
            throw new NotOpenException();
        }
        try {
            if (!open) {
                throw new NotOpenException();
            }
            PcapProxy.get().pcap_dump(dumper, header);
        } finally {
            dumperLock.readLock().unlock();
        }
    }

    /**
     * @throws PcapProxyException if an error occurs in the pcap native library.
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public void flush() throws PcapProxyException, NotOpenException {
        if (!open) {
            throw new NotOpenException();
        }

        int rc;
        if (!dumperLock.readLock().tryLock()) {
            throw new NotOpenException();
        }
        try {
            if (!open) {
                throw new NotOpenException();
            }
            PcapProxy.get().pcap_dump_flush(dumper);
        } finally {
            dumperLock.readLock().unlock();
        }
    }

    /**
     * @return the file position for a "savefile".
     * @throws PcapProxyException if an error occurs in the pcap native library.
     * @throws NotOpenException if this PcapHandle is not open.
     */
    public long ftell() throws PcapProxyException, NotOpenException {
        if (!open) {
            throw new NotOpenException();
        }

        long position;
        if (!dumperLock.readLock().tryLock()) {
            throw new NotOpenException();
        }
        try {
            if (!open) {
                throw new NotOpenException();
            }
            position = PcapProxy.get().pcap_dump_ftell(dumper);
        } finally {
            dumperLock.readLock().unlock();
        }

        if (position < 0) {
            throw new PcapProxyException("Failed to get the file position.");
        }

        return position;
    }

    /** */
    @Override
    public void close() {
        if (!open) {
            Log.w(TAG, "Already closed.");
            return;
        }

        dumperLock.writeLock().lock();
        try {
            if (!open) {
                Log.w(TAG, "Already closed.");
                return;
            }
            open = false;
        } finally {
            dumperLock.writeLock().unlock();
        }

        PcapProxy.get().pcap_dump_close(dumper);
        Log.i(TAG, "Closed.");
    }
}
