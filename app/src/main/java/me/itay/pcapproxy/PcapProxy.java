package me.itay.pcapproxy;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import me.itay.pcapproxy.structs.pcap_if;
import me.itay.pcapproxy.structs.pcap_pkthdr;
import me.itay.pcapproxy.structs.pcap_stat;

public class PcapProxy {

    // function ids

    private static final int PCAP_LIB_VERSION = 1;
    private static final int PCAP_FINDALLDEVS = 2;
    private static final int PCAP_OPEN_LIVE = 3;
    private static final int PCAP_CLOSE = 4;
    private static final int PCAP_DATALINK = 5;
    private static final int PCAP_NEXT = 6;
    private static final int PCAP_SETNONBLOCK = 7;
    private static final int PCAP_GETNONBLOCK = 8;
    private static final int PCAP_LOOKUPDEV = 9;
    private static final int PCAP_STRERROR = 10;
    private static final int PCAP_GETERR = 11;
    private static final int PCAP_STATS = 12;

    // global instance

    private static PcapProxy instance;

    public static PcapProxy get() {
        assert instance != null;
        return instance;
    }

    public static void init(Context context) {
        instance = new PcapProxy(context);
        Log.i("PcapProxy", String.format("successfully loaded the native pcap library: %s", instance.pcap_lib_version()));
    }

    // actual implementation

    private DataStream stream;
    private Process process;

    private Thread logger_thread;
    private InputStream logger_stream;

    public PcapProxy(Context context) {
        try {
            // TODO: Use root tools maybe?
            process = Runtime.getRuntime().exec(new String[] { "su", "-c", String.format("%s/libpcapproxy.so", context.getApplicationInfo().nativeLibraryDir) });
            stream = new DataStream(process.getInputStream(), process.getOutputStream());

            logger_stream = process.getErrorStream();
            logger_thread = new Thread(() -> {
                StringBuilder sb = new StringBuilder();
                while(true) {
                    int b = 0;

                    try {
                        b = logger_stream.read();
                    } catch (IOException e) {
                        e.printStackTrace();
                        break;
                    }

                    if(b == -1) {
                        Log.w("PcapProxyLogger", "stderr closed! stopping logger");
                        break;
                    }

                    if(b == 10) {
                        Log.d("PcapProxyLogger", sb.toString());
                        sb = new StringBuilder();
                    }else {
                        sb.append((char)b);
                    }
                }

                if(!sb.toString().isEmpty()) {
                    Log.d("PcapProxyLogger", sb.toString());
                }
            }, "PcapProxyLogger");

            logger_thread.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String pcap_lib_version() {
        stream.writeInt(PCAP_LIB_VERSION);
        return stream.readString();
    }

    public List<pcap_if> pcap_findalldevs() {
        stream.writeInt(PCAP_FINDALLDEVS);
        stream.checkErr();

        List<pcap_if> devices = new ArrayList<>();
        stream.readArray(() -> devices.add(new pcap_if(stream)));

        return devices;
    }

    public long pcap_open_live(String device, int spanlen, int promisc, int to_ms) {
        stream.writeInt(PCAP_OPEN_LIVE);
        stream.writeString(device);
        stream.writeInt(spanlen);
        stream.writeInt(promisc);
        stream.writeInt(to_ms);

        stream.checkErr();
        return stream.readLong();
    }

    public void pcap_close(long handle) {
        stream.writeInt(PCAP_CLOSE);
        stream.writeLong(handle);
    }

    public int pcap_datalink(long handle) {
        stream.writeInt(PCAP_DATALINK);
        stream.writeLong(handle);
        return stream.readInt();
    }

    public pcap_pkthdr pcap_next(long handle) {
        stream.writeInt(PCAP_NEXT);
        stream.writeLong(handle);

        if(stream.readBool()) {
            return new pcap_pkthdr(stream);
        }else {
            return null;
        }
    }

    public void pcap_setnonblock(long p, int nonblock) {
        stream.writeInt(PCAP_SETNONBLOCK);
        stream.writeLong(p);
        stream.writeInt(nonblock);

        stream.checkErr();
    }

    public int pcap_getnonblock(long p) {
        stream.writeInt(PCAP_GETNONBLOCK);
        stream.writeLong(p);

        stream.checkErr();
        return stream.readInt();
    }

    public String pcap_lookupdev() {
        stream.writeInt(PCAP_LOOKUPDEV);
        stream.checkErr();
        return stream.readString();
    }

    public String pcap_strerror(int error) {
        stream.writeInt(PCAP_STRERROR);
        stream.writeInt(error);
        return stream.readString();
    }

    public String pcap_geterr(long handle) {
        stream.writeInt(PCAP_GETERR);
        stream.writeLong(handle);
        return stream.readString();
    }

    public pcap_stat pcap_stats(long handle) {
        stream.writeInt(PCAP_STATS);
        stream.writeLong(handle);
        return new pcap_stat(stream);
    }

}
