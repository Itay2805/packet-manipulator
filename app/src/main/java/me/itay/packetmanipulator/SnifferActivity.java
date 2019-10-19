package me.itay.packetmanipulator;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import me.itay.packetmanipulator.display.PacketEntry;
import me.itay.packetmanipulator.display.PacketEntryTransfomer;
import me.itay.packetmanipulator.display.impl.EthernetTransfomer;

import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TextView;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Locale;
import java.util.Queue;
import java.util.Stack;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;

public class SnifferActivity extends AppCompatActivity implements Runnable {

    private static final String TAG = "SnifferActivity";

    // register all transfomers
    private static HashMap<Class<?>, PacketEntryTransfomer> transfomers = new HashMap<>();
    static {
        transfomers.put(EthernetPacket.class, new EthernetTransfomer());
    }


    private PcapNetworkInterface pif;
    private PcapHandle handle;

    private Thread captureThread;
    private ConcurrentLinkedQueue<Packet> packets = new ConcurrentLinkedQueue<>();

    private Button btnSetFilter;
    private EditText txtFilterExpression;
    private RecyclerView recyclerPackets;
    private RecyclerPacketsAdapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // set layout and get controls
        setContentView(R.layout.activity_sniffer);
        btnSetFilter = findViewById(R.id.btnSetFilter);
        txtFilterExpression = findViewById(R.id.txtFilterExpression);
        recyclerPackets = findViewById(R.id.recyclerPackets);
        adapter = new RecyclerPacketsAdapter();

        recyclerPackets.setAdapter(adapter);
        recyclerPackets.setLayoutManager(new LinearLayoutManager(this));

        // get the device
        String pifName = getIntent().getStringExtra("INTERFACE_NAME");
        pif = Pcaps.getDevByName(pifName);
        assert pif != null;
        Log.d(TAG, pif.toString());

        // attempt to open a live capture
        // TODO: Pass PROMISCOUS in an extra of the intent
        handle = pif.openLive(1500, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 0);
        Log.d(TAG, handle.toString());

        // start the capturing thread
        captureThread = new Thread(this, "SnifferActivityCapture");
        captureThread.start();

    }

    @Override
    public void run() {
        while(true) {
            try {
                // get a packet and create the entry
                Packet packet = handle.getNextPacket();
                PacketEntry entry = new PacketEntry();
                entry.original = packet;
                entry.length = Integer.toString(packet.length());

                // transform it if possible
                Packet current = packet;
                while(current != null) {
                    PacketEntryTransfomer transfomer = transfomers.get(current.getClass());
                    if(transfomer != null) {
                        transfomer.transformEntry(current, entry);
                    }
                    current = current.getPayload();
                }

                // add to adapter
                adapter.add(entry);
                recyclerPackets.post(() -> {
                    adapter.notifyDataSetChanged();
                    recyclerPackets.scrollToPosition(adapter.getItemCount());
                });
            } catch (NotOpenException e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();

        try {
            handle.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
