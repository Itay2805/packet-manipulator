package me.itay.packetmanipulator;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import me.itay.packetmanipulator.display.PacketEntry;
import me.itay.packetmanipulator.display.PacketDissector;

import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.EditText;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import java.io.IOException;
import java.util.concurrent.ConcurrentLinkedQueue;

public class SnifferActivity extends AppCompatActivity implements Runnable {

    private static final String TAG = "SnifferActivity";

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

                // transform it if possible
                Packet current = packet;
                while(current != null) {
                    if(current instanceof PacketDissector) {
                        ((PacketDissector) current).dissect(entry);
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
