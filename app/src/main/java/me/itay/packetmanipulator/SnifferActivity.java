package me.itay.packetmanipulator;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import java.io.IOException;

public class SnifferActivity extends AppCompatActivity {

    private static final String TAG = "SnifferActivity";

    private PcapNetworkInterface pif;
    private PcapHandle handle;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sniffer);

        // get the controls
        TextView txtError = findViewById(R.id.txtError);

        // get the error and set it
        String pifName = getIntent().getStringExtra("INTERFACE_NAME");

        pif = Pcaps.getDevByName(pifName);
        assert pif != null;

        Log.d(TAG, pif.toString());

        // attempt to open a live capture
        handle = pif.openLive(1500, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 0);
        Log.d(TAG, handle.toString());

        try {
            Packet packet = handle.getNextPacket();
            Log.d(TAG, packet.toString());
        } catch (NotOpenException e) {
            e.printStackTrace();
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
