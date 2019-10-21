package me.itay.packetmanipulator;

import androidx.annotation.NonNull;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.ActionBarDrawerToggle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.GravityCompat;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import me.itay.packetmanipulator.display.PacketEntry;
import me.itay.packetmanipulator.display.PacketDissector;

import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.navigation.NavigationView;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.Packet;

import java.io.IOException;
import java.util.concurrent.ConcurrentLinkedQueue;

public class SnifferActivity extends AppCompatActivity implements Runnable, NavigationView.OnNavigationItemSelectedListener {

    private static final String TAG = "SnifferActivity";

    private PcapNetworkInterface pif;
    private PcapHandle handle;
    private boolean autoScroll = true;

    private Thread captureThread;
    private ConcurrentLinkedQueue<Packet> packets = new ConcurrentLinkedQueue<>();

    private Toolbar toolbar;
    private DrawerLayout drawer;
    private NavigationView optionsView;
    private TextView lblInterfaceName;
    private TextView lblInterfaceDescription;

    private Button btnSetFilter;
    private EditText txtFilterExpression;
    private RecyclerView recyclerPackets;
    private RecyclerPacketsAdapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // set layout and get controls
        setContentView(R.layout.sniffer_activity);

        /////////////////////////////////////////////////////////////////
        // get the controls
        /////////////////////////////////////////////////////////////////
        toolbar = findViewById(R.id.toolbar);
        drawer = findViewById(R.id.sniffer_drawer);
        optionsView = findViewById(R.id.options_view);
        setSupportActionBar(toolbar);

        View headerView = optionsView.getHeaderView(0);
        lblInterfaceName = headerView.findViewById(R.id.lblInterfaceName);
        lblInterfaceDescription = headerView.findViewById(R.id.lblInterfaceDescription);
        optionsView.setNavigationItemSelectedListener(this);
        optionsView.setCheckedItem(R.id.option_auto_scroll);

        btnSetFilter = findViewById(R.id.btnSetFilter);
        txtFilterExpression = findViewById(R.id.txtFilterExpression);
        recyclerPackets = findViewById(R.id.recyclerPackets);
        adapter = new RecyclerPacketsAdapter((entry) -> {
            new PacketInfoBottomSheet(entry.original.toString()).show(getSupportFragmentManager(), TAG);
        });
        recyclerPackets.setAdapter(adapter);
        recyclerPackets.setLayoutManager(new LinearLayoutManager(this));

        /////////////////////////////////////////////////////////////////
        // get the device
        /////////////////////////////////////////////////////////////////
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

        /////////////////////////////////////////////////////////////////
        // finish setting the layout
        /////////////////////////////////////////////////////////////////

        // set the interface info
        lblInterfaceName.setText(String.format("%s (%s)", pif.getName(), handle.getDlt().name()));
        if(pif.getDescription() != null) {
            lblInterfaceDescription.setText(pif.getDescription());
        }else {
            lblInterfaceDescription.setText("No description");
        }
    }

    @Override
    public void run() {
        while(true) {
            try {
                // get a packet and create the entry
                Packet packet = handle.getNextPacket();
                PacketEntry entry = new PacketEntry();
                entry.original = packet;
                entry.protocol = packet.getClass().toString();
                entry.info = packet.toString();

                // transform it if possible
                Packet current = packet;
                while(current != null) {
                    if(current instanceof PacketDissector) {
                        if(((PacketDissector) current).dissect(entry)) {
                            break;
                        }
                    }
                    current = current.getPayload();
                }

                ColorEngine.color(entry);

                // add to adapter
                adapter.add(entry);
                recyclerPackets.post(() -> {
                    adapter.notifyDataSetChanged();

                    if(autoScroll) {
                        recyclerPackets.scrollToPosition(adapter.getItemCount() - 1);
                    }
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

    @Override
    public boolean onNavigationItemSelected(@NonNull MenuItem menuItem) {
        switch(menuItem.getItemId()) {

            case R.id.option_save:
                if(handle.isOpen()) {
                    Toast.makeText(this, "Can not save capture while running", Toast.LENGTH_LONG).show();
                }else {

                }
                break;

            case R.id.option_auto_scroll:
                autoScroll = !autoScroll;
                menuItem.setChecked(autoScroll);
                break;

            case R.id.option_go_to_first:
                recyclerPackets.scrollToPosition(0);
                break;

            case R.id.option_go_to_last:
                recyclerPackets.scrollToPosition(adapter.getItemCount() - 1);
                break;

            default:
                return false;
        }

        drawer.closeDrawer(GravityCompat.END);
        return true;
    }

    @Override
    public void onBackPressed() {
        if(drawer.isDrawerOpen(GravityCompat.END)) {
            drawer.closeDrawer(GravityCompat.END);
        }else {
            super.onBackPressed();
        }
    }
}
