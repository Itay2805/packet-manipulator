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
import me.itay.pcapproxy.PcapProxy;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Looper;
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
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.Packet;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
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

    private boolean running = true;

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
        String type = getIntent().getStringExtra("CAPTURE_TYPE");
        if(type.equals("live")) {

            // live capture
            String pifName = getIntent().getStringExtra("INTERFACE_NAME");
            pif = Pcaps.getDevByName(pifName);
            Log.d(TAG, pif.toString());

            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS;
            if(getIntent().getBooleanExtra("PROMISCUOUS", false)) {
                mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
            }

            // attempt to open a live capture
            handle = pif.openLive(1500, mode, 0);
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

            // make sure only the needed menu buttons are visible
            updateMenu();


        }else if(type.equals("offline")) {

            // offline capture (from file)
            running = true;
            optionsView.getMenu().findItem(R.id.option_stop).setVisible(false);
            optionsView.getMenu().findItem(R.id.option_start).setVisible(false);
            optionsView.getMenu().findItem(R.id.option_save).setVisible(false);

            String filename = getIntent().getStringExtra("PCAP_FILE");
            handle = Pcaps.openOffline(filename);

            lblInterfaceName.setText("Offline capture");
            lblInterfaceDescription.setText(filename);
        }else {
            assert false;
        }
    }

    private void updateMenu() {
        optionsView.getMenu().findItem(R.id.option_stop).setVisible(running);
        optionsView.getMenu().findItem(R.id.option_start).setVisible(!running);
        optionsView.getMenu().findItem(R.id.option_save).setVisible(!running);
    }

    @Override
    public void run() {
        while(running) {
            try {
                // get a packet
                Packet packet = handle.getNextPacket();

                // have this check just in case we were in the middle
                // of the get while taking the packet
                if(!running) {
                    return;
                }

                // create the entry
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

        stopCapture();
    }

    @SuppressLint("SimpleDateFormat")
    private String getFilename() {
        String path = Environment.getExternalStorageDirectory().getPath() + File.separator + "pcaps" + File.separator;
        File folder = new File(path);
        boolean success = true;
        if (!folder.exists()) {
            success = folder.mkdirs();
        }
        if (success) {
            return path + pif.getName() + "_" + new SimpleDateFormat("yyyy-MM-dd_hh-mm-ss").format(new Date()) + ".pcap";
        } else {
            Log.e(TAG, "Failed to create directory!");
            return null;
        }
    }

    private void stopCapture() {
        running = false;

        // if the capture thread is alive need to stop it
        if(captureThread.isAlive()) {
            try {
                // we are going to try and wait a second for it to exit
                Log.i(TAG, "Waiting a second for the capture to finish");
                captureThread.join(1000);

                // the thread is still alive, hard stop it by interrupting and
                // and restart the pcapproxy (we might have interrupted the thread
                // in the middle of function call which means the stream is in
                // unknown context)
                if(captureThread.isAlive()) {
                    Log.w(TAG, "Failed to wait, killing");
                    captureThread.interrupt();
                    PcapProxy.init(this);
                }else {
                    handle.close();
                }
            } catch (InterruptedException | IOException e) {
                e.printStackTrace();
            }
        }

    }

    @Override
    public boolean onNavigationItemSelected(@NonNull MenuItem menuItem) {
        switch(menuItem.getItemId()) {

            case R.id.option_save:
                // only allow to save when stopped
                if(running) {
                    Toast.makeText(this, "Can not save capture while running", Toast.LENGTH_LONG).show();
                }else {
                    // TODO: Show a progress dialog instead
                    Toast.makeText(this, "Please wait while we are saving the capture", Toast.LENGTH_LONG).show();

                    try {
                        // open a dumper
                        String filename = getFilename();
                        PcapDumper dumper = handle.dumpOpen(filename);

                        // do it in the background
                        new Thread(() -> {
                            int lastP = 0;
                            try {
                                Log.d(TAG, "Starting save");

                                // just go over the packets and add them
                                for(int i = 0; i < adapter.getItemCount(); i++) {
                                    PacketEntry entry = adapter.get(i);
                                    dumper.dump(entry.original);

                                    if((i * 100) / adapter.getItemCount() > lastP) {
                                        // flush every 1% just in case
                                        dumper.flush();
                                    }
                                }

                            } catch (NotOpenException e) {
                                e.printStackTrace();
                            }

                            dumper.close();

                            // set the path in the clipboard
                            ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                            ClipData clip = ClipData.newPlainText("Capture Path", filename);
                            assert clipboard != null;
                            clipboard.setPrimaryClip(clip);

                            // finished!
                            Looper.prepare();
                            Toast.makeText(this, String.format("Saved! Path copied to clipboard"), Toast.LENGTH_LONG).show();
                        }, "CaptureSave").start();

                    } catch (NotOpenException e) {
                        e.printStackTrace();
                    }
                }
                break;

            case R.id.option_close:
                stopCapture();
                finish();
                break;

            case R.id.option_start:
                running = true;
                updateMenu();

                // if the thread is dead wake it up
                if(!captureThread.isAlive()) {
                    captureThread.start();
                }

                break;

            case R.id.option_stop:
                // soft stop
                running = false;
                updateMenu();
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
