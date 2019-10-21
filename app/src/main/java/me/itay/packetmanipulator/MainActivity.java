package me.itay.packetmanipulator;

import androidx.appcompat.app.AppCompatActivity;
import me.itay.pcapproxy.PcapProxy;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.Switch;

import com.stericson.RootTools.RootTools;

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.io.File;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    public static final String TAG = "MainActivity";

    @SuppressLint("SetTextI18n")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // get the controls of the current layout
        Spinner spnrInterface = findViewById(R.id.spnrInterface);
        Switch switchPromiscuous = findViewById(R.id.switchPromiscuous);
        Button btnStartSniffer = findViewById(R.id.btnStartSniffer);
        Button btnChooseFile = findViewById(R.id.btnChooseFile);

        // check we have root
        if(!RootTools.isRootAvailable() || !RootTools.isAccessGiven()) {

            Intent intent = new Intent(this, ErrorActivity.class);
            intent.putExtra("EXTRA_ERROR_STRING", "This app requires root in order to run!");
            startActivity(intent);
            finish();

        // we have root!
        }else {

            // initialize the pcap proxy
            try {
                PcapProxy.init(this);
            }catch(Exception e) {
                e.printStackTrace();
                Intent intent = new Intent(this, ErrorActivity.class);
                intent.putExtra("EXTRA_ERROR_STRING", e.getMessage());
                startActivity(intent);
                finish();
            }

            List<PcapNetworkInterface> pifs = Pcaps.findAllDevs();
            List<String> interfaceNames = new ArrayList<>();
            for(PcapNetworkInterface pif : Pcaps.findAllDevs()) {
                StringBuilder sb = new StringBuilder();

                sb.append(pif.getName());

                if(pif.getDescription() != null) {
                    sb.append(" (");
                    sb.append(pif.getDescription());
                    sb.append(")");
                }

                interfaceNames.add(sb.toString());
            }

            // add them to the spinner so the user can choose
            ArrayAdapter<String> adapter = new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item, interfaceNames);
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            spnrInterface.setAdapter(adapter);


            // on button click send us to the SnifferActivity
            btnStartSniffer.setOnClickListener((view) -> {

                // get the interface and send it to the sniffer
                PcapNetworkInterface networkInterface = pifs.get(spnrInterface.getSelectedItemPosition());
                Intent intent = new Intent(this, SnifferActivity.class);
                intent.putExtra("INTERFACE_NAME", networkInterface.getName());
                intent.putExtra("PROMISCUOUS", switchPromiscuous.isChecked());
                intent.putExtra("CAPTURE_TYPE", "live");
                startActivity(intent);

            });

            btnChooseFile.setOnClickListener((view) -> {
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("*/*");
                startActivityForResult(intent, 42);
            });
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent resultData) {
        if (requestCode == 42 && resultCode == Activity.RESULT_OK) {
            Uri uri = null;
            if (resultData != null) {
                uri = resultData.getData();
                assert uri != null;

                File file = new File(uri.getPath());

                Intent intent = new Intent(this, SnifferActivity.class);
                intent.putExtra("PCAP_FILE", uri.getPath());
                intent.putExtra("CAPTURE_TYPE", "offline");
                startActivity(intent);
            }
        }else {
            super.onActivityResult(requestCode, resultCode, resultData);
        }
    }

}
