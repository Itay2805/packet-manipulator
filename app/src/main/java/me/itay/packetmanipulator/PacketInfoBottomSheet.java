package me.itay.packetmanipulator;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class PacketInfoBottomSheet extends BottomSheetDialogFragment {

    private final String text;
    private TextView lblPacketInfo;

    public PacketInfoBottomSheet(String text) {
        this.text = text;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        View v = inflater.inflate(R.layout.sniffer_packet_info_bottom_sheet, container, false);

        lblPacketInfo = v.findViewById(R.id.lblPacketInfo);
        lblPacketInfo.setText(text);

        return v;
    }

}
