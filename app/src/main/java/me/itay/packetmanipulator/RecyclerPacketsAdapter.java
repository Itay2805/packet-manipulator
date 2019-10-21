package me.itay.packetmanipulator;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import me.itay.packetmanipulator.display.PacketEntry;

public class RecyclerPacketsAdapter extends RecyclerView.Adapter<RecyclerPacketsAdapter.ViewHolder> {

    private final List<PacketEntry> entries = new ArrayList<>();
    private final OnClick<PacketEntry> onclick;

    public RecyclerPacketsAdapter(OnClick<PacketEntry> onclick) {
        this.onclick = onclick;
    }

    public void add(PacketEntry entry) {
        synchronized (entries) {
            entries.add(entry);
        }
    }

    public PacketEntry get(int position) {
        synchronized (entries) {
            return entries.get(position);
        }
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.packet_table_entry, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        PacketEntry entry;
        synchronized (entries) {
            entry = entries.get(position);
        }

        holder.lblSource.setText(entry.source);
        holder.lblDestination.setText(entry.destination);
        holder.lblProtocol.setText(entry.protocol);
        holder.lblInfo.setText(entry.info);

        holder.lblSource.setTextColor(entry.textColor);
        holder.lblDestination.setTextColor(entry.textColor);
        holder.lblProtocol.setTextColor(entry.textColor);
        holder.lblInfo.setTextColor(entry.textColor);

        holder.container.setBackgroundColor(entry.backgroundColor);
        holder.container.setOnClickListener((view) -> {
            if(onclick != null) {
                onclick.click(get(position));
            }
        });
    }

    @Override
    public int getItemCount() {
        synchronized (entries) {
            return entries.size();
        }
    }

    public class ViewHolder extends RecyclerView.ViewHolder {

        public final TextView lblSource;
        public final TextView lblDestination;
        public final TextView lblProtocol;
        public final TextView lblInfo;

        public final View container;

        public ViewHolder(@NonNull View itemView) {
            super(itemView);

            this.lblSource = itemView.findViewById(R.id.lblSource);
            this.lblDestination = itemView.findViewById(R.id.lblDestination);
            this.lblProtocol = itemView.findViewById(R.id.lblProtocol);
            this.lblInfo = itemView.findViewById(R.id.lblInfo);
            this.container = itemView.findViewById(R.id.container);
        }
    }

}
