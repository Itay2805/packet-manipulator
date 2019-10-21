package me.itay.pcapproxy.structs;

import me.itay.pcapproxy.DataStream;

public class timeval {

    public long tv_sec;
    public long tv_usec;

    public timeval(DataStream stream) {
        this.tv_sec = stream.readLong();
        this.tv_usec = stream.readLong();
    }

    public timeval() {

    }

    public void write(DataStream stream) {
        stream.writeLong(this.tv_sec);
        stream.writeLong(this.tv_usec);
    }

}
