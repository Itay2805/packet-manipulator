package me.itay.pcapproxy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class DataStream {

    private InputStream in;
    private OutputStream out;

    public DataStream(InputStream in, OutputStream out) {
        this.in = in;
        this.out = out;
    }

    public void checkErr() {
        if(!readBool()) {
            throw new PcapProxyException(readString());
        }
    }

    public boolean readBool() {
        try {
            return in.read() > 0;
        } catch (IOException e) {
            e.printStackTrace();
            throw new PcapProxyException();
        }
    }

    public void readBytes(byte[] bytes) {
        try {
            if(in.read(bytes) != bytes.length) {
                throw new PcapProxyException();
            }
        } catch (IOException e) {
            e.printStackTrace();
            throw new PcapProxyException();
        }
    }

    public void writeBytes(byte[] bytes) {
        try {
            out.write(bytes);
        } catch (IOException e) {
            e.printStackTrace();
            throw new PcapProxyException();
        }
    }


    public short readShort() {
        byte[] bytes = new byte[2];

        try {
            if(in.read(bytes) != 2) {
                throw new PcapProxyException();
            }
        } catch (IOException e) {
            e.printStackTrace();
            throw new PcapProxyException();
        }

        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.order(ByteOrder.nativeOrder());
        return buffer.getShort();
    }

    public int readInt() {
        byte[] bytes = new byte[4];

        try {
            if(in.read(bytes) != 4) {
                throw new PcapProxyException();
            }
        } catch (IOException e) {
            e.printStackTrace();
            throw new PcapProxyException();
        }

        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.order(ByteOrder.nativeOrder());
        return buffer.getInt();
    }

    public long readLong() {
        byte[] bytes = new byte[8];

        try {
            if(in.read(bytes) != 8) {
                throw new PcapProxyException();
            }
        } catch (IOException e) {
            e.printStackTrace();
            throw new PcapProxyException();
        }

        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        buffer.order(ByteOrder.nativeOrder());
        return buffer.getLong();
    }

    public void writeInt(int t) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.order(ByteOrder.nativeOrder());
        buffer.putInt(t);
        try {
            out.write(buffer.array(), buffer.arrayOffset(), 4);
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
            throw new PcapProxyException();
        }
    }

    public void writeLong(long t) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.nativeOrder());
        buffer.putLong(t);
        try {
            out.write(buffer.array(), buffer.arrayOffset(), 8);
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
            throw new PcapProxyException();
        }
    }

    public String readString() {
        int length = readInt();

        if(length == 0) {
            return null;
        }

        byte[] bytes = new byte[length];

        try {
            if(in.read(bytes) != length) {
                throw new PcapProxyException();
            }
        } catch (IOException e) {
            e.printStackTrace();
            throw new PcapProxyException();
        }

        return new String(bytes);
    }

    public void writeString(String str) {
        writeInt(str.getBytes().length);
        try {
            out.write(str.getBytes());
            out.flush();
        } catch (IOException e) {
            e.printStackTrace();
            throw new PcapProxyException();
        }
    }

    public void readArray(Runnable iter) {
        int count = readInt();
        for(int i = 0; i < count; i++) {
            iter.run();
        }
    }

    public void writeArray(int count, Runnable iter) {
        writeInt(count);
        for(int i = 0; i < count; i++) {
            iter.run();
            try {
                out.flush();
            } catch (IOException e) {
                e.printStackTrace();
                throw new PcapProxyException();
            }
        }
    }

}
