/*_##########################################################################
  _##
  _##  Copyright (C) 2012-2019 Pcap4J.org
  _##
  _##########################################################################
*/

package org.pcap4j.packet.factory;

import android.util.Log;

import java.net.URL;
import java.security.ProtectionDomain;
import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import org.pcap4j.packet.namednumber.NamedNumber;

/**
 * @author Kaito Yamada
 * @since pcap4j 0.9.11
 */
public final class PacketFactories {

    private static final String TAG = "PacketFactories";
    private static final PacketFactoryBinder FACTORY_BINDER;

    static {
        PacketFactoryBinder factoryBinder = null;
        try {
            ServiceLoader<PacketFactoryBinderProvider> loader =
                    ServiceLoader.load(PacketFactoryBinderProvider.class);
            Iterator<PacketFactoryBinderProvider> iter = loader.iterator();
            if (iter.hasNext()) {
                PacketFactoryBinderProvider packetFactoryBinderProvider = iter.next();
                ProtectionDomain pd = packetFactoryBinderProvider.getClass().getProtectionDomain();
                URL codeSrcLocation = null;
                if (pd != null) {
                    codeSrcLocation = pd.getCodeSource().getLocation();
                }
                Log.i(TAG,
                        String.format("A PacketFactoryBinderProvider implementation is found. ClassLoader: %s, URL: %s",
                        packetFactoryBinderProvider.getClass().getClassLoader().toString(),
                        codeSrcLocation));
                factoryBinder = packetFactoryBinderProvider.getBinder();
                Log.i(TAG, "Succeeded in PacketFactoryBinderProvider.getBinder()");
            } else {
                Log.w(TAG,
                        "No PacketFactoryBinder is available. All packets will be captured as UnknownPacket.");
            }
        } catch (ServiceConfigurationError e) {
            Log.w(TAG, e.getClass().getName() + ": " + e.getMessage());
        }
        FACTORY_BINDER = factoryBinder;
    }

    private PacketFactories() {
        throw new AssertionError();
    }

    /**
     * @param <T> target
     * @param <N> number
     * @param targetClass targetClass
     * @param numberClass numberClass
     * @return a {@link org.pcap4j.packet.factory.PacketFactory PacketFactory} object.
     */
    public static <T, N extends NamedNumber<?, ?>> PacketFactory<T, N> getFactory(
            Class<T> targetClass, Class<N> numberClass) {
        if (numberClass == null || targetClass == null) {
            StringBuilder sb = new StringBuilder();
            sb.append("numberClass: ").append(numberClass).append(" targetClass: ").append(targetClass);
            throw new NullPointerException(sb.toString());
        }

        if (FACTORY_BINDER != null) {
            return FACTORY_BINDER.getPacketFactory(targetClass, numberClass);
        } else {
            return SimplePacketFactoryBinder.getInstance().getPacketFactory(targetClass, numberClass);
        }
    }
}