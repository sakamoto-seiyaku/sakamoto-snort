package com.sakamoto.snort.androidruntime;

import java.io.IOException;
import java.util.Properties;

/** Validated agreement between the packaged native stack and Android TUN. */
final class VpnPacketProfile {
    static final int STANDARD_MTU = 1500;
    static final int LARGE_MTU = 10000;
    static final int VIRTUAL_BUFFER_BYTES = 10240;
    static final int VIRTUAL_BUFFER_COUNT = 2048;

    final int mtu;
    final int bufferBytes;
    final boolean virtualOnly;

    private VpnPacketProfile(int mtu, int bufferBytes, boolean virtualOnly) {
        this.mtu = mtu;
        this.bufferBytes = bufferBytes;
        this.virtualOnly = virtualOnly;
    }

    static boolean supportsMtu(int mtu) {
        return mtu == STANDARD_MTU || mtu == 3000 || mtu == LARGE_MTU;
    }

    static VpnPacketProfile standard() {
        return new VpnPacketProfile(STANDARD_MTU, 2048, false);
    }

    static VpnPacketProfile fromManifest(Properties manifest) throws IOException {
        try {
            String large = manifest.getProperty("vpnLargeSegmentExperiment", "OFF");
            String virtual = manifest.getProperty("vpnBufferVirtualOnly", "OFF");
            if ((!large.equals("ON") && !large.equals("OFF"))
                    || (!virtual.equals("ON") && !virtual.equals("OFF")))
                throw new IOException("invalid packaged VPN packet profile");
            int mtu = Integer.parseInt(manifest.getProperty("vpnTunMtu", "1500"));
            int mss = Integer.parseInt(manifest.getProperty("vpnTcpMss", "1360"));
            int buffer = Integer.parseInt(manifest.getProperty("vpnBufferDataBytes", "2048"));
            boolean virtualOnly = virtual.equals("ON");
            if (!supportsMtu(mtu) || large.equals("ON") != (mtu != STANDARD_MTU)
                    || mss != (mtu == STANDARD_MTU ? 1360 : mtu - 60)
                    || (buffer != 2048 && buffer != 3072 && buffer != VIRTUAL_BUFFER_BYTES)
                    || buffer <= mtu || virtualOnly != (buffer == VIRTUAL_BUFFER_BYTES))
                throw new IOException("packaged VPN MTU/MSS/buffer profile disagrees");
            return new VpnPacketProfile(mtu, buffer, virtualOnly);
        } catch (NumberFormatException error) {
            throw new IOException("invalid packaged VPN packet profile number", error);
        }
    }

    String bufferConfig(int validationBuffers) throws IOException {
        if (validationBuffers != 0 && (validationBuffers < 512 || validationBuffers > 4096
                || validationBuffers % 32 != 0))
            throw new IOException("invalid native buffer validation capacity");
        int count = validationBuffers != 0 ? validationBuffers
                : virtualOnly ? VIRTUAL_BUFFER_COUNT : 0;
        if (count == 0 && bufferBytes == 2048) return "";
        return "buffers { " + (virtualOnly ? "virtual-only " : "")
                + (count == 0 ? "" : "buffers-per-numa " + count + " ")
                + (bufferBytes == 2048 ? "" : "default data-size " + bufferBytes + " ")
                + "}\n";
    }
}
