#!/usr/bin/env python3
"""Run the actual Java packaged-profile gate without an Android runtime."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/VpnPacketProfile.java'
TEST = r'''
package com.sakamoto.snort.androidruntime;
import java.io.IOException;
import java.util.Properties;
public final class ProfileTest {
  static Properties profile(String large,String mtu,String mss,String buffer,String virtual) {
    Properties p=new Properties();
    p.setProperty("vpnLargeSegmentExperiment",large); p.setProperty("vpnTunMtu",mtu);
    p.setProperty("vpnTcpMss",mss); p.setProperty("vpnBufferDataBytes",buffer);
    p.setProperty("vpnBufferVirtualOnly",virtual); return p;
  }
  static void reject(Properties p) throws Exception {
    try { VpnPacketProfile.fromManifest(p); throw new AssertionError("profile accepted: "+p); }
    catch(IOException expected) { }
  }
  public static void main(String[] args) throws Exception {
    VpnPacketProfile original=VpnPacketProfile.fromManifest(new Properties());
    assert original.mtu==1500 && original.bufferConfig(0).isEmpty();
    assert original.bufferConfig(512).equals("buffers { buffers-per-numa 512 }\n");
    VpnPacketProfile previous=VpnPacketProfile.fromManifest(profile("ON","3000","2940","3072","OFF"));
    assert previous.mtu==3000 && !previous.virtualOnly;
    VpnPacketProfile large=VpnPacketProfile.fromManifest(profile("ON","10000","9940","10240","ON"));
    assert large.mtu==10000 && large.virtualOnly;
    assert large.bufferConfig(0).equals("buffers { virtual-only buffers-per-numa 2048 default data-size 10240 }\n");
    assert large.bufferConfig(512).contains("buffers-per-numa 512 ");
    VpnPacketProfile control=VpnPacketProfile.fromManifest(profile("ON","3000","2940","10240","ON"));
    assert control.bufferConfig(0).equals(large.bufferConfig(0));
    reject(profile("ON","10000","9940","3072","OFF"));
    reject(profile("ON","10000","9940","10240","OFF"));
    reject(profile("ON","10000","2940","10240","ON"));
    reject(profile("OFF","10000","9940","10240","ON"));
    reject(profile("ON","1500","1360","2048","OFF"));
    reject(profile("ON","10000","9940","10240","yes"));
    reject(profile("ON","10000","9940","10000","ON"));
    reject(profile("ON","8500","8440","10240","ON"));
    reject(profile("ON","n/a","9940","10240","ON"));
    for(int count:new int[]{1,511,513,4097}) {
      try { large.bufferConfig(count); throw new AssertionError("capacity accepted"); }
      catch(IOException expected) { }
    }
    assert !VpnPacketProfile.supportsMtu(9999) && !VpnPacketProfile.supportsMtu(0);
    System.out.println("VPN MTU/profile/storage/capacity agreement PASS");
  }
}
'''
with tempfile.TemporaryDirectory(prefix='vpn-packet-profile-') as folder:
    tmp = Path(folder)
    harness = tmp / 'ProfileTest.java'
    harness.write_text(TEST)
    subprocess.run(['javac', '-d', str(tmp), str(SOURCE), str(harness)], check=True)
    subprocess.run(['java', '-ea', '-cp', str(tmp),
                    'com.sakamoto.snort.androidruntime.ProfileTest'], check=True)
