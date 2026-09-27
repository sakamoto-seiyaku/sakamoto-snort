// Test-only real socket driver. It contains no policy or observation logic.
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;

public final class T23Probe {
    private static String hex(byte[] data) {
        StringBuilder out = new StringBuilder();
        for (byte value : data) out.append(String.format("%02x", value & 255));
        return out.toString();
    }
    private static DatagramSocket open(InetAddress local, int port, InetAddress peer, int destination) throws Exception {
        DatagramSocket socket = new DatagramSocket(null);
        socket.bind(new InetSocketAddress(local, port));
        socket.connect(peer, destination); socket.setSoTimeout(750);
        return socket;
    }
    public static void main(String[] args) throws Exception {
        InetAddress peer = InetAddress.getByName(args[0]);
        int destination = Integer.parseInt(args[1]), source = Integer.parseInt(args[2]);
        InetAddress local = InetAddress.getByName(args[3]);
        ArrayList<DatagramSocket> sockets = new ArrayList<>();
        int sequence = 0;
        try {
            for (int i=0; i<128; i++) sockets.add(open(local, source+i, peer, destination));
            System.out.println(new JSONObject().put("ready", true).put("source", source)
                .put("pid", android.os.Process.myPid()).put("uid", android.os.Process.myUid()));
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            for (String line; (line=input.readLine()) != null;) {
                JSONObject command = new JSONObject(line);
                if (command.optBoolean("quit")) break;
                int count=command.getInt("count"), size=command.optInt("size",64);
                if (count<0 || count>4096 || size<32 || size>1024) throw new IllegalArgumentException("bounds");
                long began=System.nanoTime(); JSONArray rows=new JSONArray(); int received=0;
                for (int i=0; i<count; i++) {
                    boolean shortSocket=command.optBoolean("short");
                    DatagramSocket socket=shortSocket ? open(local,source+128+i,peer,destination)
                        : sockets.get(i % command.optInt("sockets",1));
                    byte[] payload=new byte[size]; Arrays.fill(payload,(byte)'x');
                    byte[] id=MessageDigest.getInstance("SHA-256").digest((command.getString("nonce")+":"+sequence).getBytes(StandardCharsets.UTF_8));
                    System.arraycopy(id,0,payload,0,id.length); sequence++;
                    long start=System.nanoTime(), wall=System.currentTimeMillis()*1000000L;
                    socket.send(new DatagramPacket(payload,payload.length)); boolean echoed=false;
                    try {
                        while (System.nanoTime()-start<750000000L) {
                            DatagramPacket reply=new DatagramPacket(new byte[2048],2048); socket.receive(reply);
                            if (Arrays.equals(payload,Arrays.copyOf(reply.getData(),reply.getLength()))) { echoed=true; received++; break; }
                        }
                    } catch (SocketTimeoutException missing) { }
                    rows.put(new JSONObject().put("id",sequence-1).put("sentMonoNs",start).put("sentUtcNs",wall)
                        .put("endMonoNs",System.nanoTime()).put("sourcePort",socket.getLocalPort())
                        .put("payload",hex(payload)).put("echoed",echoed));
                    if (shortSocket) socket.close();
                    if (command.optInt("delayMs")>0) Thread.sleep(command.getInt("delayMs"));
                }
                System.out.println(new JSONObject().put("label",command.getString("label"))
                    .put("startedMonoNs",began).put("completedMonoNs",System.nanoTime())
                    .put("sent",count).put("received",received).put("exchanges",rows));
            }
        } finally { for (DatagramSocket socket:sockets) socket.close(); }
    }
}
