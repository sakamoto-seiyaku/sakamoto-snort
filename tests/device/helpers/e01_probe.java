    // E01 experimental workload overlay only; not a Product capability.
    private static void e01(Context app, JSONObject plan, JSONObject result, String nonce,
            InetAddress endpoint, InetAddress local, int source, int port) throws Exception {
        java.util.ArrayList<DatagramSocket> sockets = new java.util.ArrayList<>();
        int sequence = 0;
        try {
            for (int i = 0; i < 128; ++i) {
                DatagramSocket socket = new DatagramSocket(null);
                socket.bind(new InetSocketAddress(local, source + i));
                socket.connect(endpoint, port); socket.setSoTimeout(1000); sockets.add(socket);
            }
            String[] phases = {"idle", "low", "burst", "sustained", "active", "short", "pause"};
            int pauseFlows = plan.optInt("e01PauseFlows", 1024);
            if (pauseFlows < 1 || pauseFlows > 1024) throw new IllegalArgumentException("E01 pause bound");
            int[] counts = {0, 20, 256, 1000, 512, 128, pauseFlows};
            gate(app, nonce, result, "e01_ready");
            for (int phase = 0; phase < phases.length; ++phase) {
                long started = System.nanoTime();
                org.json.JSONArray exchanges = new org.json.JSONArray();
                int sent = 0, received = 0;
                if (phase == 0) Thread.sleep(10000);
                for (int i = 0; i < counts[phase]; ++i) {
                    DatagramSocket socket = sockets.get(phase == 4 || phase == 6 ? i % 128 : 0);
                    boolean shortSocket = phase == 5 || phase == 6;
                    if (shortSocket) {
                        socket = new DatagramSocket(null);
                        socket.bind(new InetSocketAddress(local, source + (phase == 6 ? 256 : 128) + i));
                        socket.connect(endpoint, port); socket.setSoTimeout(1000);
                    }
                    byte[] payload = Arrays.copyOf((String.format(java.util.Locale.ROOT,
                        "%08d:", sequence++) + nonce).getBytes(StandardCharsets.US_ASCII), 64);
                    long begin = System.nanoTime();
                    socket.send(new DatagramPacket(payload, payload.length)); ++sent;
                    boolean echoed = false;
                    try {
                        DatagramPacket reply = new DatagramPacket(new byte[256], 256);
                        socket.receive(reply);
                        echoed = Arrays.equals(payload, Arrays.copyOf(reply.getData(), reply.getLength()));
                        if (echoed) ++received;
                    } catch (java.net.SocketTimeoutException missing) { }
                    exchanges.put(new JSONObject().put("id", sequence-1).put("sentMonoNs", begin)
                        .put("endMonoNs", System.nanoTime()).put("echoed", echoed)
                        .put("sourcePort", socket.getLocalPort()).put("payload", toHex(payload)));
                    if (shortSocket) socket.close();
                    if (phase == 1) Thread.sleep(100);
                    if (phase == 3) Thread.sleep(2);
                }
                result.put("e01", new JSONObject().put("name", phases[phase])
                    .put("startedMonoNs", started).put("completedMonoNs", System.nanoTime())
                    .put("sent", sent).put("received", received).put("exchanges", exchanges));
                gate(app, nonce, result, "e01_" + phases[phase]);
            }
        } finally {
            for (DatagramSocket socket : sockets) socket.close();
        }
    }
