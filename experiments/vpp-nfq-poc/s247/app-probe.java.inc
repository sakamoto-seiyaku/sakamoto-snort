                    int burst = 1, stopOverlap = 0;
                    try (java.util.Scanner config = new java.util.Scanner(new File(getFilesDir(), "s247-config"))) {
                        config.nextInt(); config.nextInt(); burst = config.nextInt(); stopOverlap = config.nextInt();
                    }
                    try (DatagramSocket socket = new DatagramSocket()) {
                        socket.setSoTimeout(4000);
                        int total = burst > 1 ? 4 : (stopOverlap != 0 ? 2 : 3);
                        int sequence = 1;
                        while (sequence <= total) {
                            int batch = sequence == 1 ? burst : 1;
                            for (int offset = 0; offset < batch; offset++) {
                                int id = sequence + offset;
                                byte[] expected = ("s245-payload-" + id).getBytes(StandardCharsets.US_ASCII);
                                socket.send(new DatagramPacket(expected, expected.length, destination, port));
                                appendProbeLog(new File(getFilesDir(), "logs/s247-app.log"),
                                    "s247 event=app_send seq=" + id + " bytes=" + expected.length + " local_port=" + socket.getLocalPort());
                            }
                            boolean[] receivedIds = new boolean[total + 1];
                            long deadline = android.os.SystemClock.elapsedRealtime() + 4000;
                            int receivedCount = 0;
                            while (receivedCount < batch && android.os.SystemClock.elapsedRealtime() < deadline) {
                                socket.setSoTimeout((int)Math.max(1, deadline - android.os.SystemClock.elapsedRealtime()));
                                byte[] reply = new byte[256];
                                DatagramPacket response = new DatagramPacket(reply, reply.length);
                                try {
                                    socket.receive(response);
                                } catch (java.net.SocketTimeoutException timeout) { break; }
                                String replyText = new String(reply, 0, response.getLength(), StandardCharsets.US_ASCII);
                                boolean exact = false;
                                for (int id = sequence; id < sequence + batch; id++) {
                                    if (replyText.equals("s245-payload-" + id) && !receivedIds[id]) {
                                        receivedIds[id] = true; receivedCount++; exact = true; break;
                                    }
                                }
                                appendProbeLog(new File(getFilesDir(), "logs/s247-app.log"),
                                    "s247 event=app_receive result=" + (exact ? "EXACT" : "MISMATCH") + " payload=" + replyText);
                            }
                            for (int id = sequence; id < sequence + batch; id++)
                                appendProbeLog(new File(getFilesDir(), "logs/s247-app.log"),
                                    "s247 event=app_result seq=" + id + " result=" + (receivedIds[id] ? "EXACT" : "TIMEOUT") +
                                    " local_port=" + socket.getLocalPort());
                            sequence += batch;
                            Thread.sleep(350L);
                        }
                        appendProbeLog(new File(getFilesDir(), "logs/s247-app.log"), "s247 event=app_done packets=" + total);
                        result = "S247_RECORDED";
                    }
