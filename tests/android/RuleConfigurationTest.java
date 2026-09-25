import com.sakamoto.snort.androidruntime.RuleConfiguration;

public final class RuleConfigurationTest {
    private static void require(boolean condition) {
        if (!condition) throw new AssertionError();
    }
    public static void main(String[] args) {
        RuleConfiguration.Rule rule = RuleConfiguration.udp(1012632, "127.0.0.1", "192.168.4.22", 32000, 40608, 2);
        require(rule.uid == 1012632 && rule.sourceAddress == 0x7f000001 && rule.destinationAddress == 0xc0a80416);
        for (String invalid : new String[]{"127.1", "127.0.0.256", "0127.0.0.1", "example.test"}) {
            try { RuleConfiguration.ipv4(invalid); throw new AssertionError(invalid); }
            catch (IllegalArgumentException expected) {}
        }
        long[] reply = {0, 9, 3, 2, 0xfedcba9876540002L, 0xfedcba9876540001L,
                4, 0, 4, 1, 1012632, 6, 3, 2, 32000, 40608, 0x7f000001, 0xc0a80416L};
        RuleConfiguration.Status status = new RuleConfiguration.Status(reply);
        require(!status.applied());
        require(status.properties().contains("savedRuleVersion=18364758544493051906\n"));
        require(status.properties().contains("savedRevision=3\nactiveRevision=2\n"));
        reply[3] = 3; reply[5] = reply[4]; reply[6] = 0; reply[8] = 0;
        require(new RuleConfiguration.Status(reply).applied());
        reply[0] = 14;
        require(!new RuleConfiguration.Status(reply).applied());
        long[] full = RuleConfiguration.completeWire("0 0 1012632 4294967295 4294967295 0 0 17 3 2 127.0.0.0/8 127.0.0.2/32 0 65535 40000 41000\n"
                + "18364758544493051906 0 1012632 4294967295 4294967295 1 0 6 1 1 2001:db8::/32 ::1/128 1 65535 443 443");
        require(full.length == 52 && full[0] == 0 && full[26] == 0xfedcba9876540002L);
        require(full[7] == 4 && full[33] == 6 && full[18] == 0x7f000000L);
        long[] mapped = RuleConfiguration.completeWire("0 0 12632 4294967295 4294967295 0 0 6 0 1 ::ffff:192.0.2.1/128 ::ffff:c000:202/128 0 65535 443 443");
        require(mapped[7] == 6 && mapped[20] == 65535 && mapped[21] == 0xc0000201L);
        long[] graph = RuleConfiguration.completeWire("0 0 4294967295 4294967295 4294967295 5 0 17 3 2 0.0.0.0/0 0.0.0.0/0 0 65535 0 65535\n"
                + "group 10\nedge 10 1 0\nbind 7 1012632 2 10 1");
        require(graph.length == 40 && graph[0] == -1 && graph[1] == 1 && graph[2] == 1 && graph[3] == 1 && graph[4] == 1);
        require(graph[31] == 10 && graph[35] == 7 && graph[39] == 1);
        long[] groupedReply = new long[13 + 26 + 1 + 3 + 1 + 3 + 5];
        groupedReply[9] = 1; groupedReply[10] = 1;
        groupedReply[40] = 1; groupedReply[41] = 1; groupedReply[42] = 1;
        System.arraycopy(graph, 31, groupedReply, 43, 9);
        require(new RuleConfiguration.CompleteStatus(groupedReply).properties().contains("binding.0=7,1012632,2,10,1\n"));
        System.out.println("RuleConfiguration: exact inputs, saved/active distinction, unsigned identity, unknown transport");
    }
}
