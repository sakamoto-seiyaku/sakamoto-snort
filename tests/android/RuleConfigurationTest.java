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
        System.out.println("RuleConfiguration: exact inputs, saved/active distinction, unsigned identity, unknown transport");
    }
}
