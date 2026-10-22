"""Accounting regression checks: IRQ subsets, missing data and counter reset."""
import unittest
import tcp_single_little_analysis as a


def snapshot(ticks, residency, missing=None):
    rows=['PATH /proc/uptime', '10.0 20.0', 'PATH /proc/stat']
    for i in range(8):
        if i != missing:
            # Guest fields must not be added again to the first eight fields.
            rows.append('cpu'+str(i)+' '+' '.join(map(str,[*ticks,999,999])))
    rows+=['PATH /sys/devices/system/cpu/cpu0/cpufreq/stats/time_in_state',
           '300000 '+str(residency[0]),'1803000 '+str(residency[1]),'11.0 21.0']
    return '\n'.join(rows)+'\n'


class Accounting(unittest.TestCase):
    def test_irq_and_softirq_are_busy_subsets_not_extra_cpu(self):
        before=snapshot([0]*8,[0,0])
        after=snapshot([10,0,20,50,5,5,10,0],[1,3])
        result=a.system_cpu(before,after)
        for cpu in result['core_cpu']:
            self.assertEqual(cpu['busy_percent'],45)
            self.assertEqual(cpu['irq_percent'],5)
            self.assertEqual(cpu['softirq_percent'],10)
        self.assertEqual(result['policy0_residency_weighted_khz'],1427250)

    def test_missing_core_is_not_silently_zero(self):
        with self.assertRaisesRegex(ValueError,'missing per-core'):
            a.system_cpu(snapshot([0]*8,[0,0]),snapshot([1]*8,[1,1],missing=4))

    def test_cpu_reset_is_not_a_negative_utilization(self):
        with self.assertRaisesRegex(ValueError,'nonmonotonic'):
            a.system_cpu(snapshot([2]*8,[0,0]),snapshot([1]*8,[1,1]))

    def test_frequency_counter_reset_is_rejected(self):
        with self.assertRaisesRegex(ValueError,'residency'):
            a.system_cpu(snapshot([0]*8,[2,2]),snapshot([1]*8,[1,1]))


if __name__=='__main__':
    unittest.main()
