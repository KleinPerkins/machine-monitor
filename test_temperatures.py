import ctypes
import json
import unittest
from temperatures import CPU_KEYS,GPU_KEYS,SMCTemperatures,_Data,summarize

class TemperatureRules(unittest.TestCase):
    def test_average_max_and_coverage(self):
        t=summarize({CPU_KEYS[0]:50,CPU_KEYS[1]:70,GPU_KEYS[0]:45,GPU_KEYS[1]:55},at=1)
        self.assertEqual(t['cpu_c'],60);self.assertEqual(t['cpu_max_c'],70)
        self.assertEqual(t['gpu_c'],50);self.assertEqual(t['gpu_max_c'],55)
        self.assertEqual(len(t['cpu_sensors']),2);self.assertEqual(t['at'],1)
    def test_reject_invalid_and_unmapped_sensors(self):
        t=summarize(dict(zip(CPU_KEYS,[0,-1,float('nan'),float('inf'),151,None,'60',False]))|{'Ts0P':120})
        self.assertIsNone(t['cpu_c']);self.assertIsNone(t['gpu_c'])
        self.assertEqual(t['cpu_sensors'],[])
        json.dumps(t,allow_nan=False)
    def test_missing_one_component_does_not_invent_other(self):
        t=summarize({GPU_KEYS[0]:50})
        self.assertIsNone(t['cpu_c']);self.assertEqual(t['gpu_c'],50)
    def test_smc_wire_layout(self):
        self.assertEqual(ctypes.sizeof(_Data),80);self.assertEqual(_Data.data.offset,48)
    def test_write_commands_are_rejected(self):
        reader=SMCTemperatures.__new__(SMCTemperatures)
        with self.assertRaises(ValueError):reader._call(0,_Data(command=6))

if __name__=='__main__':unittest.main()
