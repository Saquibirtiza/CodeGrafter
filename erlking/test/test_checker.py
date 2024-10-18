import unittest
import sys
sys.path[0:0] = ['.', '..']

from dwarvenking.dwarvenking import DWARVENking
from elftools.elf.elffile import ELFFile


class TestChecker(unittest.TestCase):
	filename = 'testTarget/bin/example_1.bin'
	elfFile = ELFFile(open(filename, 'rb'))
	dwarfinfo = elfFile.get_dwarf_info()
	dking = DWARVENking(filename)
	varList = dking.getUnrolledInfo()

	def test_insecure_call(self):
		self.assertEqual(self.varList['runServer'][0].varName, 'addrlen', "Should be addrlen")
		self.assertEqual(self.varList['runServer'][1].varName, 'req.buffer', "Should be req.buffer")
		self.assertEqual(self.varList['runServer'][2].varName, 'req.authenticated', "Should be req.authenticated")
	# Result:> ID: 878, CallerID: 233 Caller: runServer, Callee: recv
	# req.authenticated = *((int*)(new_client + 64) [DW_TAG_member]
	# Return = *((int*)(new_client + 68) [DW_TAG_member]

if __name__ == '__main__':
    unittest.main()