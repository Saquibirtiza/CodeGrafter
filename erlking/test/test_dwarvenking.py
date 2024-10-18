import unittest
import sys
sys.path[0:0] = ['.', '..']
from dwarvenking.dwarvenking import *
# from sigbin.sigbin import FuncInfo, stripFuncLibData, demangleFunction

class TestDwarvenKing(unittest.TestCase):

	filename = 'testTarget/bin/example_1.bin'
	elfFile = ELFFile(open(filename, 'rb'))
	dwarfinfo = elfFile.get_dwarf_info()
	CUoffsets = []
	for CU in dwarfinfo.iter_CUs():
		CUoffsets.append(CU)
		# break
	#The choosen binary has 2 Compile Units
	firstTopDIE = CUoffsets[0].get_top_DIE()
	firstCUoffset = CUoffsets[0].cu_offset
	secondTopDIE = CUoffsets[1].get_top_DIE()
	secondCUoffset = CUoffsets[1].cu_offset	

	# def test_getCFAOffsetsByAddr(self):
	# 	funcInfo = FuncInfo("strcpy@@GLIBCXX_3.4", "/home/test/file.c")
	# 	newFuncInfo = stripFuncLibData(funcInfo)
	# 	self.assertEqual(newFuncInfo.funcName, "strcpy", "Should be equal to strcpy")

	def test_hex_sub(self):
		offsetHX = hex_sub(self.firstTopDIE.offset, self.firstCUoffset)
		self.assertEqual(offsetHX, '0xb', "Check 11-0; Should be 0xb")
		offsetHX = hex_sub(self.secondTopDIE.offset, self.secondCUoffset)
		self.assertEqual(offsetHX, '0xb', "Check 1497-1486; Should be 0xb")		

	def test_hex_addition(self):
		offsetHX = hex_addition(self.firstTopDIE.offset, self.firstCUoffset)
		self.assertEqual(offsetHX, '0xb', "Check 11+0; Should be 0xb")
		offsetHX = hex_addition(self.secondTopDIE.offset, self.secondCUoffset)
		self.assertEqual(offsetHX, '0xba7', "Check 1497+1486; Should be 0xba7")		
	# def test_sortByLocation(self):

	# def test_format_hex(self):

	# def test_decode_seq(self):

	# def test_decode_leb128(self):


if __name__ == '__main__':
    unittest.main()