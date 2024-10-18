import unittest
import sys
sys.path[0:0] = ['.', '..']
from sigbin.sigbin import FuncInfo, stripFuncLibData, demangleFunction

class TestSigBin(unittest.TestCase):
	
	def test_stripFuncLibData(self):
		funcInfo = FuncInfo("strcpy@@GLIBCXX_3.4", "/home/test/file.c")
		newFuncInfo = stripFuncLibData(funcInfo)
		self.assertEqual(newFuncInfo.funcName, "strcpy", "Should be equal to strcpy")


	def test_demangleFunction(self):
		funcInfo = FuncInfo("_ZN7MyClass8myMethodEv", "/home/test/file.c")
		newFuncInfo = demangleFunction(funcInfo)
		print(newFuncInfo.funcName)
		self.assertEqual(newFuncInfo.funcName, "myMethod", "Should be equal to myMethod")
		self.assertEqual(newFuncInfo.funcClass, "MyClass", "Should be equal to MyClass")

if __name__ == '__main__':
    unittest.main()