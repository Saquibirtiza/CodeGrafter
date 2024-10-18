#python3 debugDK.py --bin <PATH_TO_BIN>
#e.g. python3 debugDK.py --bin ../../targets/ex1/bin/example_1.bin
from __future__ import print_function
from struct import *
import sys
import re
import struct
import os
# from flask import Flask, render_template
# app = Flask(__name__)

sys.path[0:0] = ['.','..']

# from mylogging.erlLogger import mylogger



from dwarvenking import DWARVENking
from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import bytes2str
from elftools.dwarf.dwarf_expr import DW_OP_opcode2name

def process_file_in_bin():
	# print("Processing file %s",filename)

	path = '../bin'

	for r,d,f in os.walk(path):
		for file in f:
			file = os.path.join(r,file)
			with open(file,'rb') as fname:
				elffile = ELFFile(fname)

				if not elffile.has_dwarf_info():
					print('file has no DWARF info')
					return
				# print(file)

				# dwarfinfo = elffile.get_dwarf_info()
				dking = DWARVENking(elffile)
				return dking.getUnrolledInfo()
				# for CU in dwarfinfo.iter_CUs():
				# 	dking = DWARVENKing(CU)
				# 	lst = dking.processDWARF()
				# 	print("=======================")
				# 	print("Unrolled variable list")
				# 	print("=======================")
				# 	for l in lst:
				# 		print("%s -> %s loc: %s in %s" % (l.name,l.total_size,l.location,l.funcname))



# @app.route("/")
def process_file():
# def process_file(filename):


	# if len(sys.argv) > 1:
	# 	if sys.argv[1] == '--bin':

	# 		for filename in sys.argv[2:]:
	# 			process_file(filename)
	filename =sys.argv[2]
	with open(filename,'rb') as fname:
		elffile = ELFFile(fname)
		if not elffile.has_dwarf_info():
			print('file has no DWARF info')
			return

		dwarfinfo = elffile.get_dwarf_info()

		# dking = DWARVENking(elffile)
		dking = DWARVENking(filename)
		# dking._printDeclarations()
		varList = dking.getUnrolledInfo()
		retList = dking.getRetList()

		print("=======================")
		print("Unrolled variable list")
		print("=======================")
		for l in varList:
			if(len(varList[l])>0):
		# 				self.varName = varName
		# self.refType = None
		# self.cfa_offset = cfa_offset
		# self.size = size  
				print("----------")
				print(l)
				print("----------")
				for item in varList[l]:
					print(item.varName, item.refType, item.cfa_offset, item.size, item.explicitType, item.baseType, item.length, item.tag)

		# print("Return List")

		# for function in retList:
		# 	print("Function: %s" % function)
		# 	print(retList[function])
		# return render_template('stack.html', layout=varList)
		# return render_template("index.html", message="Hello Flask!");

if __name__ == '__main__':
	#TODO: host? 0.0.0.0 or 127.0.0.1
	# app.run(host='0.0.0.0', port=7475, debug=True)
	if len(sys.argv) > 1:
		if sys.argv[1] == '--bin':
			for filename in sys.argv[2:]:
				process_file(filename)
	# else:
	# 	process_file_in_bin()
	# else:
		# print("Usage: python3 testDWARF.py --bin <bin_path>")
