from enum import Enum
import argparse
import math
import sys
import re
import bap
import networkx as nx
import pygraphviz as pgv
from graphviz import Source
from termcolor import colored
import elftools
from elftools.elf.elffile import ELFFile 
import cxxfilt
sys.path[0:0] = ['..']
from sigbin.sigbin import sigBIN
from mylogging.erlLogger import mylogger
import logging

mylogger = logging.getLogger('ek.sb')



description = """
Disassemble the binary and create a List of nodes,essentially depicting the CFG
"""
def main():
	None
	parser = argparse.ArgumentParser(description=description)
	parser.add_argument('--bin',required=True, help='Target Binary')
	# # parser.add_argument('-f','--flag',required=True,help='Sample option')
	args = parser.parse_args()
	sbin = sigBIN(args.bin)
	# sbin.drawFuncCFG("my_strncpy")
	# sbin.drawSrcCFG("my_strncpy")
	sbin.generateCG()
		# sbin.drawFuncCFG("add_line_buffer")
	# sbin.printEffects("main")
	# sbin.getInsByFuncOffset('sub_611','0x4')	#TODO: offstes must be unique for each instruction per function, There can't be more than one instructions
	# mylogger.info(sbin.getCFG())

if __name__ == "__main__":
	main()
