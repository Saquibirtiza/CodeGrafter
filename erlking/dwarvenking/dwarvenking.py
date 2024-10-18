#-------------------------------------------------------------------------------
# elftools example: dwarvenking.py
# Dependency: pip install pyelftools
# Input : DWARF Compile UNit
# Output : List of UnrolledVarInfo
# usage:        dk = DWARFKing(<CompileUnit>)
#               lst = dk.processDWARF()
# scw130030@utdallas.edu
#-------------------------------------------------------------------------------
from __future__ import print_function
from struct import *
import subprocess
import sys
import re
import struct
sys.path[0:0] = ['.', '..']
from mylogging.erlLogger import mylogger
import logging


from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import bytes2str
from elftools.dwarf.dwarf_expr import DW_OP_opcode2name
# from typing import Any, Collection, Dict, List, Optional, Set, Tuple, Union

# from elftools.dwarf.callframe import FDE
# from elftools.dwarf.descriptions import set_global_machine_arch
# from elftools.dwarf.descriptions import describe_reg_name
# from elftools.dwarf.descriptions import instruction_name
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.descriptions import (
	describe_reg_name, describe_attr_value, set_global_machine_arch,
	describe_CFI_instructions, describe_CFI_register_rule,
	describe_CFI_CFA_rule, describe_reg_name, instruction_name
	)
from elftools.dwarf.constants import (
	DW_LNS_copy, DW_LNS_set_file, DW_LNE_define_file)
from elftools.dwarf.callframe import CIE, FDE

mylogger = logging.getLogger('ek.dk')

'''
  Return CFA (Canonical Frame Address) offsets for all registers
  defined for the given address.
  Currently only retrieves data for DW_CFA_offset opcodes.
'''
def getCFAOffsetsByAddr(elf,addr):
	# Set machine arch to get architecture-specific register names
	set_global_machine_arch(elf.get_machine_arch())
	# Get CFI (Call Frame Information) used for exception handling
	cfi_entries = elf.get_dwarf_info().EH_CFI_entries()
	registers = {}
	for entry in cfi_entries:
	# Check whether this FDE (Frame Description Entry) starts at
	# the address we seek; if so, enumerate through its call frame
	# instructions (not native instructions)
		if isinstance(entry,FDE) and entry.header['initial_location'] == addr:
			data_alignment_factor = entry.cie.header['data_alignment_factor']
			for i in entry.instructions:
				if instruction_name(i.opcode) == 'DW_CFA_offset':
					reg = describe_reg_name(i.args[0])
					factored_offset = i.args[1]
					registers[reg] = factored_offset*data_alignment_factor
	del cfi_entries
	return registers


def hex_sub(from_val,init_val):
    return hex(from_val - init_val)

def hex_addition(from_val,init_val):
    return hex(from_val + init_val)

def sortByLocation(unrolledList):
	sortedList = unrolledList[:]
	sortedList.sort(key = lambda c: c.cfa_offset,reverse=True)
	# list2 = sorted(list,reverse=True)
	return sortedList

def format_hex(addr, elfClass, fieldsize=None, fullhex=False, lead0x=True):
	""" Format an address into a hexadecimal string.
		fieldsize:
			Size of the hexadecimal field (with leading zeros to fit the
			address into. For example with fieldsize=8, the format will
			be %08x
			If None, the minimal required field size will be used.
		fullhex:
			If True, override fieldsize to set it to the maximal size
			needed for the elfclass
		lead0x:
			If True, leading 0x is added
	"""
	s = '0x' if lead0x else ''
	if fullhex:
		# fieldsize = 8 if self.elffile.elfclass == 32 else 16
		fieldsize = 8 if elfClass == 32 else 16
	if fieldsize is None:
		field = '%x'
	else:
		field = '%' + '0%sx' % fieldsize
	return s + field % addr

def resolveStructLoc(sortedList):
	"""
	sortedList may have variable and struct members interleaved. Correct offsets must be assigned
	"""
	idx = 0
	orig_base = None
	new_base = None

	while idx < len(sortedList)-1:
		if sortedList[idx].tag != "DW_TAG_member":
			orig_base = None
			new_base = None
		if (sortedList[idx].cfa_offset == sortedList[idx+1].cfa_offset and sortedList[idx].baseType != sortedList[idx+1].baseType):
			orig_base = sortedList[idx].cfa_offset
			if(sortedList[idx].tag != "DW_TAG_member"):
				new_base = int(hex_addition(int(sortedList[idx].cfa_offset,16), sortedList[idx].size), 16)
			if(sortedList[idx+1].tag != "DW_TAG_member"):
				new_base = int(hex_addition(int(sortedList[idx+1].cfa_offset, 16), sortedList[idx+1].size), 16)
		if (new_base is not None and sortedList[idx+1].tag == "DW_TAG_member"):
			new_offset = int(sortedList[idx+1].cfa_offset,16)- int(orig_base,16)
			sortedList[idx+1].cfa_offset = hex_addition(new_base, new_offset)
		idx += 1
	return sortedList


def decode_seq(seq, length):
	""" This function takes integer array and the length of operands
		first element is the opcode and number of elements specified by the length is decoded
		Usage:
		arr = [145, 180, 127]
		print(decode_seq(arr,len(arr)))
	"""    
	# mylogger.trace("decoding sequence: %s of length %s" % (seq, length))
	op = seq[0]
	if op in DW_OP_opcode2name:
		opname = DW_OP_opcode2name[op]

		revlist = seq[1:length][::-1]
		code = ""
		for item in revlist:
			code = code + (hex(item)).lstrip('0x').zfill(2)
		#Returning decoded opcode and the parameters
		#DW_OP_bregN, DW_OP_bregx, DW_OP_fbreg
		#TODO: All opnames to be considered
		pattern_breg = re.compile("DW_OP_.*breg.*")

		#DW_OP_addr
		pattern_static = re.compile("DW_OP_addr")
		# mylogger.trace("OPNAME: %s, CODE: %s" % (opname, code))
		if(pattern_breg.match(opname)):
			return opname, hex(decode_leb128(code))
		elif(pattern_static.match(opname)):
			return opname, hex(int(code,16))
		else:
			return opname, code
	else:
		#TODO: decoding sequence: [242, 255, 226, 47, 0, 0] of openssl
		# PEM_get_EVP_CIPHER_INFO in openssl-OpenSSL_1_0_1r/crypto/pem/pem_lib.c Failed
		# According to dwarf spec possible opcode values are 03-157
		return 'NoOp', 0

def decode_leb128(byte_str):
	value = bin(0)[2:].zfill(7)
	byte_stream = bytearray.fromhex(byte_str)
	for b in byte_stream:
		b_bin = bin(b)[2:].zfill(8)
		mask = bin(int("0x7f",16))[2:].zfill(8)
		value = bin((int(value,2) << 7) | (int(b_bin,2) & int(mask,2)))
	newValue = (int(value,2) - 0b1)
	new_b_bin = bin(newValue)[2:]
	newValue = newValue ^ int(len(new_b_bin)*'1',2)
	del(value)
	del(byte_stream)
	return (-newValue)


class DIErecord():
	def __init__(self,die):
		self.die = die
		self.refType = None			#Reference type's DIE offset
		self.size = None			#Size depends on reference type (e.g. Base type/pointer/array)
		self.explicitType = None	#Variable type (e.g. base/pointer/array)
		self.length = None			#For array lengths
		self.baseType = None 		#The primary(eventual) type
	def __str__(self):
		return str(self.__dict__)
	def __repr__(self):
		return str(self.__dict__)

class TypeRecord(object):
	def __init__(self, name, size, baseType, explicitType):
		self.name = name
		self.size = size
		self.baseType = baseType
		self.explicitType = explicitType
	def __str__(self):
		return str(self.__dict__)
	def __repr__(self):
		return str(self.__dict__)

class RetRecord(object):
	def __init__(self, typeRecord, memberList = []):
		self.name = typeRecord.name
		self.size = typeRecord.size
		self.baseType = typeRecord.baseType
		self.explicitType = typeRecord.explicitType
		self.members = memberList	#List of TypeRecords
		self.isReturningPtr = False
	def __str__(self):
		return str(self.__dict__)
	def __repr__(self):
		return str(self.__dict__)

class StructRecord(object):
	def __init__(self, die):
		self.members = []
		self.die = die
		self.visited = 0
	def __str__(self):
		return str(self.__dict__)
	def __repr__(self):
		return str(self.__dict__)

class LayoutInfo:
	def __init__(self, varName, cfa_offset, size, refType, explType, baseType, tag, arrLength=None, ssz=None):
		self.varName = varName			#VariableName/StructName/StructName.memberName
		self.refType = refType			#Direct reference type (e.g pointer type)
		self.explicitType = explType 	#e.g. pointer|long|short etc
		self.baseType = baseType 		#final type directed at
		self.length = arrLength 		#length if is an array
		self.cfa_offset = cfa_offset 	#Offset
		self.size = size 				#bases Size
		self.ssz = ssz					#stack size
		self.tag = tag 					#e.g. DW_TAG_formal_parameter| DW_TAG_variable | DW_TAG_structure_type | DW_TAG_member
	def __str__(self):
		return str(self.__dict__)
	def __repr__(self):
		return str(self.__dict__)

regs64 = {80:'rax',81:'rbx', 82:'rcx', 83:'rdx', 84:'rsi', 85:'rdi', 86:'rbp', 87:'rsp', 88:'r8', 89:'r9', 90:'r10',
	91:'r11', 92:'r12', 93:'r13', 94:'r14', 95:'r15'}

class DWARVENking(object):
	#Constructor
	def __init__(self,binFile):
		self._layoutList = []
		self._layoutDict = { }
		self._layoutDict['global'] = []
		self._dieGraph = { }
		self._structList = { }
		self._retList = { }
		self._topCUoffset = None
		self.binFile = binFile
		self.elfFile = ELFFile(open(binFile, 'rb'))
		if self.elfFile.has_dwarf_info():
			self._dwarfinfo = self.elfFile.get_dwarf_info()	
		self._processDWARF()

	def __del__(self):
		None
	# 	mylogger.trace('Destructor called')

	def getUnrolledInfo(self):
		return self._layoutDict

	def getRetList(self):
		return self._retList

	def _processDWARF(self):
		"""
			for each compilation unit dwarf are processed
		"""
		if not self.elfFile.has_dwarf_info():
			raise Exception('{} file has no DWARF information'.format(self.elfFile))
		dwarfinfo = self.elfFile.get_dwarf_info()

		for CU in dwarfinfo.iter_CUs():
			top_DIE = CU.get_top_DIE()
			self._topCUoffset = CU.cu_offset
			lineprogram = self._dwarfinfo.line_program_for_CU(CU)
			self._resetLocals()
			self._processCompileUnit(top_DIE, lineprogram)
			# mylogger.trace("Printing DIE")
			# for i in self._dieGraph:
			# 	mylogger.trace("%s: %s" % (i, self._dieGraph[i]))
			# mylogger.trace("Printing Struct list")
			# for i in self._structList:
			# 	mylogger.trace("%s: %s" % (i, self._structList[i]))
		globalVarList = self._layoutDict['global']
		self._layoutDict['global'] = resolveStructLoc(sortByLocation(globalVarList))


	def _resetLocals(self):
		self._dieGraph = {}
		self._structList = {}

	#Variable information are recorded for each compile unit
	def _processCompileUnit(self, top_DIE, lineprogram):

		# if len(lineprogram['include_directory']) > 0:
		# 	cu_filename = '%s/%s' % (
		# 		bytes2str(lineprogram['include_directory'][0]),
		# 		bytes2str(lineprogram['file_entry'][0].name))
		# else:
		# 	cu_filename = bytes2str(lineprogram['file_entry'][0].name)

		# mylogger.trace('Processing %s' % top_DIE.get_full_path())
		# mylogger.info('File %s' % cu_filename)

		#Transform the flat tree into a graph like list representation
		#To assist recursively traverse through graph and update variable info
		#NO need to traverse beyond pointer DIE
		#TODO: Check following function for its usage
		# self._read_debug_line_programs()
		self._record_die_rec(top_DIE)
		# self._record_structs_rec(top_DIE)
		# self._printDeclarations()
		self._update_die_graph()
		# self._printDeclarations()
		# self._record_structs_rec(top_DIE)	
		self._read_vars_rec(top_DIE)

		self._update_ret_list()

	def _update_ret_list(self):
		"""
		Updating the return type List if it is a Struct type
		"""
		#TODO: This is a vague approach. Only helps if a return pointer points to a Struct of basic types. Need more sophisticated 
		#Solution if the Struct is a coplicated one. Hopefully this would resolve DARPA Pierrepont challenge.

		for function in self._retList:
			baseType = self._retList[function].baseType
			members = { }
			if baseType in self._structList:
				for member in self._structList[baseType].members:
					offsetHX = hex_sub(member.offset,self._topCUoffset)
					memberRecord = self._dieGraph[offsetHX]
					memberSize = memberRecord.size
					memberName = 'unknown'
					if 'DW_AT_name' in member.attributes:
						memberName = bytes2str(member.attributes['DW_AT_name'].value)
					explicitType = memberRecord.explicitType
					refType = memberRecord.refType
					members[memberName] = TypeRecord(memberName, memberSize, baseType, explicitType)
				self._retList[function].members = members


	def _read_debug_line_programs(self):
		""" Dump the (decoded) line programs from .debug_line
			The programs are dumped in the order of the CUs they belong to.
		"""
		mylogger.info('Decoded dump of debug contents of section .debug_line:\n')
		for cu in self._dwarfinfo.iter_CUs():
			lineprogram = self._dwarfinfo.line_program_for_CU(cu)
			cu_filename = ''
			if len(lineprogram['include_directory']) > 0:
				cu_filename = '%s/%s' % (
				bytes2str(lineprogram['include_directory'][0]),
				bytes2str(lineprogram['file_entry'][0].name))
			else:
				cu_filename = bytes2str(lineprogram['file_entry'][0].name)
				mylogger.trace('CU: %s:' % cu_filename)
				mylogger.trace('File name                            Line number    Starting address')
			# Print each state's file, line and address information. For some
			# instructions other output is needed to be compatible with
			# readelf.
			for entry in lineprogram.get_entries():
				state = entry.state
				if state is None:
					# Special handling for commands that don't set a new state
					if entry.command == DW_LNS_set_file:
						file_entry = lineprogram['file_entry'][entry.args[0] - 1]
						if file_entry.dir_index == 0:
							# current directory
							mylogger.trace('\n./%s:[++]' % (
							bytes2str(file_entry.name)))
						else:
							mylogger.trace('\n%s/%s:' % (
						    bytes2str(lineprogram['include_directory'][file_entry.dir_index - 1]),
						    bytes2str(file_entry.name)))
					elif entry.command == DW_LNE_define_file:
						mylogger.trace('%s:' % (
						bytes2str(lineprogram['include_directory'][entry.args[0].dir_index])))
				elif not state.end_sequence:
					# readelf doesn't print the state after end_sequence
					# instructions. I think it's a bug but to be compatible
					# I don't print them too.
					mylogger.trace('%-35s  %11d  %18s %s' % (
						bytes2str(lineprogram['file_entry'][state.file - 1].name),
						state.line,
						'0' if state.address == 0 else 
								format_hex(state.address, self.elfFile.elfclass), self._topCUoffset))
				# if entry.command == DW_LNS_copy:
				# 	# Another readelf oddity...
				# 	mylogger.info()

	def _read_vars_rec(self,cur_die):
		"""
		Recursively reading variables in each function which doesn't have an abstract origin
		"""
		if(cur_die.tag == 'DW_TAG_subprogram' and ('DW_AT_abstract_origin' not in cur_die.attributes)):

			
			if('DW_AT_linkage_name' in cur_die.attributes):
				funcName = bytes2str(cur_die.attributes['DW_AT_linkage_name'].value)
			elif('DW_AT_name' in cur_die.attributes):
				funcName = bytes2str(cur_die.attributes['DW_AT_name'].value)
			else:
				funcSpecialization = hex(cur_die.attributes['DW_AT_specification'].value)
				funcName = bytes2str(self._dieGraph[funcSpecialization].die.attributes['DW_AT_name'].value)

			# self.die = die
			# self.refType = None			#Reference type's DIE offset
			# self.size = None			#Size depends on reference type (e.g. Base type/pointer/array)
			# self.explicitType = None	#Variable type (e.g. base/pointer/array)
			# self.length = None			#For array lengths
			# self.baseType = None 

			if ('DW_AT_type' in cur_die.attributes):
				retDieRecord = self._dieGraph[hex(cur_die.attributes['DW_AT_type'].value)]
				recName = "unknown"
				if ('DW_AT_name' in retDieRecord.die.attributes):
					recName = bytes2str(retDieRecord.die.attributes['DW_AT_name'].value)
				retType = TypeRecord(recName, retDieRecord.size, retDieRecord.baseType, retDieRecord.explicitType)
				# retType = TypeRecord(retDieRecord.explicitType, retDieRecord.size, retDieRecord.baseType)
				self._retList[funcName] = RetRecord(retType)
			mylogger.trace("Reading vars from %s" % funcName)
			# if (not funcName.startswith("_")):
			# 	file = cur_die.attributes['DW_AT_decl_file'].value
			# 	mylogger.trace("Of %s" % file)
			for child in cur_die.iter_children():
				#TODO: Check if DW_AT_external check is necessary or not
				if((child.tag == 'DW_TAG_variable' or child.tag == 'DW_TAG_formal_parameter') and ('DW_AT_external' not in child.attributes)):
					if(('DW_AT_location' in child.attributes) and  (child.attributes['DW_AT_location'].form == 'DW_FORM_exprloc')):
						
						relOffset = hex_sub(child.offset,self._topCUoffset)	#Get the offset of die relative to top_die (CU)
						dieRecord = self._dieGraph[relOffset]
						locationArr = child.attributes['DW_AT_location'].value
						location = decode_seq(locationArr,len(locationArr))
						if (location[0] == 'DW_OP_fbreg' and ('DW_AT_low_pc' in cur_die.attributes) and ('DW_AT_frame_base' in cur_die.attributes)):	#We eveluate DW_OP_fbreg addresses only

							low_pc = cur_die.attributes['DW_AT_low_pc'].value
							lx_pc = '%0*X' % (4,low_pc)
							frame_base = cur_die.attributes['DW_AT_frame_base'].value
							base_ptr = None

							# # Base depends on frame base representation
							# #DW_OP_reg0-31 = 0x50-0x6f = 80-111
							# if(frame_base[0] == 86):
							# 	base_ptr = ('rbp',0)
							# #DW_OP_call_frame_cfa = 0x9c = 156
							# elif(frame_base[0] == 156):
							# 	# Following is commented, subprocess command was replaced by getCFAOffsetsByAddr
							# 	# cfa_off = subprocess.check_output('readelf -wf %s | awk -F"\n" -v RS="\n\n" \'$1 ~ /%s../\' | grep "DW_CFA_offset: r6 (rbp)"' % (self.binFile,lx_pc.lower()), shell=True)
							# 	# offVal = int(cfa_off.strip().split(' ')[-1].split('cfa')[1])
							# 	offVal = getCFAOffsetsByAddr(self.elfFile,int(lx_pc,16))['rbp']
							# 	offVal = offVal * (-1)
							# 	base_ptr = ('rbp',offVal)
							if ( frame_base[0] in regs64):
								base_ptr = (regs64[frame_base[0]],0)
							elif(frame_base[0] == 156):
								cfaOffsetList = getCFAOffsetsByAddr(self.elfFile,int(lx_pc,16))
								if('rbp' in cfaOffsetList):
									offVal = getCFAOffsetsByAddr(self.elfFile,int(lx_pc,16))['rbp']
									offVal = offVal * (-1)
									base_ptr = ('rbp',offVal)
								else:
									#TODO: Location list should be considered
									None

							if base_ptr:
								#TODO: challenge Smith has a parameter without Name but the ref type has a name.
								#varName will remain unknown if any direct name was not found
								varName = 'Unknown'
								if 'DW_AT_artificial' in child.attributes:
									varName = 'this'
								elif 'DW_AT_name' in child.attributes:
									varName = bytes2str(child.attributes['DW_AT_name'].value)
								elif ('DW_AT_type' in child.attributes):
										item = hex(child.attributes['DW_AT_type'].value)
										childRef = self._dieGraph[item].die
										if 'DW_AT_name' in childRef.attributes:
											varName = bytes2str(childRef.attributes['DW_AT_name'].value)
								# varName = bytes2str(child.attributes['DW_AT_name'].value) if ('DW_AT_artificial' not in child.attributes) else "this"
								varSize = dieRecord.size
								cfaOffset = hex(int(location[1],16) + base_ptr[1])

								field  = None
								if (dieRecord.baseType in self._structList):
									structRecord = self._structList[dieRecord.baseType]
									#TODO:Should this be commented
									# self._layoutList.append(LayoutInfo(varName, cfaOffset, varSize, dieRecord.refType, dieRecord.explicitType, dieRecord.baseType, "DW_TAG_structure_type", dieRecord.length))
									self._read_structs_rec(dieRecord, structRecord, cfaOffset, varName, False, child.tag)
								else:
									self._layoutList.append(LayoutInfo(varName, cfaOffset, varSize, dieRecord.refType, dieRecord.explicitType, dieRecord.baseType, child.tag, dieRecord.length))
								
						else:
							None	#DW_OP_addr is an constant address.
							#TODO: Should (!= 'DW_OP_fbreg') case be considered
			self._layoutList = sortByLocation(self._layoutList)
			self._layoutList = resolveStructLoc(self._layoutList)
			self._layoutDict[funcName] = self._layoutList
			self._layoutList = []
		
		# This part is for global variables
		# TODO: Locations of Global variables from different classes may overlap. CHeck please.
		elif((cur_die.tag == 'DW_TAG_variable' or cur_die.tag == 'DW_TAG_formal_parameter')):
			if(('DW_AT_location' in cur_die.attributes) and (cur_die.attributes['DW_AT_location'].form == 'DW_FORM_exprloc') and ('DW_AT_abstract_origin' not in cur_die.attributes)):
				
				relOffset = hex_sub(cur_die.offset,self._topCUoffset)	#Get the offset of die relative to top_die (CU)
				dieRecord = self._dieGraph[relOffset]
				locationArr = cur_die.attributes['DW_AT_location'].value
				location = decode_seq(locationArr,len(locationArr))
				#We eveluate DW_OP_fbreg addresses only
				if (location[0] == 'DW_OP_addr'):					

					if('DW_AT_name' in cur_die.attributes):
						varName = bytes2str(cur_die.attributes['DW_AT_name'].value)
					else:
						varSpecification = hex(cur_die.attributes['DW_AT_specification'].value)
						varName = bytes2str(self._dieGraph[varSpecification].die.attributes['DW_AT_name'].value)

					varSize = dieRecord.size
					dataOffset = location[1]

					if (dieRecord.baseType in self._structList):
						structRecord = self._structList[dieRecord.baseType]
						#TODO:Should this be commented
						# self._layoutDict['global'].append(LayoutInfo(varName, dataOffset, varSize, dieRecord.refType, dieRecord.explicitType, dieRecord.baseType, "DW_TAG_structure_type", dieRecord.length))
						self._read_structs_rec(dieRecord, structRecord, dataOffset, varName, True, cur_die.tag)
					else:
						self._layoutDict['global'].append(LayoutInfo(varName, dataOffset, varSize, dieRecord.refType, dieRecord.explicitType, dieRecord.baseType, cur_die.tag, dieRecord.length))
					
				else:
					mylogger.warning("A global variable with Unknown DW_AT_location type")

		else:
			for child in cur_die.iter_children():
				self._read_vars_rec(child)	
					
	def _read_structs_rec(self, dieRecord, structRecord, cfaOffset, parentName, isGlobal=False, tag=None):
		"""
		Recursively read struct elements and return a list of unrolled struct members
		"""	
		for member in structRecord.members:
			
			offsetHX = hex_sub(member.offset,self._topCUoffset)
			memberRecord = self._dieGraph[offsetHX]
			memberSize = memberRecord.size
			refType = memberRecord.refType
			#TODO: struct member without DW_AT_data_member_location attribute is observed. Reason is unknown.
			#assumption: since only one member is noticed location is set to 0
			memberLoc = member.attributes['DW_AT_data_member_location'].value if ('DW_AT_data_member_location' in member.attributes) else 0
			memberOffset = hex_addition(memberLoc,int(cfaOffset,16))
			if ( 'DW_AT_name' in member.attributes):
				memberName = parentName+'.'+bytes2str(member.attributes['DW_AT_name'].value)
			else:
				memberName = parentName+'.Unknown'

			if( refType in self._structList and (self._structList[refType].visited == 0)):
				memStructRecord = self._structList[refType]
				self._structList[refType].visited = 1
				if(isGlobal):
					self._layoutDict['global'].append(LayoutInfo(memberName, memberOffset, memberSize, memberRecord.refType, memberRecord.explicitType, memberRecord.baseType, "DW_TAG_member", memberRecord.length))
					self._read_structs_rec(memberRecord, memStructRecord, memberOffset, memberName,isGlobal, tag)
				else:
					self._layoutList.append(LayoutInfo(memberName, memberOffset, memberSize, memberRecord.refType, memberRecord.explicitType, memberRecord.baseType, "DW_TAG_member", memberRecord.length))
					self._read_structs_rec(memberRecord, memStructRecord, memberOffset, memberName, isGlobal, tag)
			elif( refType not in self._structList):
				if(isGlobal):
					self._layoutDict['global'].append(LayoutInfo(memberName, memberOffset, memberSize, memberRecord.refType, memberRecord.explicitType, memberRecord.baseType, "DW_TAG_member", memberRecord.length))
				else:
					self._layoutList.append(LayoutInfo(memberName, memberOffset, memberSize, memberRecord.refType, memberRecord.explicitType, memberRecord.baseType, "DW_TAG_member", memberRecord.length))
			else:
				None
			self._reset_structList()

	def _reset_structList(self):
		"""
			Reset visited flag from all records
		"""
		for struct in self._structList:
			self._structList[struct].visited = 0


	def _record_die_rec(self,cur_die):
		"""
			Recording all DIE units with ref type and sizes if available
		"""
		offsetHX = hex_sub(cur_die.offset,self._topCUoffset)	#Get the offset of die relative to top_die (CU)
		die_record = DIErecord(cur_die)

		if('DW_AT_byte_size' in cur_die.attributes):
			die_record.size = cur_die.attributes['DW_AT_byte_size'].value	#decimal
		else:
			die_record.size = 0

		if('DW_AT_type' in cur_die.attributes):
			die_record.refType = hex(cur_die.attributes['DW_AT_type'].value) #unlike offset attribute type is (direct) not-	relative
		else:
			die_record.baseType = offsetHX
		if(cur_die.tag == 'DW_TAG_array_type'):

			for child in cur_die.iter_children():
				if(child.tag == "DW_TAG_subrange_type" and 'DW_AT_upper_bound' in child.attributes):
					val = child.attributes['DW_AT_upper_bound'].value
					if (not isinstance(val,list)):
						die_record.length = child.attributes['DW_AT_upper_bound'].value + 1
					else:
						die_record.length = 0
				elif(child.tag == "DW_TAG_subrange_type" and 'DW_AT_count' in child.attributes):
					die_record.length = child.attributes['DW_AT_count'].value
				else:
					#TODO: If upperbound is not fixed, rather an expression length is unsure and set to 0
					die_record.length = 0
		elif(cur_die.tag == 'DW_TAG_base_type'):
			die_record.baseType = offsetHX
			if('DW_AT_name' in cur_die.attributes):
				die_record.explicitType = bytes2str(cur_die.attributes['DW_AT_name'].value)
			else:
				die_record.explicitType = "base"
		elif(cur_die.tag == 'DW_TAG_structure_type'):
			if('DW_AT_linkage_name' in cur_die.attributes):
				die_record.explicitType = bytes2str(cur_die.attributes['DW_AT_linkage_name'].value)
			elif('DW_AT_name' in cur_die.attributes):
				die_record.explicitType = bytes2str(cur_die.attributes['DW_AT_name'].value)
			else:			
				die_record.explicitType = "struct"
			die_record.baseType = offsetHX

			newStructRecord = StructRecord(cur_die)
			# newStructRecord.die = die
			for child in cur_die.iter_children():
				if(child.tag == "DW_TAG_member"):
					newStructRecord.members.append(child)
			self._structList[offsetHX] = newStructRecord
		elif(cur_die.tag == 'DW_TAG_typedef' and 'DW_AT_type' not in cur_die.attributes):
			die_record.explicitType = bytes2str(cur_die.attributes['DW_AT_name'].value)
		elif(cur_die.tag == 'DW_TAG_const_type' and 'DW_AT_type' not in cur_die.attributes):
			die_record.explicitType = "const"
		elif(cur_die.tag == 'DW_TAG_pointer_type'):
			die_record.explicitType = "pointer"
						
		self._dieGraph[offsetHX] = die_record

		for die in cur_die.iter_children():
			self._record_die_rec(die)

	def _update_die_graph(self):
		"""
			Bottom-up approach to update die graph
		"""
		for item in self._dieGraph:
			if (self._dieGraph[item].baseType is None):
				record = self._update_die_rec(self._dieGraph[item].refType)

				self._dieGraph[item].explicitType = record[2]
				self._dieGraph[item].refType = record[0]
				self._dieGraph[item].baseType = record[3]	
				if(self._dieGraph[item].die.tag == 'DW_TAG_array_type'):
					#TODO: Is following "or 1" part needed
					# self._dieGraph[item].size = record[1] * int(self._dieGraph[item].length or 1)
					self._dieGraph[item].size = record[1] * int(self._dieGraph[item].length)
				else:
					self._dieGraph[item].size = record[1]



	def _update_die_rec(self,ref):
		#Base case is refType is None
		if (self._dieGraph[ref].baseType is not None):
			dieRecord = self._dieGraph[ref]
			retType = self._dieGraph[ref].explicitType
			if(self._dieGraph[ref].die.tag == 'DW_TAG_array_type'):
				retType = "array"
				self._dieGraph[ref].size = int(self._dieGraph[ref].length)
			elif(self._dieGraph[ref].die.tag == 'DW_TAG_pointer_type'):
				retType = "pointer"
			return ref, self._dieGraph[ref].size, retType, self._dieGraph[ref].baseType

		else:
			record = self._update_die_rec(self._dieGraph[ref].refType)
			retType = record[2]
			refType = record[0]
			retSize = record[1]			
			retREF = ref		
			# cur_die = self._dieGraph[ref]
			if(self._dieGraph[ref].die.tag == 'DW_TAG_array_type'):
				retType = "array"
				# retREF = ref
				self._dieGraph[ref].size = record[1] * int(self._dieGraph[ref].length)
			elif(self._dieGraph[ref].die.tag == 'DW_TAG_pointer_type'):
				retType = "pointer"
				# self._dieGraph[ref].size = record[1]
			else:
				self._dieGraph[ref].size = record[1]

			self._dieGraph[ref].explicitType = record[2]
			# self._dieGraph[ref].explicitType = retType
			self._dieGraph[ref].refType = record[0]			
			self._dieGraph[ref].baseType = record[3]
	
			return retREF, self._dieGraph[ref].size, retType, record[3]

	def _record_structs_rec(self,die):
		"""
			 Recording all structs
		"""
		if(die.tag == "DW_TAG_structure_type"):
			offsetHX = hex_sub(die.offset,self._topCUoffset)    #Getting the relative offset
			self._curStructRecord = StructRecord(die)
			# StructRecord = StructRecord(die)
			# newStructRecord.die = die
			for child in die.iter_children():
				if(child.tag == "DW_TAG_member"):
					self._curStructRecord.members.append(child)
			self._structList[offsetHX] = self._curStructRecord
		else:
			for child in die.iter_children():
				self._record_structs_rec(child)


#------ Methods for debugging--------
	def _printDeclarations(self):
		for item in self._dieGraph:
			# DW_AT_external specifies global variables
			# if((self._dieGraph[item].die.tag == 'DW_TAG_variable' or self._dieGraph[item].die.tag == 'DW_TAG_formal_parameter') and ('DW_AT_external' not in self._dieGraph[item].die.attributes)):
			if((self._dieGraph[item].die.tag == 'DW_TAG_variable' or self._dieGraph[item].die.tag == 'DW_TAG_formal_parameter')):
				if ('DW_AT_name' in self._dieGraph[item].die.attributes):
					mylogger.trace(self._dieGraph[item].die.attributes['DW_AT_name'].value)
				else:
					mylogger.trace("No variable name")
				offset = hex(self._dieGraph[item].die.offset - self._topCUoffset) 
				dieRecord = self._dieGraph[item]
				mylogger.trace("[%s, offset: %s] [size: %s, refType: %s, explicitType: %s] (length: %s) (baseType: %s)->" % (dieRecord.die.tag, offset,dieRecord.size, dieRecord.refType, dieRecord.explicitType, dieRecord.length, dieRecord.baseType))
				self._printDeclarations_rec(item)

	def _printDeclarations_rec(self,item,space=' '):
		space = space + " "
		if ('DW_AT_type' in self._dieGraph[item].die.attributes):
			item = hex(self._dieGraph[item].die.attributes['DW_AT_type'].value)
			offset = hex(self._dieGraph[item].die.offset - self._topCUoffset)
			dieRecord = self._dieGraph[item]
			mylogger.trace("[%s, offset: %s] [size: %s, refType: %s, explicitType: %s] (length: %s) (baseType: %s)->" % (dieRecord.die.tag, offset,dieRecord.size, dieRecord.refType, dieRecord.explicitType, dieRecord.length, dieRecord.baseType))
			self._printDeclarations_rec(item,space)
		else:
			mylogger.trace("-------------------------")


	def _printStructs(self):
		for item in self._structList:
			print(item)


	def _test(self):
		for item in self._dieGraph:
			refType = self._dieGraph[item].refType
			print(item, refType, self._dieGraph[item].size)
			if (refType is not None):
				print(self._dieGraph[refType].die.tag)
			print("-------------")

	def _checkAll(self,cu):
		for die in cu.iter_children():
			print(die.offset, die.tag)
			print(die)




