from enum import Enum
import argparse
import math
import sys
import os
import re
import bap
import networkx as nx
from networkx.drawing.nx_agraph import write_dot
import pygraphviz as pgv
from graphviz import Source
from termcolor import colored
import elftools
from elftools.elf.elffile import ELFFile 
from elftools.common.py3compat import bytes2str
from elftools.dwarf.descriptions import describe_form_class
import cxxfilt
# from bapexpr import GenPurpRegs,BapExpr
sys.path[0:0] = ['.', '..']
from sigbin.bapexpr import GenPurpRegs,BapExpr
from mylogging.erlLogger import mylogger
import logging

mylogger = logging.getLogger('ek.sb')

class FuncInfo():
	def __init__(self, funcName, fileName, startLoc=None, exitLoc=None, funcId=None, mangName=None, retType=None, paramList=0, funcClass=None, \
		cyclomaticNum=0, loopNum=0, nestingDegree=0, SLOC=0, ALOC=0, localVars=0, localPtrVars=0, globalVarList=0, pointerArgs=0,\
		isReturningPointers=0, callees=0, callers=0, height=0, conditions=0, cmps=0, jmps=0, ptrAssn=0, remark=None, address=0x0):
		self.funcName = funcName
		self.mangName = mangName
		self.funcId = funcId
		self.fileName = fileName
		self.address = address
		self.startLoc = startLoc 	#Starting Line number
		self.exitLoc = exitLoc   	#Exit Line Number
		self.retType = retType 		#Return Type
		self.paramList = paramList 	#List of Parameters
		self.funcClass = funcClass  #Class containing func
		self.cyclomaticNum	= cyclomaticNum		#Cyclomatic complexity
		self.loopNum = loopNum				#Total loops
		self.nestingDegree = nestingDegree 	#Maximum Nesting Level
		self.SLOC = SLOC
		self.ALOC = ALOC 			#Assembly lines of codes
		self.localVars = localVars 		#Number of local Vars
		self.localPtrVars = localPtrVars	#Number of local pointer Vars
		self.globalVarList = globalVarList 		#GlobalVarList
		self.pointerArgs = pointerArgs 	#NUmber of Pointer arguments
		self.isReturningPointers = isReturningPointers #Is returning entity containing pointers? 0=False/1=True
		self.callees = callees 		#Number of function callings by this func
		self.callers = callers 		#Number of functions calling this function
		self.height =  height 		#Shortest distance from an entrypoint
		self.conditions = conditions 		#Number of Conditions Statements
		self.cmps = cmps 			#Number of CMP assembly instructions 
		self.jmps = jmps 			#Number of JMP instructions
		self.ptrAssn = ptrAssn		#Number of pointer Assignments
		self.remark = remark
		self.vulnScore = 0
		self.codeComplexity = 0


	#TODO: should decide on what constitute filePath (fullPath or last few tokens)
	def __key(self):
		# return (self.funcName, self.filePath, self.funcClass)
		return (self.funcName, self.fileName)
		# return (self.funcName)
	'''
		Hash is needed for checking if an object is in a list
	'''
	def __hash__(self):
		return hash(self.__key())
	def __eq__(self, other):
		if isinstance(other, FuncInfo):
			return self.__key() == other.__key()
		return NotImplemented
	def __repr__(self):
		return 'FuncInfo(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)' % \
				(self.funcId, self.funcName, self.fileName, self.address, self.startLoc, self.exitLoc, self.retType, self.paramList, self.funcClass, \
					self.cyclomaticNum, self.loopNum, self.nestingDegree, self.SLOC, self.ALOC, self.localVars, self.localPtrVars, \
					self.globalVarList,	self.pointerArgs, self.isReturningPointers, self.callees, self.callers, self.height, \
					self.conditions, self.cmps, self.jmps, self.ptrAssn , self.remark, self.vulnScore, self.codeComplexity)
	def __update__(self, other):
		self.funcId = other.funcId
		self.mangName = other.mangName
		self.fileName = other.fileName
		self.startLoc = other.startLoc 	#Starting Line number
		self.exitLoc = other.exitLoc   	#Exit Line Number
		self.retType = other.retType 		#Return Type
		self.paramList = other.paramList 	#List of Parameters
		self.funcClass = other.funcClass  #Class containing func
		self.funcId = other.funcId 		#For source function info
		# self.cyclomaticNum	= other.cyclomaticNum
		# self.loopNum = other.loopNum
		# self.nestingDegree = other.nestingDegree
		self.SLOC = other.SLOC
		self.ALOC = other.ALOC
		self.localVars = other.localVars
		self.localPtrVars = other.localPtrVars
		self.globalVarList = other.globalVarList
		self.pointerArgs = other.pointerArgs
		self.isReturningPointers = other.isReturningPointers
		self.callees = other.callees
		self.callers = other.callers
		# self.height =  other.height
		self.ptrAssn = other.ptrAssn
		self.conditions = other.conditions
		self.cmps = other.cmps
		self.jmps = other.jmps
		self.remark = other.remark if other.remark is not None else self.remark

	def __update_src__(self, other):
		self.funcName = other.funcName
		self.cyclomaticNum	= other.cyclomaticNum
		self.loopNum = other.loopNum
		self.nestingDegree = other.nestingDegree
		self.height =  other.height


class InsType(Enum):
	Sub_entry = "Sub_entry"
	Blk_entry = "Blk_entry"
	Def = "Def"
	Jmp = "Jmp"
	Connector = "Connector"

class BranchType(Enum):
	Goto = "Goto"
	Call = "Call"
	Ret = "Ret"

class TargetType(Enum):
	Direct = "Direct"
	Indirect = "Indirect"

class Branch(object):
	def __init__(self,cond=None,target=None):
		self.condition = cond
		self.target = target 	#Target ID
		self.branchType = None	#(Fallthrough|Call|Ret)
		self.targetType = None	#(Direct|Indirect)
		self.retID = None	#Only set if returnable

	def __repr__(self):
		return "{%s %s if %s ? %s ;Returning %s}" % (self.targetType, self.branchType, self.condition,self.target, self.retID)       

class Effect(object):
	def __init__(self,lhs,rhs):
		self.lhs = lhs
		self.rhs = rhs
	def __repr__(self):
		return "{%s = %s}" % (self.lhs,self.rhs)

class BAPInsn(object):
	def __init__(self, blkID, tid=None, func_id=None):
		self.tid = tid
		self.address = None
		self.offset = None
		self.insn = None
		self.insType = None
		self.effects = []   #List of Side Effects
		self.targets = []   #List of Jmp Targets
		self.blk_id = blkID
		self.func_id = int(func_id)
		self.loop_id = None
		self.regValSet = GenPurpRegs()

	def __str__(self):
		# return str(self.__dict__)
		return "(ID:%s, Type:%s, BlkID:%s, Address:%s, Offset:%s, Insn:%s, Effects:%s, Targets:%s)" % (self.tid,self.insType,self.blk_id,self.address, self.offset, self.insn,self.effects, self.targets)
	# def __repr__(self):
	#   return "printing"

	def __del__(self):
		#mylogger.trace('Destructor Called')
		None

class BAPblk(object):
	def __init__(self,id):
		self.id = id
		self.insns = {} #Dict of BAPInsn <tid,BAPInsn>
		self.startAddr = None
		self.endAddr = None
		self.finalRegValSet = GenPurpRegs()
	def __del__(self):
		#mylogger.trace('Destructor Called')
		None

class BapSub(object):
	def __init__(self,id):
		self.id = id
		self.name = None
		self.address = None
		self.blks = {} #Dict of BAP BBLKs <blkid, BAPblk>
		# self.insns = {} #Dict of BAPInsn <tid,BAPInsn>
	def __del__(self):
		#mylogger.trace('Destructor Called')
		None
class GraphVisitor():
	def __init__(self, prog):
		#TODO: remove everythin related to fullCFG
		# self.fullCFG = nx.DiGraph()
		self.subList = {} #List of BapSubs
		self.sub = None
		self.blk = None
		self.curIns = None
		self.curRegVals = GenPurpRegs()
		self.callgraph = nx.DiGraph()
		self.cfgs = {}
		self.parentFunc = {}
		self.process(prog)


	def __del__(self):
		# self.fullCFG = None
		self.subList = None
		self.sub = None
		self.curIns = None

	def __addIns(self, id, curInsn, blkID, newID=None):
		'''Adding the current ins to the subroutine'''
		self.blk.insns[id] = curInsn		

		'''Initiating the self.curIns'''
		if(newID is not None):
			self.curIns = BAPInsn(blkID, newID, self.sub.id)

	def process(self, prog):
		# BAP aggressively detect function entry points. It can cause functions split into
		# several snippets. The first snippet is considered as the parent or original. For each of rest
		# of the snippets, the graphs should be added to the parent/original function.
		# self.parentFunc should record {child_name : parent_name}

		for sub in prog.subs:
			# mylogger.trace(sub)
		#TODO: Adding SUB node; Sub(Tid(0x3e97, "%00003e97"), Attrs("[]"), "%00003e97", Args("[]"), Blks("[]"))
		# Note: no attributes
			subName = sub.name.lstrip('@')
			if subName not in self.parentFunc:
				# cfg = nx.DiGraph()
				#TODO: Check if sub and cfg should be added to nodes
				# self.callgraph.add_node(sub.id.number, name=sub.name, sub=sub, cfg=cfg)
				self.sub = BapSub(sub.id.number)
				self.callgraph.add_node(sub.id.number, name=subName, type='sub')
				self.cfgs[sub.name] = nx.DiGraph()
				self.sub.name = subName
			else:
				self.sub = self.subList[self.parentFunc[subName]]

			if( len(sub.attrs) !=0 and 'address' in sub.attrs):
				# print("SUB: %s" % sub.id.name)
				# mylogger.trace("SUB: %s" % sub.id.name)
				if self.sub.address is None:
					self.sub.address = sub.attrs['address']
				for blk in sub.blks:
					self.cfgs[self.sub.name].add_node(blk.id.number, type='blk')

					blkID = blk.id.number
					noOfDefs = len(blk.defs)	#Regular BBL have definitions
					self.blk = BAPblk(blkID)
					expr = BapExpr()
					self.curRegVals = GenPurpRegs()
					if (noOfDefs > 0):
						'''
						Defs are always followed by one or more jmps, Defs exists -> Blk attributes, No blk Attrs <-> NO Defs
						Create first node instruction
						self.blk.startAddr = blk.attrs['address']
						'''
						#TODO: Check,Seems some attributes do not contain address field hence commented out
						self.curIns = BAPInsn(blkID, blkID, self.sub.id)
						self.curIns.insType = InsType.Blk_entry.value

						for bapDef in blk.defs:
							curDefID = bapDef.id.number
							address = bapDef.attrs['address']
							effect = Effect(bapDef.lhs, bapDef.rhs)

							self.curRegVals = expr.resolveInsn(bapDef,self.curRegVals)
							self.curIns.regValSet = self.curRegVals

							if(self.curIns.insType != InsType.Def.value or self.curIns.address != address):
								'''
								Inside a bbl, all definitions Fallthrough and target is Direct
								Therefore current instr is set as the target of prev instr
								Current and prev instrns have different addresses
								'''
								branch = Branch()
								branch.target = curDefID
								branch.branchType = BranchType.Goto.value
								branch.condition = 'Int(0x1, 0x1)'	#Fallthrough
								branch.targetType = TargetType.Direct.value

								self.curIns.targets.append(branch)
								self.__addIns(self.curIns.tid, self.curIns,blkID,curDefID)

								#Since current instrn is a either a new instr type or new address
								#Initiate it with new values
								self.curIns.address = address
								self.curIns.insn = bapDef.attrs['insn']
								self.curIns.offset = hex(int(address,16)-int(self.sub.address,16))
								self.curIns.effects.append(effect)
								self.curIns.insType = bapDef.constr
							elif (self.curIns.address == address):
								self.curIns.effects.append(effect)
							else:
								mylogger.warning("Warning: %s == %s case is not expected and not handled" % (self.curIns.insType, InsType.Def.value))

						for bapJmp in blk.jmps:
							curJmpID = bapJmp.id.number
							if(len(bapJmp.attrs) > 0):	#Case where JMPS (jmp/call/ret)
								address = bapJmp.attrs['address']
								if(self.curIns.address != address):	#Case where jmp(je/jge...)
									#Old instruction (Def) should connect to current node (jmp instrn)
									
									branch = Branch()
									branch.branchType = BranchType.Goto.value
									branch.condition = 'Int(0x1, 0x1)'
									branch.target = curJmpID
									branch.targetType = TargetType.Direct.value

									self.curIns.targets.append(branch)
									self.__addIns(self.curIns.tid, self.curIns,blkID,curJmpID) #New Jmp is created
									self.curIns.address = address
									self.curIns.insn = bapJmp.attrs['insn']
									self.curIns.offset = hex(int(address,16)-int(self.sub.address,16))
									self.curIns.effects.append(effect)
									self.curIns.insType = bapJmp.constr	

									#Current instr is a jmp hence should set the target
									# branch.branchType = bapJmp.constr   #Old value:
									branch = Branch()
									branch.branchType = BranchType.Goto.value
									branch.condition = 'Int(0x1, 0x1)'

									#TODO branch.targetType = TargetType.Direct.value
									'''
									This is problematic. 
									1). jmps can be Direct or Indirect.
									2). Some jmps are categarized as Call instead of Goto
									e.g. Call(Tid(0x9e, "%0000009e"), Attrs("[Attr("address", "0x39CAB"), Attr("insn", "jmp -0x31cf0")]"), Int(0x1, 0x1), (Direct(Tid(0xa2, "@__xstat"))))
									branch.targetType = bapJmp.target.constr  #Old value:TargetType.Direct.value
									'''
				
									if(bapJmp.constr == 'Call'):
										branch.targetType = bapJmp.target[0].constr
										if(bapJmp.target[0].constr == 'Direct'):
											branch.target = bapJmp.target[0].arg.number
										else:
											branch.target = bapJmp.target[0].arg
										self.callgraph.add_edge(self.sub.id, self.blk.id)
										self.callgraph.add_edge(self.blk.id, branch.target)
										if(len(bapJmp.target) > 1): 	#[Ref1] : cheking #of targets > 1, second is the Return location
											branch.retID = bapJmp.target[1].arg.number

									if(bapJmp.constr == 'Ret'):
										branch.targetType = bapJmp.target.constr
										branch.target = bapJmp.target.arg
									if(bapJmp.constr == 'Goto'):
										branch.targetType = bapJmp.target.constr
										if(bapJmp.target.constr == 'Direct'):
											branch.target = bapJmp.target.arg.number
										else:
											branch.target = bapJmp.target.arg
										self.cfgs[self.sub.name].add_edge(self.blk.id, branch.target)


									# if(bapJmp.target.constr == 'Direct'):
									# 	branch.target = bapJmp.target.arg.number
									# else:
									# 	branch.target = bapJmp.target.arg
									self.curIns.targets.append(branch)

								else:	#Case where call/ret or a second Jmp. Either way just append the branch to current Insn
									branch = Branch()
									branch.branchType = bapJmp.constr
									branch.condition = bapJmp.cond
									#Call(Tid(0x1de, "%000001de"), Attrs("[Attr("address", "0x6C5"), Attr("insn", "callq -0x5c")]"), Int(0x1, 0x1), (Direct(Tid(0x51, "@_Z5funcAi")), Direct(Tid(0x1df, "%000001df"))))
									#Call(Tid(0x146, "%00000146"), Attrs("[]"), Int(0x1, 0x1), (Direct(Tid(0x179, "@deregister_tm_clones"))))

									#TODO: two types of Calls, one with a return and without? Findout the reason;
									#TODO: For call instruction operand should be resolved and the instruction type should be changed to def to call 
									if(bapJmp.constr == 'Call'):
										branch.targetType = bapJmp.target[0].constr
										if(bapJmp.target[0].constr == 'Direct'):
											branch.target = bapJmp.target[0].arg.number
											self.curIns.insn = re.sub(r'^(\s*(?:\S+\s+){1})\S+', r'\1'+bapJmp.target[0].arg.name.lstrip('@'), self.curIns.insn)
											self.callgraph.add_edge(self.sub.id, self.blk.id)
											self.callgraph.add_edge(self.blk.id, branch.target)
										else:
											branch.target = bapJmp.target[0].arg
										if(len(bapJmp.target) > 1):     #[Ref1] : cheking #of targets > 1, second is the Return location
											branch.retID = bapJmp.target[1].arg.number
										else:
											branch.branchType = BranchType.Goto.value #Call without a return; consider as a goto                                

										self.cfgs[self.sub.name].add_edge(self.blk.id, branch.target)
									if(bapJmp.constr == 'Ret'):
										branch.targetType = bapJmp.target.constr
										branch.target = bapJmp.target.arg
									if(bapJmp.constr == 'Goto'):
										branch.targetType = bapJmp.target.constr
										if(bapJmp.target.constr == 'Direct'):
											branch.target = bapJmp.target.arg.number
										else:
											branch.target = bapJmp.target.arg
										self.cfgs[self.sub.name].add_edge(self.blk.id, branch.target)

									self.curIns.targets.append(branch)  
									# print("This is a Call or Ret or Second jmp(%s). Last INsn must be saved (%s)." % (self.curIns.id,None))
									self.__addIns(self.curIns.tid, self.curIns,blkID,None)

							else:
								#Case where bbl end with block(node)-jmp rather actual jmp insn. Update(Not append) the prev def target.
								#TODO: check ('Jmp:', Call(Tid(0x83fcb, "%00083fcb"), Attrs("[]"), Int(0x1, 0x1), (Direct(Tid(0x835e2, "@sub_21620")))))
								#It is a call without a returning location
								branch = Branch()
								# branch.target = bapJmp.target.arg.number
								branch.branchType = BranchType.Goto.value
								branch.condition = bapJmp.cond
								# branch.targetType = TargetType.Direct.value
								if(bapJmp.constr == 'Call'):
									childFuncName = bapJmp.target[0].arg.name.lstrip('@')
									# In case of function split more than into 2 pieces each child pieces should
									# appended to parent/original function
									if childFuncName:
										if subName not in self.parentFunc.keys():
											self.parentFunc[childFuncName] = subName
										else:
											self.parentFunc[childFuncName] = self.parentFunc[subName]
									self.curIns.targets = []	#TODO: is this necessary?
									branch.targetType = bapJmp.target[0].constr
									if(bapJmp.target[0].constr == 'Direct'):
										branch.target = bapJmp.target[0].arg.number
										self.callgraph.add_edge(self.sub.id, self.blk.id)
										self.callgraph.add_edge(self.blk.id, branch.target)
									else:
										branch.target = bapJmp.target[0].arg
									if(len(bapJmp.target) > 1): 	#[Ref1] : cheking #of targets > 1, second is the Return location
										branch.retID = bapJmp.target[1].arg.number
										if(bapJmp.target[1].constr == 'Direct'):
											self.cfgs[self.sub.name].add_edge(self.blk.id, branch.retID)
								else:
									branch.targetType = bapJmp.target.constr
									if(bapJmp.target.constr == 'Direct'):
										branch.target = bapJmp.target.arg.number
									else:
										branch.target = bapJmp.target.arg
									self.cfgs[self.sub.name].add_edge(self.blk.id, branch.target)
								# self.curIns.targets = []
								self.curIns.targets.append(branch)
								# print("SB:This is a node connector . Last Def must be saved.")
								self.__addIns(self.curIns.tid, self.curIns,blkID,None)


					else:
						#Not a regular Blk,but a connector, Doesn't have Defs but Jmps
						self.curIns = BAPInsn(blkID, blkID, self.sub.id)
						self.curIns.insType = InsType.Connector.value
						for bapJmp in blk.jmps:
							# if(bapJmp.constr == 'Call'):
							# if(bapJmp.constr != BranchType.Call.value):
							curJmpID = bapJmp.id.number
							branch = Branch()
							# branch.target = bapJmp.target.arg.number
							branch.branchType = BranchType.Goto.value
							branch.condition = bapJmp.cond
							# branch.targetType = bapJmp.target.constr

							if(bapJmp.constr == 'Call'):
								childFuncName = None
								if(type(bapJmp.target) is tuple):
									targetJmp = bapJmp.target[0]
								else:
									targetJmp = bapJmp.target
								if (targetJmp.constr is not 'Indirect'):
									childFuncName = targetJmp.arg.name.lstrip('@')
								# In case of function split more than into 2 pieces each child pieces should
								# appended to parent/original function
								if childFuncName:
									if subName not in self.parentFunc.keys():
										self.parentFunc[childFuncName] = subName
									else:
										self.parentFunc[childFuncName] = self.parentFunc[subName]
								branch.targetType = bapJmp.target[0].constr
								if(bapJmp.target[0].constr == 'Direct'):
									branch.target = bapJmp.target[0].arg.number
									self.callgraph.add_edge(self.sub.id, self.blk.id)
									self.callgraph.add_edge(self.blk.id, branch.target)
								else:
									branch.target = bapJmp.target[0].arg
								if(len(bapJmp.target) > 1): 	#[Ref1] : cheking #of targets > 1, second is the Return location
									branch.retID = bapJmp.target[1].arg.number
									if(bapJmp.target[1].constr == 'Direct'):
										self.cfgs[self.sub.name].add_edge(self.blk.id, branch.retID)

							if(bapJmp.constr == 'Ret'):
								branch.targetType = bapJmp.target.constr
								branch.target = bapJmp.target.arg
							if(bapJmp.constr == 'Goto'):
								branch.targetType = bapJmp.target.constr
								if(bapJmp.target.constr == 'Direct'):
									branch.target = bapJmp.target.arg.number
									self.cfgs[self.sub.name].add_edge(self.blk.id, branch.target)
								else:
									branch.target = bapJmp.target.arg

							self.curIns.targets.append(branch)
						# print("SB:This is a Connector Last Def must be saved.")
						self.__addIns(self.curIns.tid, self.curIns,blkID,None)	#TODO: Is this redundant with end __addIns			
					# print("SB:If any instuction missed save them.")
					self.__addIns(self.curIns.tid, self.curIns,blkID,None)

					del(blkID)
					del(noOfDefs)#Regular BBL have definitions
					del(expr)

					#TODO:check if there is an unhandled instrn
					# self.curIns = None
					# self.sub.blks[blkID] = self.blk

					self.sub.blks[self.blk.id] = self.blk
					self.curRegVals.temps = {}
			else:
				mylogger.warning("No attributes or no address in the attributes is not covered")
			#Leaving sub
			self.subList[self.sub.name] = self.sub
			'''RESETTING self.sub '''
			self.sub = None
			self.curIns = None #At each sub entrance curIns should be None


#TODO: Remove Graphbuilder; Not using anymore.
class GraphsBuilder(bap.adt.Visitor):
	def __init__(self):
		#TODO: remove everythin related to fullCFG
		# self.fullCFG = nx.DiGraph()
		self.subList = {} #List of BapSubs
		self.sub = None
		self.blk = None
		self.curIns = None
		self.curRegVals = GenPurpRegs()
		self.callgraph = nx.DiGraph()
		self.cfgs = {}

	def __del__(self):
		# self.fullCFG = None
		self.subList = None
		self.sub = None
		self.curIns = None	

	def enter_Sub(self,sub):
		#TODO: Adding SUB node; Sub(Tid(0x3e97, "%00003e97"), Attrs("[]"), "%00003e97", Args("[]"), Blks("[]"))
		# Note: no attributes
		cfg = nx.DiGraph()
		#TODO: Check if sub and cfg should be added to nodes
		self.callgraph.add_node(sub.id.number, name=sub.name, sub=sub, cfg=cfg)
		self.cfgs[sub.name] = cfg
		del(cfg)

		if( len(sub.attrs) !=0 and 'address' in sub.attrs):
			# print("SUB: %s" % sub.id.name)
			# mylogger.trace("SUB: %s" % sub.id.name)
			self.sub = BapSub(sub.id.number)
			self.sub.name = sub.id.name.lstrip('@')
			self.sub.address = sub.attrs['address']

	def leave_Sub(self,sub):
		self.subList[sub.id.name.lstrip('@')] = self.sub
		'''RESETTING self.sub '''
		self.sub = None
		self.curIns = None #At each sub entrance curIns should be None

	def __addIns(self,id,curInsn,blkID,newID=None):
		'''Adding the current ins to the subroutine'''
		self.blk.insns[id] = curInsn		

		'''Initiating the self.curIns'''
		if(newID is not None):
			self.curIns = BAPInsn(blkID, newID, self.sub.id)
		
	def enter_Blk(self,blk):
		self.cfgs[self.sub.name].add_node(blk.id.number, blk=blk)

		blkID = blk.id.number
		noOfDefs = len(blk.defs)	#Regular BBL have definitions
		self.blk = BAPblk(blkID)
		expr = BapExpr()
		self.curRegVals = GenPurpRegs()
		if (noOfDefs > 0):
			'''
			Defs are always followed by one or more jmps, Defs exists -> Blk attributes, No blk Attrs <-> NO Defs
			Create first node instruction
			self.blk.startAddr = blk.attrs['address']
			'''
			#TODO: Check,Seems some attributes do not contain address field hence commented out
			self.curIns = BAPInsn(blkID, blkID, self.sub.id)
			self.curIns.insType = InsType.Blk_entry.value

			for bapDef in blk.defs:
				curDefID = bapDef.id.number
				address = bapDef.attrs['address']
				effect = Effect(bapDef.lhs, bapDef.rhs)

				self.curRegVals = expr.resolveInsn(bapDef,self.curRegVals)
				self.curIns.regValSet = self.curRegVals

				if(self.curIns.insType != InsType.Def.value or self.curIns.address != address):
					'''
					Inside a bbl, all definitions Fallthrough and target is Direct
					Therefore current instr is set as the target of prev instr
					Current and prev instrns have different addresses
					'''
					branch = Branch()
					branch.target = curDefID
					branch.branchType = BranchType.Goto.value
					branch.condition = 'Int(0x1, 0x1)'	#Fallthrough
					branch.targetType = TargetType.Direct.value

					self.curIns.targets.append(branch)
					self.__addIns(self.curIns.tid, self.curIns,blkID,curDefID)

					#Since current instrn is a either a new instr type or new address
					#Initiate it with new values
					self.curIns.address = address
					self.curIns.insn = bapDef.attrs['insn']
					self.curIns.offset = hex(int(address,16)-int(self.sub.address,16))
					self.curIns.effects.append(effect)
					self.curIns.insType = bapDef.constr
				elif (self.curIns.address == address):
					self.curIns.effects.append(effect)
				else:
					mylogger.trace("Warning: %s == %s case is not expected and not handled" % (self.curIns.insType, InsType.Def.value))		

			for bapJmp in blk.jmps:
				curJmpID = bapJmp.id.number
				if(len(bapJmp.attrs) > 0):	#Case where JMPS (jmp/call/ret)
					address = bapJmp.attrs['address']
					if(self.curIns.address != address):	#Case where jmp(je/jge...)
						#Old instruction (Def) should connect to current node (jmp instrn)
						
						branch = Branch()
						branch.branchType = BranchType.Goto.value
						branch.condition = 'Int(0x1, 0x1)'
						branch.target = curJmpID
						branch.targetType = TargetType.Direct.value

						self.curIns.targets.append(branch)
						self.__addIns(self.curIns.tid, self.curIns,blkID,curJmpID) #New Jmp is created
						self.curIns.address = address
						self.curIns.insn = bapJmp.attrs['insn']
						self.curIns.offset = hex(int(address,16)-int(self.sub.address,16))
						self.curIns.effects.append(effect)
						self.curIns.insType = bapJmp.constr	

						#Current instr is a jmp hence should set the target
						# branch.branchType = bapJmp.constr   #Old value:
						branch = Branch()
						branch.branchType = BranchType.Goto.value
						branch.condition = 'Int(0x1, 0x1)'

						#TODO branch.targetType = TargetType.Direct.value
						'''
						This is problematic. 
						1). jmps can be Direct or Indirect.
						2). Some jmps are categarized as Call instead of Goto
						e.g. Call(Tid(0x9e, "%0000009e"), Attrs("[Attr("address", "0x39CAB"), Attr("insn", "jmp -0x31cf0")]"), Int(0x1, 0x1), (Direct(Tid(0xa2, "@__xstat"))))
						branch.targetType = bapJmp.target.constr  #Old value:TargetType.Direct.value
						'''
	
						if(bapJmp.constr == 'Call'):
							branch.targetType = bapJmp.target[0].constr
							if(bapJmp.target[0].constr == 'Direct'):
								branch.target = bapJmp.target[0].arg.number
							else:
								branch.target = bapJmp.target[0].arg
							if(len(bapJmp.target) > 1): 	#[Ref1] : cheking #of targets > 1, second is the Return location
								branch.retID = bapJmp.target[1].arg.number

						if(bapJmp.constr == 'Ret'):
							branch.targetType = bapJmp.target.constr
							branch.target = bapJmp.target.arg
						if(bapJmp.constr == 'Goto'):
							branch.targetType = bapJmp.target.constr
							if(bapJmp.target.constr == 'Direct'):
								branch.target = bapJmp.target.arg.number
							else:
								branch.target = bapJmp.target.arg


						# if(bapJmp.target.constr == 'Direct'):
						# 	branch.target = bapJmp.target.arg.number
						# else:
						# 	branch.target = bapJmp.target.arg
						self.curIns.targets.append(branch)

					else:	#Case where call/ret or a second Jmp. Either way just append the branch to current Insn
						branch = Branch()
						branch.branchType = bapJmp.constr
						branch.condition = bapJmp.cond
						#Call(Tid(0x1de, "%000001de"), Attrs("[Attr("address", "0x6C5"), Attr("insn", "callq -0x5c")]"), Int(0x1, 0x1), (Direct(Tid(0x51, "@_Z5funcAi")), Direct(Tid(0x1df, "%000001df"))))
						#Call(Tid(0x146, "%00000146"), Attrs("[]"), Int(0x1, 0x1), (Direct(Tid(0x179, "@deregister_tm_clones"))))

						#TODO: two types of Calls, one with a return and without? Findout the reason;
						#TODO: For call instruction operand should be resolved and the instruction type should be changed to def to call 
						if(bapJmp.constr == 'Call'):

							branch.targetType = bapJmp.target[0].constr
							if(bapJmp.target[0].constr == 'Direct'):
								branch.target = bapJmp.target[0].arg.number
								self.curIns.insn = re.sub(r'^(\s*(?:\S+\s+){1})\S+', r'\1'+bapJmp.target[0].arg.name.lstrip('@'), self.curIns.insn)

							else:
								branch.target = bapJmp.target[0].arg
							if(len(bapJmp.target) > 1):     #[Ref1] : cheking #of targets > 1, second is the Return location
								branch.retID = bapJmp.target[1].arg.number
							else:
								branch.branchType = BranchType.Goto.value #Call without a return; consider as a goto                                

						if(bapJmp.constr == 'Ret'):
							branch.targetType = bapJmp.target.constr
							branch.target = bapJmp.target.arg
						if(bapJmp.constr == 'Goto'):
							branch.targetType = bapJmp.target.constr
							if(bapJmp.target.constr == 'Direct'):
								branch.target = bapJmp.target.arg.number
							else:
								branch.target = bapJmp.target.arg							

						self.curIns.targets.append(branch)  
						# print("This is a Call or Ret or Second jmp(%s). Last INsn must be saved (%s)." % (self.curIns.id,None))
						self.__addIns(self.curIns.tid, self.curIns,blkID,None)

				else:	#Case where bbl end with block(node)-jmp rather actual jmp insn. Update(Not append) the prev def target.
					#TODO: check ('Jmp:', Call(Tid(0x83fcb, "%00083fcb"), Attrs("[]"), Int(0x1, 0x1), (Direct(Tid(0x835e2, "@sub_21620")))))
					#It is a call without a returning location
					branch = Branch()
					# branch.target = bapJmp.target.arg.number
					branch.branchType = BranchType.Goto.value
					branch.condition = bapJmp.cond
					# branch.targetType = TargetType.Direct.value
					if(bapJmp.constr == 'Call'):
						self.curIns.targets = []	#TODO: is this necessary?
						branch.targetType = bapJmp.target[0].constr
						if(bapJmp.target[0].constr == 'Direct'):
							branch.target = bapJmp.target[0].arg.number
						else:
							branch.target = bapJmp.target[0].arg
						if(len(bapJmp.target) > 1): 	#[Ref1] : cheking #of targets > 1, second is the Return location
							branch.retID = bapJmp.target[1].arg.number
					else:					
						branch.targetType = bapJmp.target.constr
						if(bapJmp.target.constr == 'Direct'):
							branch.target = bapJmp.target.arg.number
						else:
							branch.target = bapJmp.target.arg
					# self.curIns.targets = []
					self.curIns.targets.append(branch)
					# print("SB:This is a node connector . Last Def must be saved.")
					self.__addIns(self.curIns.tid, self.curIns,blkID,None)				


		else:		#Not a regular Blk,but a connector, Doesn't have Defs but Jmps
			# print("No defs, only a jmp")
			self.curIns = BAPInsn(blkID, blkID, self.sub.id)
			self.curIns.insType = InsType.Connector.value
			for bapJmp in blk.jmps:

				if(bapJmp.constr != BranchType.Call.value):
					curJmpID = bapJmp.id.number
					branch = Branch()
					# branch.target = bapJmp.target.arg.number
					branch.branchType = BranchType.Goto.value
					branch.condition = bapJmp.cond
					# branch.targetType = bapJmp.target.constr

					if(bapJmp.constr == 'Call'):
						branch.targetType = bapJmp.target[0].constr
						if(bapJmp.target[0].constr == 'Direct'):
							branch.target = bapJmp.target[0].arg.number
						else:
							branch.target = bapJmp.target[0].arg
						if(len(bapJmp.target) > 1): 	#[Ref1] : cheking #of targets > 1, second is the Return location
							branch.retID = bapJmp.target[1].arg.number

					if(bapJmp.constr == 'Ret'):
						branch.targetType = bapJmp.target.constr
						branch.target = bapJmp.target.arg
					if(bapJmp.constr == 'Goto'):
						branch.targetType = bapJmp.target.constr
						if(bapJmp.target.constr == 'Direct'):
							branch.target = bapJmp.target.arg.number
						else:
							branch.target = bapJmp.target.arg

					self.curIns.targets.append(branch)	
			# print("SB:This is a Connector Last Def must be saved.")
			self.__addIns(self.curIns.tid, self.curIns,blkID,None)	#TODO: Is this redundant with end __addIns			
		# print("SB:If any instuction missed save them.")
		self.__addIns(self.curIns.tid, self.curIns,blkID,None)

		del(blkID)
		del(noOfDefs)#Regular BBL have definitions
		del(expr)

		#TODO:check if there is an unhandled instrn
		# self.curIns = None
		# self.sub.blks[blkID] = self.blk
	def leave_Blk(self,blk):
		self.sub.blks[self.blk.id] = self.blk
		self.curRegVals.temps = {}

	def enter_Call(self, jmp):
		callee = direct(jmp.target[0])
		if callee:
			self.callgraph.add_edge(self.sub.id, self.blk.id)
			self.callgraph.add_edge(self.blk.id, callee.number, jmp=jmp)
		fall = direct(jmp.target[1]) if len(jmp.target) == 2 else None
		if fall:
			self.cfgs[self.sub.name].add_edge(self.blk.id, fall.number, jmp=jmp)
		del(callee)
		del(fall)

	def enter_Goto(self, jmp):
		dst = direct(jmp.target)
		if dst:
			self.cfgs[self.sub.name].add_edge(self.blk.id, dst.number, jmp=jmp)
		del(dst)

	def enter_Exn(self, exn):
		fall = exn.target[1]
		if fall:
			self.cfgs[self.sub.name].add_edge(self.blk.id, fall.number, exn=exn)
		del(fall)

def direct(jmp):
	return jmp.arg if jmp is not None and jmp.constr == 'Direct' else None


class sigBIN(object):
	def __init__(self,binFile,dbconn=None):
		mylogger.trace("Calling BAP")
		proj = bap.run(binFile)
		self.prog = proj.program
		# graphs = GraphsBuilder()
		graphs = GraphVisitor(self.prog)

		# graphs.run(proj.program)
		self.subList = graphs.subList
		self.srcFuncInfoList = []
		self.dbconn = dbconn
		self.elfFile = ELFFile(open(binFile, 'rb'))
		self.dwarfinfo = self.elfFile.get_dwarf_info()
		self.cfgs = graphs.cfgs
		self.cg = graphs.callgraph

		del(graphs)
	
	def __del__(self):
		mylogger.trace("Destructor called")

	def extractFuncInfo(self):
		demangledFuncInfoList = []
		binFuncInfoList = getBinFuncInfo(self.elfFile, self.cfgs, self.dbconn)
		demangledFuncInfoList = list(getDemangledFunctions(binFuncInfoList))
		return demangledFuncInfoList

	def genBinNodes(self,funcMangName, funcID):
		mylogger.info("Gen bin node for %s" % funcMangName)

		for blkidx in self.subList[funcMangName].blks:
			blk = self.subList[funcMangName].blks[blkidx]
			for idx in blk.insns:
				bapIns = blk.insns[idx]
				q = "g.addVertex("
				for attr, value in bapIns.__dict__.items():
					q = q + attr + ":'" + str(value).strip("\n").strip("'").lower() + "',"
				q_addNode = q + ",kind:'"+str("ASM")+"',functionId:"+str(funcID)+").dedup"

				try:
					self.dbconn.runGremlinQuery(q_addNode)
				except:
					mylogger.warning( colored('Query failed in genNode: %s' % q,'yellow') )

			del(blk)
	'''
	Iterate line - addr info. It does not contain the respective function info, hence ID. To get the
	corresponding ID each line info must check with each src functionInfo list.
	genSrcAsmEdges called seperately because looping through line info is done only once.
	'''
	def genSrcAsmEdges(self, cuFuncInfoList):
		mylogger.info("Generating source assembly edges")
		for cu in self.dwarfinfo.iter_CUs():
			lineProg = self.dwarfinfo.line_program_for_CU(cu)
			cuOffset = cu.cu_offset
			for line in lineProg.get_entries():
				if line.state is not None and line.state.line != 0:
					fileName = bytes2str(lineProg['file_entry'][line.state.file - 1].name)
					srcLine = line.state.line
					binAddr = line.state.address
					for funcInfo in cuFuncInfoList[cuOffset]:
						#TODO: Why binAddr? srcLine is not working. Which one is correct?
						if binAddr >= funcInfo.startLoc and binAddr < funcInfo.exitLoc:

							funcName = funcInfo.funcName
							funcInfo.fileName = fileName
							# mylogger.info("Adding Line-Address edges for %s in %s" % (funcName, fileName))
							if funcInfo in self.srcFuncInfoList:
								idx = self.srcFuncInfoList.index(funcInfo)
								funcId = self.srcFuncInfoList[idx].funcId

								q_addEdge = "g.addEdge(g.V().has('location').filter { \
									it.location.startsWith('%d:') && it.functionId == %d && it.code != '' || \
									it.location.startsWith('%d:') && it.name == '%s' || \
									it.location.startsWith('%d:') && it.functionId == %d && it.code != '' }.next(), \
									g.V().has('address','%s').filter{ it.functionId == %d }.next(),'src2line')" \
								% (srcLine, funcId, srcLine-1, funcName, srcLine-1, funcId, hex(binAddr), funcId)

								try:
									self.dbconn.runGremlinQuery(q_addEdge)
									# mylogger.info( colored('GenSrcAsmEdges query Succesful: %s' % q_addEdge, 'cyan') )
								except Exception as e:
									None
									# TODO: When testing, following should be uncommented and checked
									# mylogger.error( colored('GenSrcAsmEdges query %s Failed due to \n%s' % (q_addEdge, e), 'red') )
								break
							else:
								mylogger.warning(colored("FuncInfo for %s not found in srcFuncInfoList" % funcName, 'yellow'))

	def genBinEdges(self,funcMangName):
		for blkidx in self.subList[funcMangName].blks:
			blk = self.subList[funcMangName].blks[blkidx]
			for idx in blk.insns:
				bapIns = blk.insns[idx]
				# label = "falls"
				for branch in bapIns.targets:
					targetNode = branch.target
					label = branch.branchType
					targetType = branch.targetType
					if targetType == 'Direct' and label != 'Call':
						q_addEdge = "g.addEdge(g.V().has('tid','"+ str(bapIns.tid) +"').next(), g.V().has('tid','" + str(targetNode) + "').next(),'" + label + "')"
						try:
							self.dbconn.runGremlinQuery(q_addEdge)
						except:
							mylogger.warning( colored('Query failed in genEdge: %s' % q_addEdge,'yellow') )
			del(blk)


	def generateCPG(self, demangledFuncInfoList):
		mylogger.trace("Executing generateCPG")
		db = self.dbconn
		dwarf_info = self.elfFile.get_dwarf_info()

		# Strip to only filename, as getLineInfo can recognize
		# only the filenames right now
		# TODO: Need to check how dwarfwould distinguish between
		# two identical filenames in different directories

		#TODO: genSrcAsmEdges must be called only if above succeed
		# line_info = getLineInfo(dwarf_info, sf, se[0], se[1])
		# The starting line of a function was retrieved from the
		# source cpg.  This is the line the function was defined.
		# However, this may not correspond to the first line of
		# the function according to the dwarf info!  It appears to
		# start with the opening curly brace, which may not be
		# on the same line as the function definition.  Therefore,
		# we need to take the lowest line number we found in the
		# line info to use to find the start address.
		self.srcFuncInfoList = getSrcFuncInfo(db)
		fileNameList = getFileNameListByCU(dwarf_info)
		cuFuncInfoList = self.decode_funcname(fileNameList)
		totalFunc = len(demangledFuncInfoList)
		for demIdx in range(len(demangledFuncInfoList)):
			binFuncInfo = demangledFuncInfoList[demIdx]
			mang = binFuncInfo.mangName
			demang = binFuncInfo.funcName

			funcID = None
			if binFuncInfo in self.srcFuncInfoList:
				#This is where we should merge two corresponding record from srcFuncInfoList to binFuncInfo
				srcIdx = self.srcFuncInfoList.index(binFuncInfo)	#Getting the corresponding index from src-func-info list
				binFuncInfo.__update__(self.srcFuncInfoList[srcIdx])
				self.srcFuncInfoList[srcIdx].__update_src__(binFuncInfo)

				funcID = self.srcFuncInfoList[srcIdx].funcId
				mylogger.trace( 'Adding binary cpg nodes for [%s]; Demangled Name: %s [%d of %d]' % (mang, demang, demIdx+1, totalFunc) )

				self.genBinNodes(mang, funcID)
				self.genBinEdges(mang)
			# else:
			# 	mylogger.trace("%s not found on src List" % binFuncInfo)

		#TODO: If call edges must be added uncomment following to call genBinEdges(mang)
		# for idx in range(len(mangDemangTpl)):
		# 	funcInfo = mangDemangTpl[idx]
		# 	mang = funcInfo[0]
		# 	demang = funcInfo[1]
		# 	# funcID = getFunctionId(db,demang)
		# 	funcID = None
		# 	if demang[-1] in self.funcListByName and mang in self.subList:
		# 		funcID = self.funcListByName[demang[-1]]
		# 		mylogger.trace( 'Adding binary cpg edges for [%s]; Demangled Name: %s [%d of %d]' % (mang, demang[0], idx, totalFunc) )
		# 		self.genBinEdges(mang)

		self.genSrcAsmEdges(cuFuncInfoList)

		del(db)
		del(dwarf_info)


	def decode_funcname(self, fileNameList):
		# Go over all DIEs in the DWARF information, looking for a subprogram
		# entry with an address range that includes the given address. Note that
		# this simplifies things by disregarding subprograms that may have
		# split address ranges. Provide <cu_offset>-> [list_of_funcINfo]

		cuFuncInfoList = {}

		for cu in self.dwarfinfo.iter_CUs():
			cuFuncInfoList[cu.cu_offset] = []
			for die in cu.iter_DIEs():
				try:
					if die.tag == 'DW_TAG_subprogram':
						lowpc = die.attributes['DW_AT_low_pc'].value
						funcName = bytes2str(die.attributes['DW_AT_name'].value)
						# DWARF v4 in section 2.17 describes how to interpret the
						# DW_AT_high_pc attribute based on the class of its form.
						# For class 'address' it's taken as an absolute address
						# (similarly to DW_AT_low_pc); for class 'constant', it's
						# an offset from DW_AT_low_pc.

						highpc_attr = die.attributes['DW_AT_high_pc']
						fileName = fileNameList[cu.cu_offset, (die.attributes['DW_AT_decl_file'].value)].split('/')[-1]
						highpc_attr_class = describe_form_class(highpc_attr.form)
						if highpc_attr_class == 'address':
							highpc = highpc_attr.value
						elif highpc_attr_class == 'constant':
							highpc = lowpc + highpc_attr.value
						else:
							mylogger.error(colored('invalid DW_AT_high_pc class:%s' % highpc_attr_class, 'red'))
							continue
						cuFuncInfoList[cu.cu_offset].append(FuncInfo(funcName, fileName, lowpc, highpc))
				except KeyError:
					continue
		return cuFuncInfoList

	def getCFG(self):
		return self.cfgs

	def getBAPSubList(self):
		return self.subList

	def getCG(self):
		return self.cg

	def getFuncList(self):
		return self.funcListByName, self.funcListById

	def getUpdatedFuncList(self):
		return self.srcFuncInfoList

	def getInsByFuncOffset(self,funcMangName,offset):

		for item in self.subList[funcMangName].insns:
			if (self.subList[funcMangName].insns[item].offset == offset):
				print(self.subList[funcMangName].insns[item])

	def printEffects(self,funcMangName):
		for blkidx in self.subList[funcMangName].blks:
			blk = self.subList[funcMangName].blks[blkidx]
			for insidx in blk.insns:
				curNode = blk.insns[insidx]
				e = curNode.effects
				for x in range(len(e)):
					mylogger.trace(e[x])
			del(blk)

	def drawSrcCFG(self, funcName):
		os.system("echo 'getFunctionsByName(\"" + funcName + "\").id' | joern-lookup -g| tail -n 1 | joern-plot-proggraph -cfg > ~/logs/\"" + funcName+"\"_src_cfg.dot;")


	def drawFuncCFG(self,funcMangName):
		graph=pgv.AGraph(strict=False,directed=True)

		for blkidx in self.subList[funcMangName].blks:
			blk = self.subList[funcMangName].blks[blkidx]
			for insidx in blk.insns:
				curNode = blk.insns[insidx]
				label="%s-%s\n%s" % (curNode.tid,curNode.insType ,curNode.insn)

				if(curNode.insType == 'Def'):
					graph.add_node(curNode.tid,label=label,color='blue')
				elif(curNode.insType == 'Blk_entry' or curNode.insType == 'Connector'):
					graph.add_node(curNode.tid,label=label,style='filled',fillcolor='yellow')
				else:
					graph.add_node(curNode.tid,label=label,style='filled', fillcolor='red')
				for branch in curNode.targets:
					toNode = branch.target
					if (toNode is not None):
						graph.add_edge(curNode.tid,toNode,color='green')
					if(branch.branchType == 'Call'):
						graph.add_edge(curNode.tid,branch.retID,color='red')
			del(blk)

		graph.layout()
		# graph.write(funcName + ".dot")
		pathHome = os.getenv("HOME")
		pathFile = os.path.join(pathHome, "logs", funcName +"_bin_cfg.dot")
		graph.write(pathFile)
		del(graph)
		

		# s = Source.from_file(funcName + ".dot")
		# s.view()
		# Use "dot -Tsvg funcName.dot -o cfg.svg; eog cfg.svg" in log folder of host



	def generateCG(self):
		graph=pgv.AGraph(strict=False,directed=True)
		graphNodeID = None
		for sub in self.subList:
			graphNodeID = self.subList[sub].id
			graph.add_node(self.subList[sub].id,label=self.subList[sub].name, color='blue')
			for blkidx in self.subList[sub].blks:
				blk = self.subList[sub].blks[blkidx]
				for insidx in blk.insns:
					curNode = blk.insns[insidx]
					label="%s-%s\n%s" % (curNode.tid,curNode.insType ,curNode.insn)

					for branch in curNode.targets:
						if(branch.branchType == 'Call'):
							graph.add_node(curNode.blk_id, label=label, color='blue')
							graph.add_edge(graphNodeID, curNode.blk_id, label=label, color='red')
							# graph.add_node(curNode.tid, label=label, color='blue')
							graph.add_edge(curNode.blk_id, branch.target, label='Return', color='green')
							graphNodeID = curNode.blk_id
					# graphNodeID = curNode.blk_id
		graph.layout()
		# graph.write("CG.dot")
		pathHome = os.getenv("HOME")
		pathFile = os.path.join(pathHome, "logs", "CG.dot")
		graph.write(pathFile)		
		# s = Source.from_file("CG.dot")
		# s.view()
		# Use "dot -Tsvg CG.dot -o cg.svg; eog cg.svg" in log folder of host

'''
        Get dictionary of DIEs (debugging information entries) containing
        filename data for each compilation unit, indexed by
        their compilation unit's offset
'''
def getCompilationUnitTopDIEs(elf):
	dwarfinfo = elf.get_dwarf_info()
	die_dict = {}
	for cu in dwarfinfo.iter_CUs():
		top_DIE = cu.get_top_DIE()
		die_dict[cu.cu_offset] = top_DIE
	return die_dict


def getFunctionsList(db):
	q_getFuncs = """g.V().has('type','Function').dedup"""
	funcNodes = db.runGremlinQuery(q_getFuncs)
	funcList = {}
	for funcNode in funcNodes:
		nodeId = int(funcNode.ref.split('/')[1])
		funcName = funcNode.properties['name']
		q_funcFile = """g.v(%d).in.filepath.dedup""" % nodeId
		funcFile = db.runGremlinQuery(q_funcFile)
		#TODO: We only consider first file return. In case of redundant function names, can cause incorrect results
		# funcList[funcName] = funcFile[0].split('./')[1]
		if (len(funcFile) != 0):
			funcList[funcName] = funcFile[0].split('/')[-1]
	return funcList

'''
	Retrieve mangled function names from binary, with supplemental info
        containing which file they came from if available
        (externally defined functions in libraries don't have address info in the symbol table)
'''
def getBinFuncInfo(elf, bapCfgList, db):
	funcFileList = getFunctionsList(db)
	# mylogger.trace(funcFileList)
	die_dict = getCompilationUnitTopDIEs(elf)
	aranges = elf.get_dwarf_info().get_aranges() # aranges map addresses to compilation units
	binFuncInfoList = []
	for s in elf.iter_sections():
		if isinstance(s, elftools.elf.sections.SymbolTableSection):
			for sym in s.iter_symbols():
				#TODO: no need to consider symbol names starting with "_" or "__"
				symbolName = sym.name.split("@@")[0]
				if sym.entry['st_info']['type'] == 'STT_FUNC' and symbolName in bapCfgList:
					func_addr = sym.entry.st_value
					file_name = None
					# If there is no aranges section, or no corresponding die entry,
					# Simply don't set a file path.  This will lead to problems if
					# this info is present for the source but somehow not in the binary.
					cfg = bapCfgList[symbolName]
					if func_addr != 0 and aranges is not None:
						offs = aranges.cu_offset_at_addr(func_addr)
						if offs in die_dict:
							# file_path = die_dict[offs].get_full_path()
							file_name = die_dict[offs].get_full_path().split('/')[-1]
							# funcInfo = FuncInfo(sym.name, file_name, None, None, None)
							# cfg = bapCfgList[symbolName]
							# funcInfo.cyclomaticNum = get_cyclomatic_complexity(cfg)
							# funcInfo.loopNum = get_total_loops(cfg)
							# funcInfo.nestingDegree = get_nestingDegree(cfg)
							# funcInfo.height = get_height(self.cg)
							# binFuncInfoList.append(funcInfo)
							# del(cfg)
					else:
						#Some compilers do not include aranges section. File name info will be unknown
						mylogger.trace("Checking symbol %s : %s" % (sym.name, symbolName))
						if sym.name in funcFileList:
							file_name = funcFileList[symbolName]
						else:
							file_name = 'unknown'
					funcInfo = FuncInfo(sym.name, file_name, None, None, None)
					funcInfo.address = hex(func_addr)
					funcInfo.cyclomaticNum = get_cyclomatic_complexity(cfg)
					funcInfo.loopNum = get_total_loops(cfg)
					binFuncInfoList.append(funcInfo)
					del(cfg)
	return binFuncInfoList

'''
	Some functions have content like @@GLIBCXX_3.4, which cxxfilt does not recognize.  Remove it.
'''
def stripFuncLibData(funcInfo):
	ind = funcInfo.funcName.find('@@')
	if ind != -1:
		funcInfo.funcName = funcInfo.funcName[:funcInfo.funcName.find('@@')]
	return funcInfo

'''
	Demangle function, but for functions cxxfilt can't figure out how to demangle print a warning
	and return None.

	Also, functions are stored in a sustantially different format in the database than cxxfilt produces,
	so we need to modify the output by splitting the function into its constituent parts, such as
	namespace, class, and function.

	Currently will break when it comes to generics, as it requires more complex parsing.
'''
def demangleFunction(funcInfo):
	try:
		funcInfo.mangName = funcInfo.funcName
		res = cxxfilt.demangle(funcInfo.funcName)
		# Remove function parameters
		ind = res.find('(')
		if ind != -1:
			res = res[:ind]
		res = res.split('::')
		funcInfo.funcName = res[-1]

		# Takes whatever is present before function name to be class, and if there
		# is a namespace and a class, everything before the class is discarded.
		# TODO: Retain namespace info, but this won't be useful until we support C++
		if len(res) > 1:
			funcInfo.funcClass = res[-2]
		return funcInfo
	except cxxfilt.InvalidName:
		mylogger.warning( colored('Cannot demangle %s' % funcInfo.mangName, 'yellow') )
		return funcInfo

def getDemangledFunctions(binFuncInfoList):
	binFuncInfoList = map(stripFuncLibData, binFuncInfoList)
	return map(demangleFunction, binFuncInfoList)

'''
	Using the function's demangled name, retrieve its id, which can be used to retrieve
	other attributes.

	TODO: I am not matching on the functions' full signatures, which means I will not catch
	two functions with identical names but different arguments.
	I am currently handling identical function names in different classes, but not
	identical functions in different namespaces or method overloading.

	An idea for a different approach would be to get the source line of the function definition
	from the binary itself and doing a query based on _that_, avoiding the need to try to find
	the function based on its name, and instead writing a query based on source file and line
	number.  This would require that the line number information in a binary can consistently
	obtain the function declaration line from the function start address.
'''
def getFunctionId(db, demangled):
	q_getFucId = '''g.V().filter{ it.type == 'Function' && it.name == '%s' }.id''' % demangled[-1]
	# If demangled function has more than just the function component, assume the component preceding
	# the last is the class name, and search for that.
	if len(demangled) > 1:
		q_getFucId = '''g.V().has('type','Function').has('name','%s').as('x').in.has('name',
			'%s').back('x').id''' % (demangled[-1],demangled[-2])
		#query = '''g.V().has('type','Function').has('name','%s').as('x').id''' % (demangled[-1])
		#query = '''g.V().has('type','Function').has('name','%s').in.has('type','File').filepath''' % (demangled[-1])
	try:
		res = db.runGremlinQuery(q_getFucId)
		if len(res) > 1:
			raise ValueError # Multiple source files; will need to address if encountered
		elif len(res) == 0:
			return None # No source file
		return res[0]
	except:
		# Decline to print error for now, as many functions do not have any corresponding source,
		# such as 
		mylogger.error( colored('Query failed in getFunctionId: %s' % (query), 'yellow') )
		return None		  

'''
	Using a function id, retrieve its source filepath.
'''
def getFuncSourceFile(db, node_id):
	#query = '''g.V(%d).in.filter{ it.type == 'File'}.filepath''' % node_id
	q_getFilePath = '''g.V().filter{ it.id == %d}.in.filter{ it.type == 'File' }.filepath''' % node_id
	try:
		res = db.runGremlinQuery(q_getFilePath)
		# In which situation could an id yield multiple results?  This will raise an alarm if
		# it does happen.
		if len(res) > 1:
			raise ValueError
		return res[0]
	except:
		mylogger.error( colored('Query failed in getSourceFile: %s' % (query), 'yellow') )
		return None

'''
	Getting function Information from SRC CPG
	getSrcFuncInfo() : Populate a List with Function Info: Name Class Filepath RetType ParamList startLoc exitLoc
	key = (name, class, file)
	srcFuncInfoList[<id>] = FuncInfo(startLoc, exitLoc, RetType, ParamList...)
'''
def getSrcFuncInfo(db):
	srcFuncInfoList = []
	q_getAllFiles = "g.V().has('type','File')"
	allFiles = db.runGremlinQuery(q_getAllFiles)
	for file in allFiles:
		file_id = int(file.ref.split('/')[1])
		#TODO: Probably we should consider the full path here. Caution: will effect funcInfo comparison.
		fileName = file.properties['filepath'].split('/')[-1]
		filePath = None
		q_getFuncs = '''g.v(%d).out.has('type','Function').dedup''' % file_id
		funcs = db.runGremlinQuery(q_getFuncs)
		for func in funcs:
			func_id = int(func.ref.split('/')[1])
			funcName = func.properties['name']
			startLoc = int(func.properties['location'].split(':')[0])
			# q_getFuncExit = '''g.V().filter{ it.functionId == %d && 
			# 	it.type == 'CFGExitNode'}.inE('FLOWS_TO').outV().location.dedup''' % func_id
			# res = db.runGremlinQuery(q_getFuncExit)
			# mylogger.trace(q_getFuncExit)
			# if res[0] != None:
			# exitLoc = int(res[0].split(':')[0])	#SLOC + start address can be used to get this
			q_getRetType = '''g.V().filter{ it.functionId == %d }.has('type','ReturnType').code.dedup''' % func_id
			retType = db.runGremlinQuery(q_getRetType)
			# retType = ';'.join(map(str,db.runGremlinQuery(q_getRetType)))
			q_getParamList = '''g.V().filter{ it.functionId == %d}.has('type','ParameterList').code.dedup''' % func_id
			# paramList = str(db.runGremlinQuery(q_getParamList)).replace(",",";")
			p = db.runGremlinQuery(q_getParamList)
			paramList = len([x for x in p[0].split(',') if x])
			# paramList = ';'.join(map(str,db.runGremlinQuery(q_getParamList)))
			# listToStr = ' '.join(map(str, s))
			q_getSLOC = '''g.V().filter{ it.functionId == %d }.has('location').dedup''' % func_id
			SLOC = len(db.runGremlinQuery(q_getSLOC))
			q_getCallees = '''g.V().filter{ it.functionId == %d }.has('type','Callee').dedup''' % func_id
			callees = len(db.runGremlinQuery(q_getCallees))
			q_getConds = '''g.V().has('code').filter{ it.functionId == %d }.has('type','Condition').dedup''' % func_id
			conds = len(db.runGremlinQuery(q_getConds))
			# q_getPtrAssignments = '''g.V().filter{it.functionId == %d && it.type == 'AssignmentExpr'}.and(_().lval.filter{ it.code.contains('*')}, _().rval.filter{ it.code.contains('*')})''' % func_id
			q_getPtrAssignments = '''g.V().filter{it.functionId == %d }.has('type','AssignmentExpr').as('x').lval.filter{ it.code.contains('*')}.back('x')''' % func_id
			ptrAssn = len(db.runGremlinQuery(q_getPtrAssignments))		
			q_getCallers = '''g.V().has('code').filter{ it.type == 'Callee' && it.code.contains('%s')}.dedup''' % funcName
			callers = len(db.runGremlinQuery(q_getCallers))

			srcFuncInfoList.append(FuncInfo(funcName, fileName, startLoc, startLoc+SLOC, func_id, None, retType, paramList, None, \
				0, 0, 0, SLOC, 0, 0, 0, None, 0, 0, callees, callers, 0, conds, 0, 0, ptrAssn, None))
			# else:
			# 	mylogger.warning(colored('Check: %s' % (q_getFuncExit), 'yellow') )
	return srcFuncInfoList


'''
	Using a function id, retrieve its start and end lines.
'''
def getFuncStartAndEnd(db, node_id):
	start = 0
	q_getFuncStart = '''g.V().filter{ it.id == %d && it.type == 'Function' }.location''' % node_id
	try:
		res = db.runGremlinQuery(q_getFuncStart)
		if len(res) > 1:
			raise ValueError
		# Result contains more than just line information, but right now we just want
		# the line, which is the first element.  Elements are separated by colons.
		start = int(res[0].split(':')[0])
	except:
		mylogger.error( colored('Query failed in getStartAndEnd: %s' % (query), 'yellow') )
		return None
	q_getFuncExit = '''g.V().filter{ it.functionId == %d && 
				it.type == 'CFGExitNode'}.inE('FLOWS_TO').outV().location.dedup''' % node_id
	try:
		res = db.runGremlinQuery(q_getFuncExit)
		# Allow for multiple results, because there is an exit node for every return statement
		# in the function.  The way the node are generated, it appears that the last
		# return statement will always be the first result here, but this is something
		# to be wary about if there are issues in the future.
		return (start, int(res[0].split(':')[0]))
	except:
		mylogger.error( colored('Query failed in getStartAndEnd: %s' % (query), 'yellow') )
		return None

'''
	Get line<->Address information from a CU file
	fileLineList[(cuOffset, file#)] -> {fileName}
'''
def getFileNameListByCU(dwarf_info):

	fileNameList = {} 	# fileNameList[(cu_offset, idx)] = fileName
	# fileLineList = {} #	<cu_offset, idx> : line_Info_list
	# Iterate through compile units
	for cu in dwarf_info.iter_CUs():
		# line_info = []
		cuOffset = cu.cu_offset
		fentry = dwarf_info.line_program_for_CU(cu).header['file_entry']
		# Find the index of the source file we're seeking
		for fi in range(len(fentry)):
			fileNameList[bytes2str(fentry[fi]['name'])] = (cuOffset, fi+1)
			fileNameList[(cuOffset, fi+1)] = bytes2str(fentry[fi]['name']) 

		# Get info for the lines within the given line range
		# for line in dwarf_info.line_program_for_CU(cu).get_entries():
		# 	if line.state is not None and line.state.line != 0:
		# 	# 	line.state.file == ind+1 and \
		# 	# 	line.state.line >= start_line and \
		# 	# 	line.state.line <= end_line:
		# 		line_info.append( (line.state.line, line.state.address) )
		# fileLineList[(cuOffset, line.state.file)] = sorted(line_info)

	# return fileNameIdx, fileLineList
	return fileNameList

'''
	Retrieve source function names from database
'''
def getSrcFunctions(db):
	try:
		q_getFuncs = "g.V().filter{ it.type == 'Function'}.name.dedup"
		res = db.runGremlinQuery(q_getFuncs)
		# for r in res:
		# 	mylogger.trace(r)
	except:
		mylogger.warning( colored('Failed query in getSrcFunctions', 'yellow') )


'''
Return file line information given an address
'''
def decode_file_line(dwarfinfo, address):
	# Go over all the line programs in the DWARF information, looking for
	# one that describes the given address.
	for CU in dwarfinfo.iter_CUs():
		# First, look at line programs to find the file/line for the address
		lineprog = dwarfinfo.line_program_for_CU(CU)
		prevstate = None
		for entry in lineprog.get_entries():
			# We're interested in those entries where a new state is assigned
			if entry.state is None:
				continue
			if entry.state.end_sequence:
				# if the line number sequence ends, clear prevstate.
				prevstate = None
				continue
			# Looking for a range of addresses in two consecutive states that
			# contain the required address.
			if prevstate and prevstate.address <= address < entry.state.address:
				filename = lineprog['file_entry'][prevstate.file - 1].name
				line = prevstate.line
				return filename, line
			prevstate = entry.state
	return None, None

'''
Find the cyclomatic complexity of a given function CFG
'''
def get_cyclomatic_complexity(CFG):
    edges = len(CFG.edges())
    nodes = len(CFG.nodes())
    parts = nx.components.number_strongly_connected_components(CFG)
    return edges - nodes + parts

def get_total_loops(CFG):
	return len(list(nx.simple_cycles(CFG)))

def get_nestingDegree(CFG):
	roots = [n for n,d in CFG.in_degree() if d==0]


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
	sbin.drawFuncCFG("main")
		# sbin.drawFuncCFG("add_line_buffer")
	# sbin.printEffects("_Z5funcAi")
	# sbin.getInsByFuncOffset('sub_611','0x4')	#TODO: offstes must be unique for each instruction per function, There can't be more than one instructions
	# print(sbin.getCFG())

if __name__ == "__main__":
	main()
