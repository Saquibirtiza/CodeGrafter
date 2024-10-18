from termcolor import colored
import logging
# from neo4j import GraphDatabase
# from neo4j.types.graph import Node, Relationship
# import pandas as pd
import pygraphviz as pgv
import os
import csv
# from graphviz import Source
import networkx as nx
import signal
from contextlib import contextmanager
# import time
import bap
from pycparser import c_parser, c_ast, c_generator

mylogger = logging.getLogger('ek.ch')
import sys
import re

sys.path[0:0] = ['.', '..']
from messages.messages import AffectedRecord, POIRecord
from dwarvenking.dwarvenking import LayoutInfo
from graphUtils.drawer import drawer
from sigbin.sigbin import FuncInfo
from auxiliary.support import timeout


class TimeoutException(Exception): pass

def isDecOrHex(offset):
	if(not offset.startswith('0x')):
		try:
			int(offset)
		except:
			return False
	return True

def getOperand(code):
	parser = c_parser.CParser()
	generator = c_generator.CGenerator()
	stmt = """ \
	void test(){ \
	%s ;\
	}""" % code

	# print(stmt)
	ast = parser.parse(stmt, filename='<none>')
	function_body = ast.ext[0].body
	operand = function_body.block_items[0]
	return operand.name

def getFunctionsList(db):
	q_getFuncs = """g.V().has('type','Function').dedup"""
	funcNodes = db.runGremlinQuery(q_getFuncs)
	funcList = {}
	for funcNode in funcNodes:
		nodeId = int(funcNode.ref.split('/')[1])
		funcName = funcNode.properties['name']
		q_funcFile = """g.v(%d).in.filepath.dedup""" % nodeId
		funcFile = db.runGremlinQuery(q_funcFile)
		funcList[nodeId] = (funcName, funcFile[0].split('./')[1])
	return funcList

def getInputSources(db, funcList):
	ext_sources = ['gets', 'read', 'recv', 'scanf', 'getenv']
	sourceCallers = []
	for source in ext_sources:
		q_getSrcCallers = "g.V().has('type','CallExpression').filter{ it.code.contains('%s')}.functionId.dedup" % source
		res = db.runGremlinQuery(q_getSrcCallers)
		for srcCall in res:
			# mylogger.trace(int(srcCall))
			func_idx = int(srcCall)
			if func_idx in funcList:
				callerFunc = funcList[int(srcCall)][0]
				if callerFunc not in sourceCallers:
					sourceCallers.append(callerFunc)
	# q_getMain = "g.V().has('type','Function').filter{ it.name.contains('main')}.name.dedup"
	# for mainFuncs in db.runGremlinQuery(q_getMain):
	# 	sourceCallers =	sourceCallers + ' %s' % mainFuncs
	listToStr = ', '.join([source for source in sourceCallers])
	return listToStr

@contextmanager
def time_limit(seconds):
	def signal_handler(signum, frame):
		raise TimeoutException("Analysis Timed out!")
	signal.signal(signal.SIGALRM, signal_handler)
	signal.alarm(seconds)
	try:
		yield
	finally:
		signal.alarm(0)

class Checker():
	def __init__(self, prog, db, sb, dk, retList, demangledFuncInfoList, funcName=None):
		#sb = sbProg, sbCFG, sbCG
		self.prog = prog
		self.db = db
		self.sbCFG = sb[1]
		self.sbCG = sb[2]
		self.subBAPList = sb[4]
		self.dk = dk
		self.affectedVarLst = []
		# self.poiList = poiList
		self.retList = retList
		self.funcInfoList = demangledFuncInfoList
		self.funcList = getFunctionsList(self.db)
		self.inputSources = getInputSources(self.db, self.funcList)
		if (funcName is not None):
			self.analyse_Func(funcName)
	def getAffectedVars(self):
		return self.affectedVarLst

	def getInputSources(self):
		return self.inputSources

	# The following function is for analysing specific function
	def analyse_Func(self, funcName):
		mylogger.trace("Analysing function %s" % funcName)
		numberOfPOIs = 0
		db = self.db
		localVarList = self.dk[funcName]
		globalVarList = self.dk['global']
		poiList = []

		vulCall_MemFromTo = { "recv" : ("rdi","rsi"), "strcpy" : ("rsi","rdi"), "memcpy" : ("rsi","rdi"), "strcat" : ("rsi","rdi") }
		q_getFuncId = "g.V().has('type','Function').filter{ it.name == '"+ str(funcName) +"'}.id"
		funcId = db.runGremlinQuery(q_getFuncId)
		poiTitle = "Insecure Call"
		poiDescription = "Insecure function call found in function %s." % str(funcName)
		poiDetails = ""
		for insec_func in vulCall_MemFromTo:
			q_insecureCalls = "g.V().filter{ it.functionId == "+ str(funcId).rstrip(']').lstrip('[') +" }.has('insn','callq " + str(insec_func) + "').dedup"
			mylogger.trace("Checking %s", q_insecureCalls)
			insecureCalls = db.runGremlinQuery(q_insecureCalls)
			for node in insecureCalls:
				nodeID = str(node.ref).split('/')[1]
				regVal = {}
				regVal['rsi'] = str(node.properties.get('regValSet')).split(',')[4]
				regVal['rdi'] = str(node.properties.get('regValSet')).split(',')[5]

				fromRegVal = regVal[vulCall_MemFromTo[insec_func][0]]
				toRegVal = regVal[vulCall_MemFromTo[insec_func][1]]
				
				fromOffset = fromRegVal.split(':')[1].split(' ')[-1].rstrip(']')
				toOffset = toRegVal.split(':')[1].split(' ')[-1].rstrip(']')

				# mylogger.trace("fromRegVal: %s, toRegVal: %s" % (fromOffset, toOffset))

				if ( toOffset != 'unknown' and toOffset != 'any'):
					
					# baseReg = regVal.split(':')[1].split(' ')[1]
					toOffset = hex(int(toOffset,16)) if toOffset.startswith('0x') else hex(int(toOffset))
					if(( fromOffset != 'unknown' and fromOffset != 'any')):
						fromOffset = hex(int(fromOffset,16)) if fromOffset.startswith('0x') else hex(int(fromOffset))

					callerID = node.properties.get('functionId')
					# q_callerName = "g.v("+ str(callerID)+").name"
					# callerName = db.runGremlinQuery(q_callerName)
					callerName = self.funcList[callerID][0]
					fileName = self.funcList[callerID][1]

					q_callLoc = "g.v(%d).as('x').in().loop('x'){ it.loops<12 && it.object.hasNot('location')}.dedup" %	int(nodeID)
					callLocs = db.runGremlinQuery(q_callLoc)

					q_offset = "g.v(%d).as('x').out.loop('x'){ it.loops < 5 && it.object.hasNot('kind')}.offset.dedup" % int(nodeID)
					lineOffset = [i for i in db.runGremlinQuery(q_offset) if i]
					mylogger.trace(lineOffset)
					lineOffset = lineOffset[0] if lineOffset else None

					if callLocs is not None:
						callCode = callLocs.properties['code']
						location = callLocs.properties['location']
						line = loc.split(':')[0]

						affectedVar = None
						affectorVar = None
						# varExist = 0
						bufferSize = 0
						isLocal = True
						mylogger.trace("Detecting side effects for %s" % callerName)
						#Check if variable presents in callers stack frame or in global data segment
						for var in localVarList:
							# print("%s %s %s %s" % (var.varName, var.refType, var.cfa_offset, var.size))
							#TODO: var types are not included
							# mylogger.trace("%s -> %s" % (fromOffset,toOffset))
							if(int(var.cfa_offset,16) == int(toOffset,16)):
								affectedVar = var
								bufferSize = var.size
								isLocal = True

							if(( fromOffset != 'unknown' and fromOffset != 'any') and int(var.cfa_offset,16) == int(fromOffset,16)):
								affectorVar = var
								# bufferSize = var.size

						for var in globalVarList:
							# mylogger.trace("===>%s %s %s %s" % (var.varName, var.refType, var.cfa_offset, var.size))
							#TODO: var types are not included

							if(int(var.cfa_offset,16) == int(toOffset,16)):
								affectedVar = var
								bufferSize = var.size
								isLocal = False
							# mylogger.trace("Checking %s and %s with %s" % (fromOffset,toOffset, var.cfa_offset))
							if(( fromOffset != 'unknown' and fromOffset != 'any') and int(var.cfa_offset,16) == int(fromOffset,16)):
								# mylogger.trace("Found")
								affectorVar = var
								# bufferSize = var.size


						if (affectedVar is not None):
							mylogger.trace("In %s, function %s:" % ("FILENAME:LINE", callerName))
							# Hold on, why does the role of affector and affected flip?
							if affectorVar is not None:
								mylogger.trace("\tCall to %s may lead to overflow of variable %s" % (funcName, affectorVar.varName ))
							else:
								mylogger.trace(colored("\tCall to %s may lead to overflow of variable %s" % (funcName, affectedVar.varName ), "yellow"))
							if isLocal:
								if len(localVarList) > 0:
									mylogger.trace("\tThe following variables may be overwritten:")
							else:
								if len(globalVarList) > 0:
									mylogger.trace("\tThe following (global) variables may be overwritten:")
							#mylogger.trace("DETECTED SIDE-EFFECTS :")
							# print(node.properties)
							nodeID = str(node.ref).split('/')[1]
							#mylogger.trace("\tResult:> ID: %s, CallerID: %s Caller: %s, Callee: %s" % (nodeID, node.properties.get('functionId'), callerName, funcName))
							affectedRecord = None
							if(isLocal):
								for var in localVarList:

									if(int(var.cfa_offset,16) > int(toOffset,16)):
										if( affectorVar is not None):
											mylogger.trace(colored("\t%s = *((int*)(%s + %s)" % (var.varName,affectorVar.varName,bufferSize),'cyan'))
											affectedRecord = AffectedRecord(var,affectorVar,bufferSize)
										else:
											mylogger.trace(colored("\t%s = *((int*)(%s + %s)" % (var.varName,affectedVar.varName,bufferSize),'cyan'))
											affectedRecord = AffectedRecord(var,affectedVar,bufferSize)
										bufferSize = bufferSize + var.size
										self.affectedVarLst.append(affectedRecord)
										vScore = 0
										codeComplx = 0
										startLine = 0
										exitLine = 0
										address = 0x0
										funcInfoObj = FuncInfo(callerName, fileName.split('/')[-1])
										if funcInfoObj in self.funcInfoList:
											idx = self.funcInfoList.index(funcInfoObj)
											vScore = self.funcInfoList[idx].vulnScore
											codeComplx = self.funcInfoList[idx].codeComplexity
											startLine = self.funcInfoList[idx].startLoc
											exitLine = self.funcInfoList[idx].exitLoc
											address = self.funcInfoList[idx].address
										pr = POIRecord('MODERATE', fileName, line, typeOfAnalysis, callerName, callCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
										if pr not in poiList:
											poiList.append(pr)
										mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, fileName, startLine, exitLine, callerName, line, callCode, vScore))
										mylogger.trace("POI location:%s" % callerName)
										numberOfPOIs += 1
								retVar = LayoutInfo("Return",8,8)
								if( affectorVar is not None):
									mylogger.trace(colored("\tReturn = *((int*)(%s + %s)" % (affectorVar.varName,bufferSize),'cyan'))
									affectedRecord = AffectedRecord(retVar,affectorVar,bufferSize)
								else:
									mylogger.trace(colored("\tReturn = *((int*)(%s + %s)" % (affectedVar.varName,bufferSize),'cyan'))
									affectedRecord = AffectedRecord(retVar,affectorVar,bufferSize)
								vScore = 0
								codeComplx = 0
								startLine = 0
								exitLine = 0
								address = 0x0
								funcInfoObj = FuncInfo(callerName, fileName.split('/')[-1])
								if funcInfoObj in self.funcInfoList:
									idx = self.funcInfoList.index(funcInfoObj)
									vScore = self.funcInfoList[idx].vulnScore
									codeComplx = self.funcInfoList[idx].codeComplexity
									startLine = self.funcInfoList[idx].startLoc
									exitLine = self.funcInfoList[idx].exitLoc
									address = self.funcInfoList[idx].address
								pr = POIRecord('MODERATE', fileName, line, typeOfAnalysis, callerName, callCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
								if pr not in poiList:
									poiList.append(pr)
								mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, fileName, startLine, exitLine, callerName, line, callCode, vulnScore))
								mylogger.trace("POI location:%s" % callerName)
								numberOfPOIs += 1
								self.affectedVarLst.append(affectedRecord)
							else:
								for var in globalVarList:

									if(int(var.cfa_offset,16) > int(toOffset,16)):
										if( affectorVar is not None):
											mylogger.trace(colored("\t%s = *((int*)(%s + %s)" % (var.varName,affectorVar.varName,bufferSize),'cyan'))
											affectedRecord = AffectedRecord(var,affectorVar,bufferSize)
										else:
											mylogger.trace(colored("\t%s = *((int*)(%s + %s)" % (var.varName,affectedVar.varName,bufferSize),'cyan'))
											affectedRecord = AffectedRecord(var,affectedVar,bufferSize)
										bufferSize = bufferSize + var.size
										vScore = 0
										codeComplx = 0
										startLine = 0
										exitLine = 0
										address = 0x0
										funcInfoObj = FuncInfo(callerName, fileName.split('/')[-1])
										if funcInfoObj in self.funcInfoList:
											idx = self.funcInfoList.index(funcInfoObj)
											vScore = self.funcInfoList[idx].vulnScore
											codeComplx = self.funcInfoList[idx].codeComplexity
											startLine = self.funcInfoList[idx].startLoc
											exitLine = self.funcInfoList[idx].exitLoc
										pr = POIRecord('MODERATE', fileName, line, typeOfAnalysis, callerName, callCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
										if pr not in poiList:
											poiList.append(pr)
										mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, fileName, startLine, exitLine, callerName, line, callCode, vScore))
										mylogger.trace("POI location:%s" % callerName)
										numberOfPOIs += 1
										self.affectedVarLst.append(affectedRecord)


				else:
					mylogger.warning("Destination register value could be Indirect or global")
		mylogger.trace("POIs generated for %s: %s, %s" % (lineOffset, typeOfAnalysis, numberOfPOIs))
		return poiList


	def show_menu(self):
		mylogger.trace("Insecure Call Analysis")
		self.insecure_call()
		self.checkBOILs()


	# def graph_from_neo4j(self, G, netG, edges):
	def graph_from_neo4j(self, netG, edges):
		# print(edges)
		def add_node(node):
			# Adds node id it hasn't already been added
			# print(node['properties'])
			u = node.ref.split('/')[1]
			# if G.has_node(u):
			# 	return
			label = "%s\n%s\n%s" % (node.ref.split('/')[1], node.properties['code'], node.properties['type'])
			netG.add_node(u, labels=label, key=u)
			# G.add_node(u,label=label)

		def add_edge(relation):
			# Adds edge if it hasn't already been added.
			# Make sure the nodes at both ends are created
			# for node in (relation.start_node, relation.end_node):
			#			add_node(node)
			# Check if edge already exists
			u = relation.start_node.ref.split('/')[1]
			v = relation.end_node.ref.split('/')[1]
			eid = relation.ref.split('/')[1]
			# if G.has_edge(u, v, key=eid):
			# 	return
			# If not, create it
			netG.add_edge(u, v, key=eid, labels=relation.type, properties=relation.properties)
			# G.add_edge(u, v, label=relation.type, color='red')

			# def _getEdges(self, function_id, type):

			#			query = """queryNodeIndex('functionId:%s AND isCFGNode:True').outE('%s')""" % (function_id, type)
			#			return j.runGremlinQuery(query)

		for edge in edges:
			# Parse node
			add_node(edge.start_node)
			add_node(edge.end_node)
			# Parse edge
			add_edge(edge)


	def effected_sinks(self):
		poiList = []
		try:
			with timeout(3600):
				self.effected_sinks_impl(poiList)
		except TimeoutException as e:
			mylogger.warn("EFFECTED_SINK Analysis Timed out!")
		except Exception as e:
			mylogger.exception(e)
		finally:
			mylogger.trace("EFFECTED_SINK POIs = %d" % len(poiList))
			return poiList

	def effected_sinks_impl(self, poiList):
		# poiList = []
		try:
			#TODO: This should be calling only on height > threshold functions.
			# Height is taken from call graph. The longer the height the chance of being sanitized is higher.
			typeOfAnalysis = 'EFFECTED_SINK'
			poiTitle = "Sink effected by pointer"
			numberOfPOIs = 0
			db = self.db
			callgraph = self.sbCG
			dr = drawer(db)

			ext_sinks = ['system','write','send','sendto','sendmsg']	#external outputs

			# ext_sinks = ['system','write','send']
			#TODO: Use regular expressions, e.g. get* for getopt, getenv, getlogin etc. There can be additional versions such as fwrite.
			#as well as custom functions write_at_x

			sinkCalls = []
			varlist = self.dk

			'''
			In order to get exact call symbol, first searched for callee name then get the expression statement
			'''
			for sink in ext_sinks:
				q_getSinkNodes = "g.V().has('type','Callee').filter{ it.code == '%s'}.in.in.filter{ it.type == 'ExpressionStatement'}.dedup" % sink
				sinkCalls = sinkCalls + db.runGremlinQuery(q_getSinkNodes)

			for sink in sinkCalls:
				funcId = sink.properties['functionId']
				sinkId = int(sink.ref.split('/')[1])
				sinkCode = sink.properties['code']
				sinkLine = sink.properties['location']
				q_offset = "g.v(%d).as('x').out.loop('x'){ it.loops < 5 && it.object.hasNot('kind')}.offset.dedup" % int(sinkId)
				lineOffset = [i for i in db.runGremlinQuery(q_offset ) if i]
				lineOffset = lineOffset[0] if lineOffset else None
				graph = dr.backwardSlicing(None, sinkId, funcId)

				callerFunc = self.funcList[funcId][0]
				callerFile = self.funcList[funcId][1]

				for node in graph:
					q_getLines = "g.v(%d).dedup" % int(node)
					line_node = db.runGremlinQuery(q_getLines)[0]
					lineCode = line_node.properties['code']

					#TODO: It seems cparser is not perfect. Failed at parsing "send ( sock , ":-)" , 4 , 0 )". Therefore,
					#Catch any exception and continue to search rest.
					try:
						operand = getOperand(lineCode)
					except:
						mylogger.warn("Error while parsing %s" % lineCode)
						continue
					if callerFunc in varlist:
						#Here we only considerring pointer parameters. Non-pointer parameters could also be a dagerous candidate.
						#TODO: Check the dependencies with global variables as well

						for var in varlist[callerFunc]:
							if (var.tag == 'DW_TAG_formal_parameter' and var.explicitType == 'pointer' and (var.varName == operand)):

								poiDescription = "%s called by %s is effected by pointer parameter %s." % (sinkCode, callerFunc, operand)
								poiDetails = ""
								# mylogger.trace("%s, %s, %s, %s, %s, %s, %s, %s" % ('MODERATE', callerFile, sinkLine, typeOfAnalysis, callerFunc, sinkCode, title=poiTitle, description=poiDescription, details=poiDetails))
								mylogger.trace(colored( '[{1},{2}] {3} in {5}'\
									.format('MODERATE', callerFile, sinkLine, typeOfAnalysis, callerFunc, sinkCode), 'cyan'))
								vScore = 0
								codeComplx = 0
								startLine = 0
								exitLine = 0
								address = 0x0
								funcInfoObj = FuncInfo(callerFunc, callerFile.split('/')[-1])
								if funcInfoObj in self.funcInfoList:
									idx = self.funcInfoList.index(funcInfoObj)
									vScore = self.funcInfoList[idx].vulnScore
									codeComplx = self.funcInfoList[idx].codeComplexity
									startLine = self.funcInfoList[idx].startLoc
									exitLine = self.funcInfoList[idx].exitLoc
									address = self.funcInfoList[idx].address
								pr = POIRecord('MODERATE', callerFile, sinkLine, typeOfAnalysis, callerFunc, sinkCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
								if pr not in poiList:
									poiList.append(pr)
								mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, callerFile, startLine, exitLine, callerFunc, sinkLine, sinkCode, vScore))
								mylogger.trace("POI location:%s" % callerFunc)
								numberOfPOIs += 1

				mylogger.trace("End sensitive sink checking for %s" % callerFunc)
			mylogger.trace("POIs generated for %s: %s" % (typeOfAnalysis, numberOfPOIs))
		except Exception as ex:
			mylogger.exception(ex)
		# finally:
		# 	return poiList

	def insecure_paths(self):
		poiList = []
		try:
			with timeout(3600):
				self.insecure_paths_impl(poiList)
		except TimeoutException as e:
			mylogger.warn("INSEC_SINK Analysis Timed out!")
		except Exception as e:
			mylogger.exception(e)
		finally:
			mylogger.trace("INSEC_SINK POIs = %d" % len(poiList))
			return poiList

	def insecure_paths_impl(self, poiList):
		# poiList = []
		try:
			typeOfAnalysis = 'INSEC_SINK'
			poiTitle = 'CWE-200: Exposure of Sensitive Information'

			numberOfPOIs = 0
			j = self.db
			callgraph = self.sbCG
			dr = drawer(j)

			ext_sources = ['gets','getenv','getopt','read','recv','scanf','recvfrom',\
			'recvmsg','getindex','gethostbyname','gethostbyaddr','gethostent']	#external inputs
			ext_sinks = ['system','write','send','sendto','sendmsg']			#external outputs
			# ext_sources = ['readLine']
			# ext_sinks = ['addDictEntry','addDictbyLine']
			# ext_sources = ['gets','read','recv','scanf', 'getenv']
			# ext_sinks = ['system','write','send']
			#TODO: Use regular expressions, e.g. get* for getopt, getenv, getlogin etc. There can be additional versions such as fwrite.
			#as well as custom functions write_at_x

			sinkCalls = []
			varlist = self.dk

			srcNodes = []
			dstNodes = []
			count = 0

			for source in ext_sources:
				srcInsn = "callq %s" % source
				q_getSrcNodes = "g.V().has('insn').filter{ it.insn.startsWith('callq %s') }" % source.lower()
				srcNodes =	srcNodes + j.runGremlinQuery(q_getSrcNodes)
			for dest in ext_sinks:
				dstInsn = "callq %s" % dest
				q_getDstNodes = "g.V().has('insn').filter{ it.insn.startsWith('callq %s') }" % dest.lower()
				dstNodes =	dstNodes + j.runGremlinQuery(q_getDstNodes)

			for srcNode in srcNodes:
				src_func_id = srcNode.properties['func_id']	#bap function ID
				# srcFId = srcNode.properties['functionId']	#joern function ID
				# src_blk_id = srcNode.properties['blk_id']	#bap blk ID
				# src_node_id = int(srcNode.ref.split('/')[1])

				for dstNode in dstNodes:
					srcFId = srcNode.properties['functionId']		#joern src function ID
					src_blk_id = srcNode.properties['blk_id']		#bap src blk ID
					src_node_id = int(srcNode.ref.split('/')[1])	#src node id
					src_call = srcNode.properties['insn'].split(' ')[1]

					# dstFId = dstNode.properties['functionId']		#joern dst function ID
					dst_blk_id = dstNode.properties['blk_id']		#bap dst blk ID
					# dst_node_id = int(dstNode.ref.split('/')[1])	#dst node id
					dst_func_id = dstNode.properties['func_id']

					if (int(src_func_id) in callgraph and int(dst_func_id) in callgraph):
						#Checking for direct call paths
						if nx.has_path(callgraph, int(src_func_id), int(dst_func_id)):

							q_getSrcLoc = "g.v(%d).as('x').in.loop('x'){ it.loops < 12 && it.object.hasNot('location')}.dedup" % int(src_node_id)
							srcLoc =	j.runGremlinQuery(q_getSrcLoc)
							if srcLoc and 'location' in srcLoc[0].properties:
								srcLoc = srcLoc[0]
								callerFunc = self.funcList[srcFId][0]
								callerFile = self.funcList[srcFId][1]
								sinkLine = srcLoc.properties['location']
								sinkCode = srcLoc['code']
								lineOffset = srcNode.properties['offset']
								poiDescription = "Path from %s exist to one of %s sinks" % (src_call, ext_sinks)
								poiDetails = ""
								# mylogger.trace("%s, %s, %s, %s, %s, %s, %s, %s" % ('MODERATE', callerFile, sinkLine, typeOfAnalysis, callerFunc, sinkCode, title=poiTitle, description=poiDescription, details=poiDetails))
								mylogger.trace(colored( '[{1},{2}] {3} in {5}'\
									.format('MODERATE', callerFile, sinkLine, typeOfAnalysis, callerFunc, sinkCode), 'cyan'))
								vScore = 0
								codeComplx = 0
								startLine = 0
								exitLine = 0
								address = 0x0
								funcInfoObj = FuncInfo(callerFunc, callerFile.split('/')[-1])
								if funcInfoObj in self.funcInfoList:
									idx = self.funcInfoList.index(funcInfoObj)
									vScore = self.funcInfoList[idx].vulnScore
									codeComplx = self.funcInfoList[idx].codeComplexity
									startLine = self.funcInfoList[idx].startLoc
									exitLine = self.funcInfoList[idx].exitLoc
									address = self.funcInfoList[idx].address
								pr = POIRecord('MODERATE', callerFile, sinkLine, typeOfAnalysis, callerFunc, sinkCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
								if pr not in poiList:
									poiList.append(pr)
								mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, callerFile, startLine, exitLine, callerFunc, sinkLine, sinkCode, vScore))
								mylogger.trace("POI location:%s" % callerFunc)
								numberOfPOIs += 1
								count = count + 1
								break
							# mylogger.trace(nx.shortest_path(callgraph, int(src_func_id), int(dst_func_id)))
						else:
							# NO direct path exists from src to dst but through a common call site
							callSites = []
							sPath = None
							dPath = None
							for sub in self.prog.subs:
								subName = sub.id.name.lstrip('@')
								if (subName.startswith('_') or subName.startswith('.') or subName == 'register_tm_clones' or subName == 'deregister_tm_clones'):
									None
								elif (nx.has_path(callgraph, int(sub.id.number), int(src_func_id)) and nx.has_path(callgraph, int(sub.id.number), int(dst_func_id))):
									sPath = nx.shortest_path(callgraph, int(sub.id.number), int(src_func_id))
									dPath = nx.shortest_path(callgraph, int(sub.id.number), int(dst_func_id))
									#TODO: Ideally should have considered nx.all_simple_paths
									#Not done because "all_simple_paths" got a generator which can only iterate once and values are destroyed then.
									#All paths starts with function_id(0th) and then blk_id(1st)

									if(len(sPath) > 1):
										src_call_blk_id = sPath[1]
									else:
										src_call_blk_id = src_blk_id
									if(len(dPath) > 1):
										dst_call_blk_id = dPath[1]
									else:
										dst_call_blk_id = dst_blk_id
									callSites.append([subName, sub.id.number, src_call_blk_id, dst_call_blk_id])
								else:
									None

							for [subName, bapSubID, src_call_blk_id, dst_call_blk_id] in callSites:
								if subName in self.sbCFG:
									cfg = self.sbCFG[subName]
									if (int(src_call_blk_id) in cfg and int(dst_call_blk_id) in cfg and nx.has_path(cfg, int(src_call_blk_id), int(dst_call_blk_id))):
										srcFId = srcNode.properties['functionId']		#joern src function ID
										# src_blk_id = srcNode.properties['blk_id']		#bap src blk ID
										src_node_id = int(srcNode.ref.split('/')[1])	#src node id
										src_call = srcNode.properties['insn'].split(' ')[1]

										# dstFId = dstNode.properties['functionId']		#joern dst function ID
										# dst_blk_id = dstNode.properties['blk_id']		#bap dst blk ID
										# dst_node_id = int(dstNode.ref.split('/')[1])	#dst node id
										q_getSrcLoc = "g.v(%d).as('x').in.loop('x'){ it.loops < 12 && it.object.hasNot('location')}.dedup" % int(src_node_id)
										srcLoc =	j.runGremlinQuery(q_getSrcLoc)
										if srcLoc and 'location' in srcLoc[0].properties:
											srcLoc = srcLoc[0]
											callerFunc = self.funcList[srcFId][0]
											callerFile = self.funcList[srcFId][1]
											sinkLine = srcLoc.properties['location']
											sinkCode = srcLoc['code']
											lineOffset = srcNode.properties['offset']
											poiDescription = "Path from %s exist to one of %s sinks" % (src_call, ext_sinks)
											poiDetails = ""

											mylogger.trace(colored( '[{1},{2}] {3} in {5}'\
												.format('MODERATE', callerFile, sinkLine, typeOfAnalysis, callerFunc, sinkCode), 'cyan'))
											vScore = 0
											codeComplx = 0
											startLine = 0
											exitLine = 0
											address = 0x0
											funcInfoObj = FuncInfo(callerFunc, callerFile.split('/')[-1])
											if funcInfoObj in self.funcInfoList:
												idx = self.funcInfoList.index(funcInfoObj)
												vScore = self.funcInfoList[idx].vulnScore
												codeComplx = self.funcInfoList[idx].codeComplexity
												startLine = self.funcInfoList[idx].startLoc
												exitLine = self.funcInfoList[idx].exitLoc
												address = self.funcInfoList[idx].address
											pr = POIRecord('MODERATE', callerFile, sinkLine, typeOfAnalysis, callerFunc, sinkCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
											if pr not in poiList:
												poiList.append(pr)
											mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, callerFile, startLine, exitLine, callerFunc, sinkLine, sinkCode, vScore))
											mylogger.trace("POI location:%s" % callerFunc)
											numberOfPOIs += 1
											count = count + 1
											break

			mylogger.trace("Total external-source -> external-sink paths = %d" % count)
			mylogger.trace("POIs generated for %s: %s" % (typeOfAnalysis, numberOfPOIs))

		except Exception as ex:
			mylogger.exception(ex)
		# finally:
		# 	return poiList

	def checkBOILs(self):
		poiList = []
		try:
			with timeout(3600):
				self.checkBOILs_impl(poiList)
		except TimeoutException as e:
			mylogger.warn("CHK_BOILS Analysis Timed out!")
		except Exception as e:
			mylogger.exception(e)
		finally:
			mylogger.trace("CHK_BOILS POIs = %d" % len(poiList))
			return poiList

	def checkBOILs_impl(self, poiList):
		typeOfAnalysis = 'CHK_BOILS'
		poiTitle = "CWE 119: Improper Restriction of Operations within the Bounds of a Memory Buffer"
		numberOfPOIs = 0
		j = self.db
		netG = nx.MultiDiGraph()
		# G = pgv.AGraph(strict=False, directed=True)
		# poiList = []
		# start_time = time.time()
		# q_getFuncIDs = "g.V().filter{it.type.matches('AssignmentExpr')}.as('x').rval.filter{ it.code.contains('*') }.back('x').functionId.toList()"
		# q_getPtrAssignments = "g.V().filter{it.type.matches('AssignmentExpr')}.and(_().lval.filter{ it.code.contains('*')}, _().rval.filter{ it.code.contains('*')})"
		q_getPtrAssignments = "g.V().filter{it.type == 'AssignmentExpr'}.and(_().lval.filter{ it.code.contains('*')}, _().rval.filter{ it.code.contains('*')})"
		ptrAssignments =	j.runGremlinQuery(q_getPtrAssignments)
		ptrUsesList = {}
		for pa in ptrAssignments:
			f_id = pa.properties['functionId']
			node_id = int(pa.ref.split('/')[1])-1	# ExpressionStatement(eg. node_306) <-(AST_OF)- AssignmentExpr(eg. node_307), and only ExpressionStatement is CFGNode
			pa_code = pa.properties['code']
			# q_getLO
			pa_location = pa.properties['location']
			# print(pa.ref, pa_code, pa_location)
			# ptrNode = {}
			# ptrNode[node_id] = tuple([pa_code, pa_location])
			if f_id in ptrUsesList : ptrUsesList[f_id].update({ node_id : (pa_code, pa_location)})
			else: ptrUsesList[f_id] = { node_id : (pa_code, pa_location)}

			# ptrNode = {}
			node_id = node_id-5
			pa_code = "some_code *"
			pa_location = "some_loc"
			# ptrNode[node_id] = tuple([pa_code, pa_location])
			ptrUsesList[f_id].update({ node_id : (pa_code, pa_location)})

		total_loops = 0
		boil = 0
		for function_id in ptrUsesList:
			#TODO: We can pass same drawer object so that we can call inbuilt getCFG method.
			q_getCFGedges = """queryNodeIndex('functionId:%s AND isCFGNode:True').outE('%s')""" % (function_id, 'FLOWS_TO')
			cfgEdges = j.runGremlinQuery(q_getCFGedges)

			nodeList = [e for e,v in ptrUsesList[function_id].items() ]

			# self.graph_from_neo4j(G, netG, cfgEdges)
			self.graph_from_neo4j(netG, cfgEdges)
			cycleList = list(nx.simple_cycles(netG))
			total_loops += len(cycleList)
			mylogger.trace("Cycles: %s\n" % len(cycleList))

			for node in nodeList:
				# print(node)
				# for sublist in cycleList:
				#		print("Checking %s in %s" % (node, sublist))
				#		if str(node) in sublist:
				#			# print(sublist)
				#			break
				if(any(str(node) in sublist for sublist in cycleList)):
					# print(node)
					boil = boil + 1
					q_getLocation = """g.v(%s).location""" % (node)
					# print(q_getLocation)
					pa_location = j.runGremlinQuery(q_getLocation)
					q_offset = "g.v(%d).as('x').out.loop('x'){ it.loops < 5 && it.object.hasNot('kind')}.offset.dedup" % int(node)
					lineOffset = [i for i in j.runGremlinQuery(q_offset ) if i]
					mylogger.trace(lineOffset)
					lineOffset = lineOffset[0] if lineOffset else None
					# q_getFunc = """g.v(%s).name""" % (function_id)
					# pa_funcName = j.runGremlinQuery(q_getFunc)
					pa_funcName = self.funcList[function_id][0]
					mylogger.trace(colored("Function %s contains %s at %s in %s" % (pa_funcName, ptrUsesList[function_id][node][0], pa_location, self.funcList[function_id][1]), 'cyan'))
					# pa_funcName, ptrUsesList[function_id][node][0], pa_location, self.funcList[function_id][1]
					poiDescription = "Loop in function %s may lead to overflow." % pa_funcName
					poiDetails = ""
					vScore = 0
					codeComplx = 0
					startLine = 0
					exitLine = 0
					address = 0x0
					funcInfoObj = FuncInfo(pa_funcName, self.funcList[function_id][1])
					if funcInfoObj in self.funcInfoList:
						idx = self.funcInfoList.index(funcInfoObj)
						vScore = self.funcInfoList[idx].vulnScore
						codeComplx = self.funcInfoList[idx].codeComplexity
						startLine = self.funcInfoList[idx].startLoc
						exitLine = self.funcInfoList[idx].exitLoc
						address = self.funcInfoList[idx].address
					pr = POIRecord('MODERATE', self.funcList[function_id][1], pa_location, typeOfAnalysis, pa_funcName, ptrUsesList[function_id][node][0], title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
					if pr not in poiList:
						poiList.append(pr)
					mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, self.funcList[function_id][1], startLine, exitLine, pa_funcName, pa_location, ptrUsesList[function_id][node][0], vScore))
					mylogger.trace("POI location:%s" % pa_funcName)
					numberOfPOIs += 1
					break

			# G.clear()
			netG.clear()
			# mylogger.trace("boils: %s\n" % boil)
			# mylogger.trace("--- %s seconds ---" % (time.time() - start_time))
		mylogger.trace("BOILS : %s" % boil)
		mylogger.trace("LOOPS : %s" % total_loops)
		mylogger.trace("POIs generated for %s: %s" % (typeOfAnalysis, numberOfPOIs))
		# return poiList

	# The following function is for analysing all functions
	#TODO: This function should call analyse_Func(self, funcName) each function
	def insecure_call(self):
		poiList = []
		try:
			with timeout(3600):
				self.insecure_call_impl(poiList)
		except TimeoutException as e:
			mylogger.warning("INSEC_CALL Analysis Timed out!")
		except Exception as e:
			mylogger.exception(e)
		finally:
			mylogger.trace("INSEC_CALL POIs = %d" % len(poiList))
			return poiList

	def insecure_call_impl(self, poiList):
		# poiList = []
		try:
			typeOfAnalysis = 'INSEC_CALL'
			poiTitle = "CWE-676: Use of Potentially Dangerous Function"
			# vulCall_MemFromTo = { "recv" : ("rdi","rsi"), "strcpy" : ("rsi","rdi"), "strcat" : ("rsi","rdi") }
			numberOfPOIs = 0
			varlist = self.dk
			db = self.db

			vulCall_MemFromTo = {"memcmp", "strcmp", "strcpy", "memcpy"}

			for insecCall in vulCall_MemFromTo:
				# "g.v(%d).as('x').in().loop('x'){ it.loops<12 && it.object.hasNot('location')}.dedup"
				q_getInsecCallStmt = "g.V().has('type','Callee').filter{ it.code == '"+ insecCall +"'}.as('x').in.loop('x'){ it.loops < 12 && it.object.hasNot('location')}.dedup"
				# q_getInsecCallStmt = "g.V().has('code').filter{ it.code.contains('" + insecCall + "')}.dedup"
				insecCallStmt = db.runGremlinQuery(q_getInsecCallStmt)
				for stmtNode in insecCallStmt:
					# callSymbol = stmtNode.properties['code']
					callerID = stmtNode.properties.get('functionId')
					callerName = self.funcList[callerID][0]
					if stmtNode.properties['type'] == 'ReturnStatement':
						#TODO: Should traverse starting form Callee node o find statement with location
						q_getParentCallers = "g.V().has('type','Callee').filter{ it.code == '" + callerName +"'}.as('x').in.loop('x'){ it.loops < 12 && it.object.hasNot('location')}.dedup"
						# q_getCallers = "g.V().has('type','CallExpression').filter{ it.code.contains('%s')}.dedup" % callerName
						parentCallers = db.runGremlinQuery(q_getParentCallers)
						for parentCaller in parentCallers:
							parentID = parentCaller.properties.get('functionId')
							parentName = self.funcList[parentID][0]
							parentFile = self.funcList[parentID][1]
							parentCallCode = parentCaller.properties['code']
							parentLoc = parentCaller.properties['location']

							q_offset = "g.v(%d).as('x').out.loop('x'){ it.loops < 5 && it.object.hasNot('kind')}.offset.dedup" % int(parentCaller.ref.split('/')[1])
							lineOffset = [i for i in db.runGremlinQuery(q_offset) if i]
							mylogger.trace(lineOffset)
							lineOffset = lineOffset[0] if lineOffset else None

							poiDescription = "Insecure function %s is called by %s via %s." % (insecCall, parentName, callerName)
							poiDetails = ""
							# mylogger.trace(q_getParentCallers)
							# mylogger.trace(colored("Insecure function %s is called by %s via %s" % (insecCall, parentName, callerName),"cyan"))
							mylogger.trace(colored( '[{1},{2}] {3} in {5}'\
								.format('MODERATE', parentFile, parentLoc, typeOfAnalysis, parentName, parentCallCode), 'cyan'))
							vScore = 0
							codeComplx = 0
							startLine = 0
							exitLine = 0
							address = 0x0
							funcInfoObj = FuncInfo(parentName, parentFile.split('/')[-1])
							if funcInfoObj in self.funcInfoList:
								idx = self.funcInfoList.index(funcInfoObj)
								vScore = self.funcInfoList[idx].vulnScore
								codeComplx = self.funcInfoList[idx].codeComplexity
								startLine = self.funcInfoList[idx].startLoc
								exitLine = self.funcInfoList[idx].exitLoc
								address = self.funcInfoList[idx].address
							else:
								mylogger.warn("No function found by name %s in FuncInfo list" % parentName)
							pr = POIRecord('MODERATE', parentFile, parentLoc, typeOfAnalysis, parentName, parentCallCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
							if pr not in poiList:
								poiList.append(pr)
							mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, parentFile, startLine, exitLine, parentName, parentLoc, parentCallCode, vScore))
							mylogger.trace("POI location:%s" % parentName)
							numberOfPOIs += 1
					else:
						fileName = self.funcList[callerID][1]
						callCode = stmtNode.properties['code']
						loc = stmtNode.properties['location']

						q_offset = "g.v(%d).as('x').out.loop('x'){ it.loops < 5 && it.object.hasNot('kind')}.offset.dedup" % int(stmtNode.ref.split('/')[1])
						mylogger.trace(q_offset)
						lineOffset = [i for i in db.runGremlinQuery(q_offset) if i]
						mylogger.trace(lineOffset)
						lineOffset = lineOffset[0] if lineOffset else None


						poiDescription = "Insecure function %s called by %s." % (insecCall, callerName)
						poiDetails = ""
						# mylogger.trace(colored("Insecure function %s called by %s" % (insecCall, callerName),"cyan"))
						mylogger.trace(colored( '[{1},{2}] {3} in {5}'\
							.format('MODERATE', fileName, loc, typeOfAnalysis, callerName, callCode), 'cyan'))
						vScore = 0
						codeComplx = 0
						startLine = 0
						exitLine = 0
						address = 0x0
						funcInfoObj = FuncInfo(callerName, fileName.split('/')[-1])
						if funcInfoObj in self.funcInfoList:
							idx = self.funcInfoList.index(funcInfoObj)
							vScore = self.funcInfoList[idx].vulnScore
							codeComplx = self.funcInfoList[idx].codeComplexity
							startLine = self.funcInfoList[idx].startLoc
							exitLine = self.funcInfoList[idx].exitLoc
							address = self.funcInfoList[idx].address
						else:
							mylogger.warn("No function found by name %s in FuncInfo list" % callerName)
						pr = POIRecord('MODERATE', fileName, loc, typeOfAnalysis, callerName, callCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
						if pr not in poiList:
							poiList.append(pr)
						mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, fileName, startLine, exitLine, callerName, loc, callCode, vScore))
						mylogger.trace("POI location:%s" % callerName)
						numberOfPOIs += 1

			poiTitle = 'CWE-120: Buffer Copy without Checking Size of Input'
			vulCall_MemFromTo = { "recv" : ("rdi","rsi"), "strcpy" : ("rsi","rdi"), "memcpy" : ("rsi","rdi"), "strcat" : ("rsi","rdi") }
			for funcName in vulCall_MemFromTo:
				# funcName = '_z9my_strcpypcs_i'
				# print("Checking calls to %s" % funcName)

				'''
				We use the binary CPG to query here because we need to check the values
				in RSI and RDI register. This method is effective than doing a VSA in the source CPG.
				The preprocessor and the compiler might evaluate some expressions and could
				read as a static value. (e.g. macros are preprocessed, some functions evaluated
				and replaced by the compiler)
				'''
				q_insecureCalls = "g.V().has('insn','callq " + funcName + "').dedup"
				insecureCalls = db.runGremlinQuery(q_insecureCalls)
				
				for node in insecureCalls:
					# mylogger.trace(node)
					# (n479 {address:"0x8b7",blk_id:"2331",effects:"[{var(\"rsp\", imm(0x40)) = minus(var(\"rsp\", imm(0x40)), int(0x8, 0x40))},
					#  {var(\"mem\", mem(0x40, 0x8)) = store(var(\"mem\", mem(0x40, 0x8)), var(\"rsp\", imm(0x40)), int(0x8bc, 0x40), littleendian(), 0x40)}]",
					#  func_id:"none",functionId:14,insType:"def",insn:"callq _z9my_strcpypcs_i",kind:"ASM",loop_id:"none",offset:"0x12d",
					#  regValSet:"[ rax : rbp -64, rbx : any, rcx : rbp -32, rdx : unknown, rsi : rbp -32, rdi : rbp -64]",
					#  targets:"[{direct call if int(0x1, 0x1) ? 3918 ;returning 3151}]",tid:"2374"})
					nodeID = str(node.ref).split('/')[1]
					# mylogger.trace("Binary node ID %s" % nodeID)
					regVal = {}
					regVal['rsi'] = str(node.properties.get('regValSet')).split(',')[4]
					regVal['rdi'] = str(node.properties.get('regValSet')).split(',')[5]


					fromRegVal = regVal[vulCall_MemFromTo[funcName][0]]
					toRegVal = regVal[vulCall_MemFromTo[funcName][1]]
					
					# if ( vulFuncReg_Dict[funcName] == 'rsi'):
					#		regVal = str(node.properties.get('regValSet')).split(',')[4]
					# elif ( vulFuncReg_Dict[funcName] == 'rdi'):
					#		regVal = str(node.properties.get('regValSet')).split(',')[5]
					# else:
					#		mylogger.trace("No RSI/RDI observed in VSA")

					# print(regVal)
					fromOffset = fromRegVal.split(':')[1].split(' ')[-1].rstrip(']')
					toOffset = toRegVal.split(':')[1].split(' ')[-1].rstrip(']')
					# regOffset = toRegVal.split(':')[1].split(' ')[-1].rstrip(']')
					# mylogger.trace("fromRegVal: %s, toRegVal: %s" % (fromOffset, toOffset))
					# regOffset = regVal.split(':')[1].split(' ')[-1].rstrip(']')
					if( isDecOrHex(toOffset) and isDecOrHex(fromOffset)):
					# if ( toOffset != 'unknown' and toOffset != 'any'):
						# baseReg = regVal.split(':')[1].split(' ')[1]
						toOffset = hex(int(toOffset,16)) if toOffset.startswith('0x') else hex(int(toOffset))
						# if(( fromOffset != 'unknown' and fromOffset != 'any')):
						# try:
						fromOffset = hex(int(fromOffset,16)) if fromOffset.startswith('0x') else hex(int(fromOffset))

						callerID = node.properties.get('functionId')

						callerName = self.funcList[callerID][0]
						fileName = self.funcList[callerID][1]


						#TODO: Getting the source location from asm line is tricky. call instruction is not mapped to actual call asm
						# instruction but to the the parameters. Here we try to step back 12 times and see if any source is connected.
						#12 here is choosen based on the observations to terminate the query running indefinitely.
						#TODO: following query may be the best match
						# q_callLoc = "g.V().filter{ it.functionId == "+ str(callerID) +" }.has('type','ExpressionStatement').filter{ it.code.contains('"+ funcName +"') }.location.dedup"
						# q_callLoc = "g.V().filter{ it.functionId == "+ str(callerID) +" }.has('type','ExpressionStatement').filter{ it.code.startsWith('"+ funcName +"') }.location.dedup"
						q_callLoc = "g.v(%d).as('x').in().loop('x'){ it.loops < 12 && it.object.hasNot('location')}.dedup" %	int(nodeID)
						# mylogger.trace(q_callLoc)
						callLocs = db.runGremlinQuery(q_callLoc)

						#TODO: callLocs can return more than one record. Should investigate this.
						if len(callLocs) != 0 and 'location' in callLocs[0].properties:
							callCode = callLocs[0].properties['code']
							loc = callLocs[0].properties['location']
							q_offset = "g.v(%d).as('x').out.loop('x'){ it.loops < 5 && it.object.hasNot('kind')}.offset.dedup" % int(callLocs[0].ref.split('/')[1])
							lineOffset = [i for i in db.runGremlinQuery(q_offset) if i]
							mylogger.trace(lineOffset)
							lineOffset = lineOffset[0] if lineOffset else None
							line = loc.split(':')[0]
							# line = str(callLocs[0]).split(':')[0]

							affectedVar = None
							affectorVar = None
							# varExist = 0
							bufferSize = 0
							isLocal = True
							mylogger.trace("Detecting side effects for %s" % callerName)
							#TODO: following lines commented due to lack of performance, essencially logging source line information
							# for loc in callLocs:
							#		mylogger.trace("File Name: %s; Source Line: %s" % (str(fileName).replace("u'","").replace("'",""), str(loc).split(':')[0]))

							#Check if variable presents in callers stack frame or in global data segment
							for var in varlist[callerName]:
								# print("%s %s %s %s" % (var.varName, var.refType, var.cfa_offset, var.size))
								#TODO: var types are not included
								# mylogger.trace("%s -> %s" % (fromOffset,toOffset))
								if(int(var.cfa_offset,16) == int(toOffset,16)):
									affectedVar = var
									localbufferSize = var.size
									isLocal = True

								if(( fromOffset != 'unknown' and fromOffset != 'any') and int(var.cfa_offset,16) == int(fromOffset,16)):
									affectorVar = var
									# bufferSize = var.size

							for var in varlist['global']:
								# mylogger.trace("===>%s %s %s %s" % (var.varName, var.refType, var.cfa_offset, var.size))
								#TODO: var types are not included

								if(int(var.cfa_offset,16) == int(toOffset,16)):
									affectedVar = var
									globalbufferSize = var.size
									isLocal = False
								# mylogger.trace("Checking %s and %s with %s" % (fromOffset,toOffset, var.cfa_offset))
								if(( fromOffset != 'unknown' and fromOffset != 'any') and int(var.cfa_offset,16) == int(fromOffset,16)):
									# mylogger.trace("Found")
									affectorVar = var
									# bufferSize = var.size

							if (affectedVar is not None):
								# poiTitle = "Insecure Call"
								poiDescription = "Insecure function call found in function %s." % callerName
								poiDetails = ""
								#TODO: Is this line number accurate?
								# And why is the file name surrounded by brackets?
								#TODO: I actually can't get the location here any more!
								# I need the location of the line that contains the call!
								#mylogger.trace("In %s:%s, function %s:" % (str(fileName).replace("u'","").replace("'","").replace("[","").replace("]",""), str(loc).split(':')[0], callerName))
								mylogger.trace("In %s:%s, function %s:" % (str(fileName).replace("u'","").replace("'","").replace("[","").replace("]",""), 'TODO', callerName))
								# Hold on, why does the role of affector and affected flip?
								if affectorVar is not None:
									mylogger.trace("\tCall to %s may overflow variable %s" % (funcName, affectorVar.varName ))
								else:
									mylogger.trace(colored("\tCall to %s may overflow variable %s" % (funcName, affectedVar.varName ), "yellow"))
								if isLocal:
									if len(varlist[callerName]) > 0:
										mylogger.trace("\tThe following variables may be overwritten:")
								else:
									if len(varlist['global']) > 0:
										mylogger.trace("\tThe following (global) variables may be overwritten:")
								#mylogger.trace("DETECTED SIDE-EFFECTS :")
								# print(node.properties)
								# nodeID = str(node.ref).split('/')[1]
								# mylogger.debug("%s, %s, %s, %s" % ('moderate', fileName, line, typeOfAnalysis))
								# poiList.append(POIRecord('moderate', fileName, line, typeOfAnalysis))
								#mylogger.trace("\tResult:> ID: %s, CallerID: %s Caller: %s, Callee: %s" % (nodeID, node.properties.get('functionId'), callerName, funcName))
								affectedRecord = None

								if(isLocal):
									for var in varlist[callerName]:
										if(int(var.cfa_offset,16) > int(toOffset,16)):
											if( affectorVar is not None):
												mylogger.trace(colored("\t%s = *((int*)(%s + %s)" % (var.varName,affectorVar.varName,localbufferSize),'cyan'))
												affectedRecord = AffectedRecord(var,affectorVar,localbufferSize)
											else:
												mylogger.trace(colored("\t%s = *((int*)(%s + %s)" % (var.varName,affectedVar.varName,localbufferSize),'yellow'))
												affectedRecord = AffectedRecord(var,affectedVar,localbufferSize)
											localbufferSize = localbufferSize + var.size
											self.affectedVarLst.append(affectedRecord)
											# vScore = 0
											# codeComplx = 0
											# funcInfoObj = FuncInfo(callerName, fileName.split('/')[-1])
											# if funcInfoObj in self.funcInfoList:
											# 	idx = self.funcInfoList.index(funcInfoObj)
											# 	vScore = self.funcInfoList[idx].vulnScore
											# 	codeComplx = self.funcInfoList[idx].codeComplexity
											# poiList.append(POIRecord('MODERATE', fileName, loc, typeOfAnalysis, callerName, callCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx))
											# numberOfPOIs += 1
									# LayoutInfo(varName, cfa_offset, size, refType, explType, baseType, tag, arrLength=None, ssz=None):
									retVar = LayoutInfo("Return", 8, 8, 0, 0, 0, 0)
									if( affectorVar is not None):
										mylogger.trace(colored("\tReturn = *((int*)(%s + %s)" % (affectorVar.varName,localbufferSize),'cyan'))
										affectedRecord = AffectedRecord(retVar,affectorVar,localbufferSize)
									else:
										mylogger.trace(colored("\tReturn = *((int*)(%s + %s)" % (affectedVar.varName,localbufferSize),'yellow'))
										affectedRecord = AffectedRecord(retVar,affectedVar,localbufferSize)
									vScore = 0
									codeComplx = 0
									startLine = 0
									exitLine = 0
									address = 0x0
									funcInfoObj = FuncInfo(callerName, fileName.split('/')[-1])
									if funcInfoObj in self.funcInfoList:
										idx = self.funcInfoList.index(funcInfoObj)
										vScore = self.funcInfoList[idx].vulnScore
										codeComplx = self.funcInfoList[idx].codeComplexity
										startLine = self.funcInfoList[idx].startLoc
										exitLine = self.funcInfoList[idx].exitLoc
										address = self.funcInfoList[idx].address
									pr = POIRecord('MODERATE', fileName, loc, typeOfAnalysis, callerName, callCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
									if pr not in poiList:
										poiList.append(pr)
									mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, fileName, startLine, exitLine, callerName, loc, callCode, vScore))
									mylogger.trace("POI location:%s" % callerName)
									numberOfPOIs += 1
									self.affectedVarLst.append(affectedRecord)
								else:
									for var in varlist['global']:

										if(int(var.cfa_offset,16) > int(toOffset,16)):
											if( affectorVar is not None):
												mylogger.trace(colored("\t%s = *((int*)(%s + %s)" % (var.varName,affectorVar.varName,globalbufferSize),'cyan'))
												affectedRecord = AffectedRecord(var,affectorVar,globalbufferSize)
											else:
												mylogger.trace(colored("\t%s = *((int*)(%s + %s)" % (var.varName,affectedVar.varName,globalbufferSize),'yellow'))
												affectedRecord = AffectedRecord(var,affectedVar,globalbufferSize)
											globalbufferSize = globalbufferSize + var.size
											self.affectedVarLst.append(affectedRecord)
									vScore = 0
									codeComplx = 0
									startLine = 0
									exitLine = 0
									address = 0x0
									funcInfoObj = FuncInfo(callerName, fileName.split('/')[-1])
									if funcInfoObj in self.funcInfoList:
										idx = self.funcInfoList.index(funcInfoObj)
										vScore = self.funcInfoList[idx].vulnScore
										codeComplx = self.funcInfoList[idx].codeComplexity
										startLine = self.funcInfoList[idx].startLoc
										exitLine = self.funcInfoList[idx].exitLoc
										address = self.funcInfoList[idx].address
									pr = POIRecord('MODERATE', fileName, loc, typeOfAnalysis, callerName, callCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
									if pr not in poiList:
										poiList.append(pr)
									mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, fileName, startLine, exitLine, callerName, loc, callCode, vScore))
									mylogger.trace("POI location:%s" % callerName)
									numberOfPOIs += 1
							# except:
							#		continue

					else:
						mylogger.trace("Destination register value could be Indirect or global")
			mylogger.trace("POIs generated for %s: %s" % (typeOfAnalysis, numberOfPOIs))
			mylogger.trace("Insecure Analysis completed..")
		# except TimeoutException as e:
		# 	mylogger.trace("Analysis Timed out- inner!")
		except Exception as e:
			mylogger.exception(e)
		# finally:
		# 	return poiList

	'''
	Compare the actual size of for condition with actual size in the binary
	'''
	def checkForConditions(self):
		poiList = []
		try:
			with timeout(3600):
				self.checkForConditions_impl(poiList)
		except TimeoutException as e:
			mylogger.warn("FOR_COND_CHK Analysis Timed out!")
		except Exception as e:
			mylogger.exception(e)
		finally:
			mylogger.trace("FOR_COND_CHK POIs = %d" % len(poiList))
			return poiList

	def checkForConditions_impl(self, poiList):
		db = self.db
		numberOfPOIs = 0
		typeOfAnalysis = 'FOR_COND_CHK'
		# poiList = []
		poiTitle = 'CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer'
		q_forStmts = "g.V().has('code').has('type','ForStatement').dedup"
		forStmts = db.runGremlinQuery(q_forStmts)
		for forStmt in forStmts:
			forId = int(forStmt.ref.split('/')[1])
			function_id = forStmt.properties['functionId']
			q_getIncrSyms = "g.v(%d).out.has('type','Expression').out.has('type','IncDecOp').out.has('type','Symbol').code.dedup" % forId
			incrSyms = db.runGremlinQuery(q_getIncrSyms)
			q_getCondSyms = "g.v(%d).out.has('type','Condition').out.has('type','Symbol').code.dedup" % forId
			condSyms = db.runGremlinQuery(q_getCondSyms)
			missingConds = list(set(incrSyms) - set(condSyms))	#Ideally incremental variables must be bound checked.
			if(len(missingConds)>0):
				funcName = self.funcList[function_id][0]
				funcFile = self.funcList[function_id][1]
				q_getLoc = "g.v(%d).out.has('type','Condition').dedup" % forId
				callNode = db.runGremlinQuery(q_getLoc)[0]
				loc = callNode.properties['location']
				q_offset = "g.v(%d).as('x').out.loop('x'){ it.loops < 5 && it.object.hasNot('kind')}.offset.dedup" % int(callNode.ref.split('/')[1])
				lineOffset = [i for i in db.runGremlinQuery(q_offset) if i]
				lineOffset = lineOffset[0] if lineOffset else None
				stmt = forStmt.properties['code']
				poiDescription = "%s is not bound checked at line %s in Function %s of %s." % (missingConds, loc.split(':')[0], funcName, funcFile)
				poiDetails = ""
				vScore = 0
				codeComplx = 0
				startLine = 0
				exitLine = 0
				address = 0x0
				funcInfoObj = FuncInfo(funcName, funcFile.split('/')[-1])
				if funcInfoObj in self.funcInfoList:
					idx = self.funcInfoList.index(funcInfoObj)
					vScore = self.funcInfoList[idx].vulnScore
					codeComplx = self.funcInfoList[idx].codeComplexity
					startLine = self.funcInfoList[idx].startLoc
					exitLine = self.funcInfoList[idx].exitLoc
					address = self.funcInfoList[idx].address
				pr = POIRecord('MODERATE', funcFile, loc, typeOfAnalysis, funcName, stmt, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
				if pr not in poiList:
					poiList.append(pr)
				mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, funcFile, startLine, exitLine, funcName, loc, stmt, vScore))
				mylogger.trace("POI location:%s" % funcName)
				numberOfPOIs += 1
				# mylogger.trace(colored(poiDescription,'cyan'))

		poiTitle = "CWE-118: Incorrect Access of Indexable Resource ('Range Error')"
		
		varlist = self.dk
		q_forStmts = "g.V().has('code').has('type','ForStatement').dedup"
		# q_forStmts = "g.V().has('code').has('type','ForStatement').out.statements().dedup"
		forStmts = db.runGremlinQuery(q_forStmts)
		graph = drawer(db, self.subBAPList)
		for forStmt in forStmts:
			stmt = forStmt.properties['code'].split(';')
			# cond = stmt[1]
			# init = stmt[0]
			# iterater = stmt[2]
			forId = int(forStmt.ref.split('/')[1])
			function_id = forStmt.properties['functionId']
			funcName = self.funcList[function_id][0]
			funcFile = self.funcList[function_id][1]

			q_cmpInsns = "g.V().has('functionId',%s).has('insn').filter{ it.insn.startsWith('cmp')}.dedup()" % function_id
			#TODO: following function didt work for Union challenge but the above with many false positives
			# q_cmpInsns = "g.v(%d).out.has('type','Condition').out('src2line').filter{ it.insn.startsWith('cmp')}.dedup()" % forId
			cmpInsns = db.runGremlinQuery(q_cmpInsns)

			#Conditions have several symbols in addition to index
			q_forUses = "g.v(%d).out.statements().has('type','Condition').out('USE').dedup" % forId
			forUses = db.runGremlinQuery(q_forUses)
			if forUses:
				#TODO : Check for location correctness
				#TODO: can q_cmpInsns and q_forCondition be combined and query for edge?
				q_forCondition = "g.v(%d).out.statements().has('type','Condition').filter{ it.functionId == %d }.dedup" % (forId, int(function_id))
				forCondition = db.runGremlinQuery(q_forCondition)

				loc = forCondition[0].properties['location']
				q_offset = "g.v(%d).as('x').out.loop('x'){ it.loops < 5 && it.object.hasNot('kind')}.offset.dedup" % int(forCondition[0].ref.split('/')[1])
				lineOffset = [i for i in db.runGremlinQuery(q_offset) if i]
				lineOffset = lineOffset[0] if lineOffset else None
				condCode = forCondition[0].properties['code']

				#Getting IDs where for-condition being used
				for forUse in forUses:
					forUseID = int(forUse.ref.split('/')[1])
					#Assumption : array object is the first symbol
					#TODO: check if there are multiple array index uses
					q_firstArrSym = "g.v(%d).in('USE').has('type','ArrayIndexing').out('USE').code.dedup[0]" % forUseID
					firstArrSym = db.runGremlinQuery(q_firstArrSym)
					# mylogger.trace(forCondition)
					if firstArrSym :
						# mylogger.trace("Checking %s in %s" % (firstArrSym, funcName))
					# echo "g.v(9678).out.statements().has('type','Condition').out('USE').dedup[1].in('USE').has('type','ArrayIndexing').
					# out('USE').dedup"|joern-lookup -g

						if "->" in firstArrSym[0]:
							structSym = firstArrSym[0].split("->")[0]
							member = firstArrSym[0].split("->")[1]
							q_getCalls = "g.V().has('type','ExpressionStatement').filter{ it.functionId == %d && it.code.startsWith('%s=')}.\
										code.dedup" % (int(function_id), structSym)
							# mylogger.trace(q_getCalls)
							getCalls = db.runGremlinQuery(q_getCalls)

							if getCalls:
								callFunction = getCalls[0].strip().split("=")[1].split("(")[0].rstrip().lstrip()
								# mylogger.trace(self.retList[callFunction])

								if callFunction in self.retList:
									for item in self.retList[callFunction].members:
										# if item.name == member:
										poiDescription = "Param or Return value %s of %s may conflict with %s at \
											\n\t%s in Function: %s of %s." % (self.retList[callFunction].members[item].size, callFunction, condCode, loc, funcName, funcFile)
										poiDetails = ""	
										vScore = 0
										codeComplx = 0
										startLine = 0
										exitLine = 0
										address = 0x0
										funcInfoObj = FuncInfo(funcName, funcFile.split('/')[-1])
										if funcInfoObj in self.funcInfoList:
											idx = self.funcInfoList.index(funcInfoObj)
											vScore = self.funcInfoList[idx].vulnScore
											codeComplx = self.funcInfoList[idx].codeComplexity
											startLine = self.funcInfoList[idx].startLoc
											exitLine = self.funcInfoList[idx].exitLoc
											address = self.funcInfoList[idx].address
										pr = POIRecord('MODERATE', funcFile, loc, typeOfAnalysis, funcName, stmt, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
										if pr not in poiList:
											poiList.append(pr)
										mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, funcFile, startLine, exitLine, funcName, loc, stmt, vScore))
										mylogger.trace("POI location:%s" % funcName)
										numberOfPOIs += 1
										# mylogger.trace(colored(poiDescription,'cyan'))
							# check for C = allocate_matrix ( Crow , Ccol )


						varSymName = firstArrSym[0].replace(" ","").replace("->",".")
						varSize = None
						if funcName in varlist:
							# mylogger.trace(varlist[funcName])
							for var in varlist[funcName]:
								if (var.varName == varSymName):
									varSize = var.size
									break

							# isSafe = True
							insCMPsize = 0
							#TODO need to get all array indexing; need to find corresponding cmp insn in binary
							if varSize:
								for cmpInsn in cmpInsns:
									# blk = cmpInsn.properties['blk_id']
									insn = cmpInsn.properties['insn']
									#cmp imm, reg ; constants are refered by operand 1
									op1 = insn.split(' ')[1].rstrip(',')
									if (op1[0] == '$'):
										op1 = op1.lstrip('$')
										# op2 = insn.split(' ')[2]
										insCMPsize = int(op1,16)
										# mylogger.trace("Compare var size %s with insCmpsize %s" % (varSize, insCMPsize))
										if (varSize < insCMPsize):
											# mylogger.trace(colored("%s [%s, %s, %s]" % (stmt, funcName, loc, funcFile),'cyan'))
											poiDescription = "Expected size:%s Actual Size:%s." % (varSize, insCMPsize)
											poiDetails = ""
											vScore = 0
											codeComplx = 0
											startLine = 0
											exitLine = 0
											address = 0x0
											funcInfoObj = FuncInfo(funcName, funcFile.split('/')[-1])
											if funcInfoObj in self.funcInfoList:
												idx = self.funcInfoList.index(funcInfoObj)
												vScore = self.funcInfoList[idx].vulnScore
												codeComplx = self.funcInfoList[idx].codeComplexity
												startLine = self.funcInfoList[idx].startLoc
												exitLine = self.funcInfoList[idx].exitLoc
												address = self.funcInfoList[idx].address
											pr = POIRecord('MODERATE', funcFile, loc, typeOfAnalysis, funcName, stmt, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
											if pr not in poiList:
												poiList.append(pr)
											mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, funcFile, startLine, exitLine, funcName, loc, stmt, vScore))
											mylogger.trace("POI location:%s" % funcName)
											numberOfPOIs += 1
											mylogger.trace(poiDescription)
							#					isSafe = False
											break
							# if not isSafe:
							#		# mylogger.trace(colored("%s in function %s may be unsafe" % (stmt, funcName),'cyan'))
							#		# mylogger.trace("At %s" % (funcFile))
							#		mylogger.trace(colored("%s [%s, %s, %s]" % (stmt, funcName, loc, funcFile),'cyan'))
							#		poiList.append(POIRecord('moderate', funcFile, loc, typeOfAnalysis, funcName, stmt))
							#		mylogger.trace("Expected size:%s Actual Size:%s" % (varSize, insCMPsize))
							#		break
						else:
							None
							# mylogger.error(colored("Function %s not found in Var List" % funcName))
		mylogger.trace("POIs generated for %s: %s" % (typeOfAnalysis, numberOfPOIs))
		del graph
		# return poiList

	def printFuncList(self,csv_file):
		pathHome = os.getenv("HOME")
		file = os.path.join(pathHome, "logs", "%s_metrics.csv" % str(csv_file))
		with open(file, 'w') as csvfile:
			writer = csv.DictWriter(csvfile,fieldnames=vars(self.funcInfoList[0]))
			writer.writeheader()

			for funcInfo in self.funcInfoList:
				writer.writerow({k:getattr(funcInfo,k) for k in vars(funcInfo)})


	def pointerCheck(self):
		poiList = []
		try:
			with timeout(3600):
				self.pointerCheck_impl(poiList)
		except TimeoutException as e:
			mylogger.warn("PTR_NULL_CHK Analysis Timed out!")
		except Exception as e:
			mylogger.exception(e)
		finally:
			mylogger.trace("PTR_NULL_CHK POIs = %d" % len(poiList))
			return poiList

	def pointerCheck_impl(self, poiList):
		numberOfPOIs = 0
		typeOfAnalysis = 'PTR_NULL_CHK'
		# poiList = []
		poiTitle = "CWE-476: NULL Pointer Dereference"
		db = self.db
		graph = drawer(db, self.subBAPList)

		#get NULL assignments
		q_nullAssgn = "g.V().has('type','AssignmentExpr').as('x').rval.filter{ it.code.matches('NULL')}.back('x').statements().dedup"
		nullAssgn = db.runGremlinQuery(q_nullAssgn)

		for nullNode in nullAssgn:
			nullNodeID = nullNode.ref.split('/')[1]
			func_id = nullNode.properties['functionId']
			fName = self.funcList[func_id][0]
			file = self.funcList[func_id][1]
			loc = nullNode.properties['location']
			q_offset = "g.v(%d).as('x').out.loop('x'){ it.loops < 5 && it.object.hasNot('kind')}.offset.dedup" % int(nullNodeID)
			lineOffset = [i for i in db.runGremlinQuery(q_offset) if i]
			lineOffset = lineOffset[0] if lineOffset else None
			nullCode = nullNode.properties['code']
			graph.addSrcCFG(fName, func_id)
			netG = graph.getNxGraph()

			# assgnSymbol = re.split('-|>|\\*',nullNode.properties['code'].split('=')[0])[-1].split(' ')[-1]
			assgnSymbol = re.split('-|>|\\*',nullNode.properties['code'].split('=')[0])[-1].replace(';',' ').rstrip().split(' ')[-1]
			# mylogger.trace("%s to %s" % (nullNode.properties['code'], assgnSymbol))
			q_ptrDefs = "g.V().filter{ it.functionId == %d }.has('type','Condition').filter{ it.code.contains('%s')}.dedup" % (int(func_id), assgnSymbol)
			ptrDefs = db.runGremlinQuery(q_ptrDefs)
			nullCondCheckList = [ str(ptrDef.ref.split('/')[1]) for ptrDef in ptrDefs ]
			# q_ptrDefs = "g.v(%d).out('DEF').in('DEF').has('isCFGNode').has('type','Condition').filter{ it.code.contains('NULL')}.dedup" % int(nullNodeID)
			# ptrDefs = db.runGremlinQuery(q_ptrDefs)
			# nullCondCheckList = [ str(ptrDef.ref.split('/')[1]) for ptrDef in ptrDefs ]

			#TODO: the symbol can contain in an assignmentExpr on right side. This case must be ruled out.
			q_getAddrUses = "g.V().filter{ it.functionId == %d }.has('type','AssignmentExpr').filter{ it.code.contains('%s') }.statements().dedup" % (int(func_id),assgnSymbol)
			addrUses = db.runGremlinQuery(q_getAddrUses)
			addrUseCheckList = [ str(addrUse.ref.split('/')[1]) for addrUse in addrUses ].remove(str(nullNodeID))

			q_ptrUses = "g.v(%d).out('DEF').in('USE').has('isCFGNode').dedup" % int(nullNodeID)
			ptrUses = db.runGremlinQuery(q_ptrUses)

			ptrUseLocs = {}
			for ptrUse in ptrUses:
				if 'location' in ptrUse.properties:
					defID = int(ptrUse.ref.split('/')[1])
					defLoc = ptrUse.properties['location'].split(':')[0]
					ptrUseLocs[defID] = defLoc

			for ptrUse in ptrUses:
				destID = int(ptrUse.ref.split('/')[1])
				nodeA = str(nullNodeID)		#NULL assignment node
				nodeB = str(destID)			#Variable usages
				if nodeA in netG and nodeB in netG:
					for usePath in list(nx.all_simple_paths(netG, nodeA, nodeB)):
						# if ( any(i in defList for i in path)):
						# If a path exist from NULL initialization to a use, it must include a definition (intersect with def list)
						if (nullCondCheckList is not None and set(nullCondCheckList).intersection(usePath)):
							# mylogger.trace("Null condition check found")
							None
						elif (addrUseCheckList is not None and set(addrUseCheckList).intersection(usePath)):
							# mylogger.trace("Symbol use is found")
							None
						else:
							mylogger.trace("In %s at %s:%s, %s may be dereferenced later" % (fName, file, loc.split(':')[0], nullCode))
							# TODO: This needs to show source files+lines, not
							# node IDs
							# for nodeDefID in usePath:
							# 	if int(nodeDefID) in ptrUseLocs:
							# 		mylogger.trace(ptrUseLocs[int(nodeDefID)])
							poiDescription = "Variable assigned to NULL in function %s may be dereferenced later." % fName
							poiDetails = ""
							vScore = 0
							codeComplx = 0
							startLine = 0
							exitLine = 0
							address = 0x0
							funcInfoObj = FuncInfo(fName, file.split('/')[-1])
							if funcInfoObj in self.funcInfoList:
								idx = self.funcInfoList.index(funcInfoObj)
								vScore = self.funcInfoList[idx].vulnScore
								codeComplx = self.funcInfoList[idx].codeComplexity
								startLine = self.funcInfoList[idx].startLoc
								exitLine = self.funcInfoList[idx].exitLoc
								address = self.funcInfoList[idx].address
							pr = POIRecord('MODERATE', file, loc, typeOfAnalysis, fName, nullCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
							if pr not in poiList:
								poiList.append(pr)
							mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, file, startLine, exitLine, fName, loc, nullCode, vScore))
							mylogger.trace("POI location:%s" % fName)
							numberOfPOIs += 1
							break
					break
			graph.resetNxGraph()

		del graph

		'''
		Checking for null pointer check returned by alloc calls
		'''
		q_allocCalls = "queryNodeIndex('isCFGNode:True').filter{ it.code.contains('calloc') || it.code.contains('malloc')}"
		allocCalls = db.runGremlinQuery(q_allocCalls)
		poiTitle = 'CWE-690: Unchecked Return Value to NULL Pointer Dereference'
		for allocCall in allocCalls:
			# mylogger.trace(allocCall)
			statementType = allocCall.properties['type']
			func_id = allocCall.properties['functionId']
			fName = self.funcList[func_id][0]
			file = self.funcList[func_id][1]
			if( statementType != 'ReturnStatement'):
				# The malloc calls usually should be immediately followed by a null check
				allocID = int(allocCall.ref.split('/')[1])

				# q_allocNullChk = "g.v(%d).out.has('type','Symbol').filter{ ! it.code.startsWith('calloc')}.in.has('type','Condition').filter{ it.code.startsWith('!')}.dedup" % allocID
				# q_allocNullChk = "g.v(%d).out.has('type','Symbol').filter{ ! it.code.startsWith('calloc')}.in.has('type','Condition').dedup" % allocID
				q_allocNullChk = "g.v(%d).out.has('type','Symbol').filter{ ! it.code.contains('alloc')}.in.has('type','Condition').dedup" % allocID
				allocNullChk = db.runGremlinQuery(q_allocNullChk)

				if (len(allocNullChk) == 0):
					loc = allocCall.properties['location']
					q_offset = "g.v(%d).as('x').out.loop('x'){ it.loops < 5 && it.object.hasNot('kind')}.offset.dedup" % int(allocCall.ref.split('/')[1])
					lineOffset = [i for i in db.runGremlinQuery(q_offset) if i]
					lineOffset = lineOffset[0] if lineOffset else None
					allocCode = allocCall.properties['code']
					mylogger.trace("In %s:%s, function %s:" % (file, loc.split(':')[0], fName))
					mylogger.trace(colored("\tNULL check may not have been done on memory allocation result: %s" % (allocCode),'cyan'))
					# poiTitle = "Missing NULL Check"
					poiDescription = "NULL check may not have been done on heap allocation result in function %s." % fName
					poiDetails = ""
					vScore = 0
					codeComplx = 0
					startLine = 0
					exitLine = 0
					address = 0x0
					funcInfoObj = FuncInfo(fName, file.split('/')[-1])
					if funcInfoObj in self.funcInfoList:
						idx = self.funcInfoList.index(funcInfoObj)
						vScore = self.funcInfoList[idx].vulnScore
						codeComplx = self.funcInfoList[idx].codeComplexity
						startLine = self.funcInfoList[idx].startLoc
						exitLine = self.funcInfoList[idx].exitLoc
						address = self.funcInfoList[idx].address
					pr = POIRecord('HIGH', file, loc, typeOfAnalysis, fName, allocCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
					if pr not in poiList:
						poiList.append(pr)
					mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, file, startLine, exitLine, fName, loc, allocCode, vScore))
					mylogger.trace("POI location:%s" % fName)
					numberOfPOIs += 1
			else:
				q_AllocPtrReturns = "queryNodeIndex('isCFGNode:True').filter{ it.code.contains('%s')}" % fName
				allocPtrReturns = db.runGremlinQuery(q_AllocPtrReturns)

				for allocPtrReturn in allocPtrReturns:
					allocID = int(allocPtrReturn.ref.split('/')[1])

					q_allocNullChk = "g.v(%d).out.has('type','Symbol').filter{ ! it.code.startsWith('calloc')}.in.has('type','Condition').filter{ it.code.startsWith('!')}.dedup" % allocID
					allocNullChk = db.runGremlinQuery(q_allocNullChk)

					if (len(allocNullChk) == 0):
						loc = allocCall.properties['location']
						q_offset = "g.v(%d).as('x').out.loop('x'){ it.loops < 5 && it.object.hasNot('kind')}.offset.dedup" % int(allocCall.ref.split('/')[1])
						lineOffset = [i for i in db.runGremlinQuery(q_offset) if i]
						lineOffset = lineOffset[0] if lineOffset else None
						allocCode = allocCall.properties['code']
						mylogger.trace("In %s:%s, function %s:" % (file, loc.split(':')[0], fName))
						mylogger.trace(colored("\tNULL check may not have been done on memory allocation result: %s" % (allocCode),'yellow'))
						# poiTitle = "Missing NULL Check"
						poiDescription = "NULL check may not have been done on heap allocation result in function %s." % fName
						poiDetails = ""
						vScore = 0
						codeComplx = 0
						startLine = 0
						exitLine = 0
						address = 0x0
						funcInfoObj = FuncInfo(fName, file.split('/')[-1])
						if funcInfoObj in self.funcInfoList:
							idx = self.funcInfoList.index(funcInfoObj)
							vScore = self.funcInfoList[idx].vulnScore
							codeComplx = self.funcInfoList[idx].codeComplexity
							startLine = self.funcInfoList[idx].startLoc
							exitLine = self.funcInfoList[idx].exitLoc
							address = self.funcInfoList[idx].address
						pr = POIRecord('HIGH', file, loc, typeOfAnalysis, fName, allocCode, title=poiTitle, description=poiDescription, details=poiDetails, vulnScore=vScore, codeComplexity=codeComplx, offset=lineOffset, funcAddr=address)
						if pr not in poiList:
							poiList.append(pr)
						mylogger.poi("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s, %s" % (address, lineOffset, typeOfAnalysis, poiTitle, file, startLine, exitLine, fName, loc, allocCode, vScore))
						mylogger.trace("POI location:%s" % fName)
						numberOfPOIs += 1
		mylogger.trace("POIs generated for %s: %s" % (typeOfAnalysis, numberOfPOIs))
		# return poiList
