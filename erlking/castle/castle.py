from termcolor import colored
import logging
# from neo4j import GraphDatabase
# from neo4j.types.graph import Node, Relationship
# import pandas as pd
import pygraphviz as pgv
import os
import sys
import re
# from graphviz import Source
import networkx as nx
from pycparser import c_parser, c_ast, c_generator
from graphUtils.drawer import drawer

mylogger = logging.getLogger('ek.cs')

sys.path[0:0] = ['.', '..']

#TODO: this function is duplicated in Checker. 
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

class Castle(object):
	#Constructor
	def __init__(self, dbconn, retList=None, demangledFuncInfoList=None, sbCG=None, varLayout=None):
		self._dbconn = dbconn
		self._retList = retList
		self._demangledFuncInfoList = demangledFuncInfoList
		self._sbCG = sbCG
		self.funcList = getFunctionsList(dbconn)
		self.plot = drawer(dbconn)
		if retList is not None:
			self._evalFuncs()
		if demangledFuncInfoList is not None:
			processFuncInfo(dbconn, demangledFuncInfoList, retList, sbCG, varLayout, self.plot)


	'''
	TODO:This function should have evaluate all functions bottom-up of call graph.
	For a start, let's just consider all the functions that call calloc/malloc
	'''

	#TODO: consider all functions in bottom-up fashion in the call graph and along CFG paths
	def _evalFuncs(self):
		mylogger.trace("Parsing C statements of functions containing alloc calls")
		db = self._dbconn
		q_funcIDs = "g.V().has('code').filter{ it.code.contains('calloc') || it.code.contains('malloc') }.functionId.dedup"
		# q_forStmts = "g.V().has('code').has('type','ForStatement').out.statements().dedup"
		funcIDs = db.runGremlinQuery(q_funcIDs)
		#Only functions with calloc or malloc calls are considered
		for funcID in funcIDs:
			funcName = self.funcList[funcID][0]
			#TODO: some funcNames do not exists in _retList. (e.g. Pierrepont challenge; function "add_var")
			if funcName in self._retList:

				varList = { }		#{'variableName': size} except for P1, P2 etc refers to actual var name 
				paramList = { }		#Pseudo References for params, Last Param -> P1, Last Second Param -> P2 etc
				q_params = "g.V().filter{ it.functionId == "+ str(funcID) +"  && it.type == 'Parameter'}.code.dedup"
				params = db.runGremlinQuery(q_params)

				paramCount = 1

				for param in params:
					#TODO: following 2 essentially do the same. if not needed remove one of them.
					# (int a, int b) => varList[P1] = a, varList[P2] = b; paramList[a] = P1, paramList[b] = P2
					noKeywords = len(param.split(" "))
					if noKeywords < 3:
						lastOperand = param.split(" ")[-1]
						varList["P%d" % paramCount] = lastOperand
						paramList[lastOperand] = "P%d" % paramCount

					else:
						varList["P%d" % paramCount] = param
						paramList[param] = "P%d" % paramCount
					paramCount = paramCount + 1

				#Get return symbols and the type
				q_retSymbols = "g.V().filter{ it.functionId == "+ str(funcID) +"  && it.type == 'ReturnStatement' && \
					! it.code.contains('NULL') }.out('USE').in.has('type','IdentifierDeclStatement').code.dedup"

				retSymbols = db.runGremlinQuery(q_retSymbols)

				returnList = { }	#return variable name and their types

				for retSym in retSymbols:
					# retType = retSym.split("=")[0].split(" ")[0]
					retType = retSym.split("=")[0].split(" ")[-2]
					retVar = retSym.split("=")[0].rstrip().split(" ")[-1]
					returnList[retVar] = retType

				q_exprs = "g.V().filter{ it.functionId == "+ str(funcID) +"  && it.type == 'ExpressionStatement'}. \
					filter{ it.code.contains('=') }.code.dedup"
				exprs = db.runGremlinQuery(q_exprs)
				for exp in exprs:
					try:
						# code = exp.properties.get('code')
						# var = exp.split("=")[0].replace("->",".")
						var = exp.split("=")[0].strip()		#A -> values
						val = exp.split("=")[1].strip()		#v

						#Replace return variable to its type
						#Replace parameter values row * col -> P1 * P2
						for key in paramList.keys():
							# val = val.replace(key, paramList[key])
							# regEx = rf'\b{key}\b'
							regEx = re.escape(key)
							val = re.sub(regEx, paramList[key], val)
						varList[var] = val


						#If the statement has calloc|malloc then the corresponding return values size must be changed

						callList = ['calloc', 'malloc']
						# callList = ['calloc']
						parser = c_parser.CParser()
						generator = c_generator.CGenerator()
						if any(elem in val for elem in callList):
							'''
							To parse the statements must be wrapped with function def, hence adding a dummy function def
							and consider only the body
							'''
							stmt = """ \
							void test(){ \
							%s = %s ;\
							}""" %(var, val)

							ast = parser.parse(stmt, filename='<none>')
							function_body = ast.ext[0].body
							ast_assgn = function_body.block_items[0]
							ast_rval = ast_assgn.rvalue
							ast_args = ast_rval.args

							#TODO expr should be extracted based on operation types (BinaryOP/UniaryOp etc.)
							ast_expr = ast_args.exprs[0]
							if len(ast_args.exprs) > 1:
								ast_expr = ast_args.exprs[1]
								try:
									ast_expr = ast_expr.right
								except:
									None

							val = generator.visit(ast_expr)
							varList[var] = val
							#Replace any existing val with new value
							if var in varList.values():
								for key in varList.keys():
									if varList[key] == var:
										varList[key] = val
					except:
						continue

				for var in varList:
					symbols = var.replace(" ","").split("->")
					if len(symbols) > 1 and self._retList[funcName].name == symbols[0]:
						if symbols[1] in self._retList[funcName].members:
							member = self._retList[funcName].members[symbols[1]]
							# mylogger.trace("member %s size %s changed to %s" % (member.name, member.size, varList[var]))
							self._retList[funcName].members[symbols[1]].size = varList[var]



	def getRetList(self):
		return self._retList

'''
FunctInfoList.height must be updated here.
'''

def processFuncInfo(dbconn, demangledFuncInfoList, retList, sbCG, varList, plot):
	mylogger.trace("Updating funcInfo with binary CPG info")
	rev_sbCG = nx.DiGraph.reverse(sbCG)
	ext_sources = ['gets','read','recv','scanf', 'getenv']
	roots = [n for n,d in sbCG.in_degree() if d==0]

	ext_srcs = []
	for source in ext_sources:
		q_getSrcNodes = "g.V().has('insn').filter{ it.insn.startsWith('callq %s') }.blk_id.dedup" % source
		sourceIds = dbconn.runGremlinQuery(q_getSrcNodes)
		ext_srcs = ext_srcs + [int(source_id) for source_id in sourceIds]


	max_params = 0
	min_params = 10000
	max_cyclomaticNum	= 0
	min_cyclomaticNum	= 10000
	max_loopNum = 0
	min_loopNum = 10000
	max_nestingDegree = 0
	min_nestingDegree = 10000
	max_SLOC = 0
	min_SLOC = 10000
	max_ALOC = 0
	min_ALOC = 10000
	max_localVars = 0
	min_localVars = 10000
	max_localPtrVars = 0
	min_localPtrVars = 10000
	max_globalVarList = 0
	min_globalVarList = 10000
	max_pointerArgs = 0
	min_pointerArgs = 10000
	# max_isReturningPointers = 1
	# min_isReturningPointers = 0
	max_callees = 0
	min_callees = 10000
	max_callers = 0
	min_callers = 10000
	max_height =  0
	min_height =  10000
	max_conditions = 0
	min_conditions = 10000
	max_cmps = 0
	min_cmps = 10000
	max_jmps = 0
	min_jmps = 10000
	max_ptrAssn = 0
	min_ptrAssn = 10000

	# sloc_point1 = min_SLOC
	# sloc_point2 = max_SLOC
		# max_remark = remark


	for funcInfo in demangledFuncInfoList:
		if (funcInfo.funcId is not None):
			incomingPtrs = 0
			localVars = 0
			localPtrVars = 0

			if funcInfo.funcName in varList:
				for layoutInfo in varList[funcInfo.funcName]:
					if (layoutInfo.explicitType == 'pointer' and layoutInfo.tag == 'DW_TAG_formal_parameter'):
						incomingPtrs += 1
					if (layoutInfo.explicitType == 'pointer' and layoutInfo.tag != 'DW_TAG_formal_parameter'):
						localPtrVars += 1
					if (layoutInfo.tag == 'DW_TAG_variable'):
						localVars += 1
			funcInfo.localVars = localVars
			if max_localVars < localVars : max_localVars = localVars
			if min_localVars > localVars : min_localVars = localVars
			funcInfo.localPtrVars = localPtrVars
			if max_localPtrVars < localPtrVars : max_localPtrVars = localPtrVars
			if min_localPtrVars > localPtrVars : min_localPtrVars = localPtrVars
			funcInfo.pointerArgs = incomingPtrs
			if max_pointerArgs < incomingPtrs : max_pointerArgs = incomingPtrs
			if min_pointerArgs > incomingPtrs : min_pointerArgs = incomingPtrs

			if (funcInfo.funcName in retList and retList[funcInfo.funcName].explicitType == 'pointer'):
				funcInfo.isReturningPointers = 1

			q_getALOC = '''g.V().filter{ it.functionId == %d && it.kind == 'ASM'}.insn.dedup''' % funcInfo.funcId
			funcInfo.ALOC = len(dbconn.runGremlinQuery(q_getALOC))
			if max_ALOC < funcInfo.ALOC : max_ALOC = funcInfo.ALOC
			if min_ALOC > funcInfo.ALOC : min_ALOC = funcInfo.ALOC
			q_getBapFuncId = '''g.V().filter{ it.functionId == %d && it.kind == 'ASM'}.func_id.dedup''' % funcInfo.funcId
			bap_func_ids = dbconn.runGremlinQuery(q_getBapFuncId)
			if (len(bap_func_ids) > 0):
				bap_func_id = int(bap_func_ids[0])

				#Closest to root has the highest impact. We select the threashold heoght as 10. (main has height 5 due to libc initial calls)
				smallestHeight = 1000
				shortestPathLength = 1000
				for root in roots:
					if (root in sbCG and bap_func_id in sbCG):

						if (nx.has_path(sbCG, root, bap_func_id)):
							shortestPathLength = nx.shortest_path_length(sbCG, source=root, target=bap_func_id)
							if max_height <= shortestPathLength : max_height = shortestPathLength
							if min_height > shortestPathLength : min_height = shortestPathLength

				for root in ext_srcs:
					if (root in sbCG and bap_func_id in sbCG):

						if (nx.has_path(sbCG, root, bap_func_id)):
							shortestPathLength = nx.shortest_path_length(sbCG, source=root, target=bap_func_id)
							if max_height <= shortestPathLength : max_height = shortestPathLength
							if min_height > shortestPathLength : min_height = shortestPathLength

				# longestPath = dag_longest_path_length(sbCG)
				funcInfo.height = shortestPathLength if shortestPathLength < max_height else max_height
				# if min_height > smallestHeight : min_height = smallestHeight
				# funcInfo.ALOC = len(dbconn.runGremlinQuery(q_getALOC))
				q_getComps = '''g.V().filter{ it.functionId == %d && it.kind == 'ASM' && it.insn.startsWith('cmp')}.dedup''' % funcInfo.funcId
				cmps = len(dbconn.runGremlinQuery(q_getComps))
				if max_cmps < cmps : max_cmps = cmps
				if min_cmps > cmps : min_cmps = cmps
				# if max_height < shortestPathLength : max_height = shortestPathLength
				q_getJmps = '''g.V().filter{ it.functionId == %d && it.kind=='ASM' && it.insn.startsWith('j')}.dedup''' % funcInfo.funcId
				jmps = len(dbconn.runGremlinQuery(q_getJmps))
				if max_jmps < jmps : max_jmps = jmps
				if min_jmps > jmps : min_jmps = jmps
				funcInfo.nestingDegree = getNestingDegree(plot.getSrcGraph('ast', None, funcInfo.funcId))
				if max_nestingDegree < funcInfo.nestingDegree : max_nestingDegree = funcInfo.nestingDegree
				if min_nestingDegree > funcInfo.nestingDegree : min_nestingDegree = funcInfo.nestingDegree
				if min_SLOC > funcInfo.SLOC : min_SLOC = funcInfo.SLOC
				if max_SLOC < funcInfo.SLOC : max_SLOC = funcInfo.SLOC
				if min_cyclomaticNum > funcInfo.cyclomaticNum : min_cyclomaticNum = funcInfo.cyclomaticNum
				if max_cyclomaticNum < funcInfo.cyclomaticNum : max_cyclomaticNum = funcInfo.cyclomaticNum
				if min_callees > funcInfo.callees : min_callees = funcInfo.callees
				if max_callees < funcInfo.callees : max_callees = funcInfo.callees
				if min_callers > funcInfo.callers : min_callers = funcInfo.callers
				if max_callers < funcInfo.callers : max_callers = funcInfo.callers
				if min_ptrAssn > funcInfo.ptrAssn : min_ptrAssn = funcInfo.ptrAssn
				if max_ptrAssn < funcInfo.ptrAssn : max_ptrAssn = funcInfo.ptrAssn
				if min_conditions > funcInfo.conditions : min_conditions = funcInfo.conditions
				if max_conditions < funcInfo.conditions : max_conditions = funcInfo.conditions
				if min_loopNum > funcInfo.loopNum : min_loopNum = funcInfo.loopNum
				if max_loopNum < funcInfo.loopNum : max_loopNum = funcInfo.loopNum
				if min_params > funcInfo.paramList : min_params = funcInfo.paramList
				if max_params < funcInfo.paramList : max_params = funcInfo.paramList
				funcInfo.cmps = cmps
				funcInfo.jmps = jmps
				funcInfo.vulnScore = calculateVulnScore(funcInfo)
				funcInfo.codeComplexity = calculateCodeComplexity(funcInfo)
		# else:
		# 	mylogger.warn("Following function does not have function ID")
		# 	mylogger.trace(funcInfo)
	mylogger.trace("max_params %s" % max_params)
	mylogger.trace("min_params %s" % min_params)
	mylogger.trace("max_cyclomaticNum %s" % max_cyclomaticNum)
	mylogger.trace("min_cyclomaticNum %s" % min_cyclomaticNum)
	mylogger.trace("max_loopNum %s" % max_loopNum)
	mylogger.trace("min_loopNum %s" % min_loopNum)
	mylogger.trace("max_nestingDegree %s" % max_nestingDegree)
	mylogger.trace("min_nestingDegree %s" % min_nestingDegree)
	mylogger.trace("max_SLOC %s" % max_SLOC)
	mylogger.trace("min_SLOC %s" % min_SLOC)
	mylogger.trace("max_ALOC %s" % max_ALOC)
	mylogger.trace("min_ALOC %s" % min_ALOC)
	mylogger.trace("max_localVars %s" % max_localVars)
	mylogger.trace("min_localVars %s" % min_localVars)
	mylogger.trace("max_localPtrVars %s" % max_localPtrVars)
	mylogger.trace("min_localPtrVars %s" % min_localPtrVars)
	mylogger.trace("max_pointerArgs %s" % max_pointerArgs)
	mylogger.trace("min_pointerArgs %s" % min_pointerArgs)
	mylogger.trace("max_callees %s" % max_callees)
	mylogger.trace("min_callees %s" % min_callees)
	mylogger.trace("max_callers %s" % max_callers)
	mylogger.trace("min_callers %s" % min_callers)
	mylogger.trace("max_height %s" % max_height)
	mylogger.trace("min_height %s" % min_height)
	mylogger.trace("max_conditions %s" % max_conditions)
	mylogger.trace("min_conditions %s" % min_conditions)
	mylogger.trace("max_cmps %s" % max_cmps)
	mylogger.trace("min_cmps %s" % min_cmps)
	mylogger.trace("max_jmps %s" % max_jmps)
	mylogger.trace("min_jmps %s" % min_jmps)
	mylogger.trace("max_ptrAssn %s" % max_ptrAssn)
	mylogger.trace("min_ptrAssn %s" % min_ptrAssn)
	# Here we update the normalized metrics. If absolute values needed comment the following lines.

	# sloc_point1 = min_SLOC + (max_SLOC - min_SLOC)/3
	# sloc_point2 = max_SLOC - (max_SLOC- min_SLOC)/3

	for funcInfo in demangledFuncInfoList:
		if (funcInfo.funcId is not None):

			funcInfo.paramList = round((funcInfo.paramList - min_params) * 1000 / (max_params - min_params) if (max_params - min_params) != 0 else 0, 2)
			funcInfo.cyclomaticNum = round((funcInfo.cyclomaticNum - min_cyclomaticNum) * 1000 / (max_cyclomaticNum - min_cyclomaticNum) if (max_cyclomaticNum - min_cyclomaticNum) != 0 else 0, 2)
			funcInfo.loopNum = round((funcInfo.loopNum - min_loopNum) * 1000 / (max_loopNum - min_loopNum) if max_loopNum != 0 else 0, 2)
			funcInfo.nestingDegree = round((funcInfo.nestingDegree - min_nestingDegree) * 1000 / (max_nestingDegree - min_nestingDegree) if (max_nestingDegree - min_nestingDegree) != 0 else 0, 2)
			funcInfo.SLOC = round((funcInfo.SLOC - min_SLOC) * 1000 / (max_SLOC - min_SLOC) if (max_SLOC - min_SLOC) != 0 else 0, 2)
			funcInfo.ALOC = round((funcInfo.ALOC - min_ALOC) * 1000 / (max_ALOC - min_ALOC) if (max_ALOC - min_ALOC) != 0 else 0, 2)
			funcInfo.localVars = round((funcInfo.localVars - min_localVars) * 1000 / (max_localVars - min_localVars) if (max_localVars - min_localVars) != 0 else 0, 2)
			funcInfo.localPtrVars  = round((funcInfo.localPtrVars - min_localPtrVars) * 1000 / (max_localPtrVars - min_localPtrVars) if (max_localPtrVars - min_localPtrVars) != 0 else 0, 2)
			# self.globalVarList =  round((funcInfo.globalVarList - min_globalVarList) /  (max_globalVarList - min_globalVarList), 2)
			funcInfo.pointerArgs = round((funcInfo.pointerArgs - min_pointerArgs) * 1000 / (max_pointerArgs - min_pointerArgs) if (max_pointerArgs - min_pointerArgs) != 0 else 0, 2)
			# max_isReturningPointers = 1
			# min_isReturningPointers = 0
			funcInfo.callees = round((funcInfo.callees - min_callees) * 1000 / (max_callees - min_callees) if (max_callees - min_callees) != 0 else 0, 2)
			funcInfo.callers = round((funcInfo.callers - min_callers) * 1000 / (max_callers - min_callers) if (max_callers - min_callers) != 0 else 0, 2)
			funcInfo.height =  round((max_height - funcInfo.height) * 1000 / (max_height - min_height) if (max_height - min_height) != 0 else 0, 2)
			funcInfo.conditions = round((funcInfo.conditions - min_conditions) * 1000 / (max_conditions - min_conditions) if (max_conditions - min_conditions) != 0 else 0, 2)
			funcInfo.cmps = round((funcInfo.cmps - min_cmps) * 1000 / (max_cmps - min_cmps) if (max_cmps - min_cmps) != 0 else 0, 2)
			funcInfo.jmps = round((funcInfo.jmps - min_jmps) * 1000 / (max_jmps - min_jmps) if (max_jmps - min_jmps) != 0 else 0, 2)
			funcInfo.ptrAssn = round((funcInfo.ptrAssn - min_ptrAssn) * 1000 / (max_ptrAssn - min_ptrAssn) if (max_ptrAssn - min_ptrAssn) != 0 else 0, 2)
			# funcInfo.codeComplexity = calculateCodeComplexity(funcInfo)

def calculateCodeComplexity(funcInfo):
	# no_of_features = 14
	# codeComplexity = funcInfo.SLOC + funcInfo.ALOC + funcInfo.localVars + funcInfo.cyclomaticNum + funcInfo.loopNum + \
	# funcInfo.localPtrVars + funcInfo.pointerArgs + funcInfo.isReturningPointers + \
	# funcInfo.height + funcInfo.conditions + funcInfo.cmps + funcInfo.jmps + funcInfo.nestingDegree + funcInfo.ptrAssn
	codeComplexity = funcInfo.cyclomaticNum + funcInfo.loopNum + funcInfo.nestingDegree
	# complexityClass = round(codeComplexity/no_of_features, 2)
	# if (codeComplexity < sloc_point2):	complexityClass = 'moderate'
	# if (codeComplexity < sloc_point1):	complexityClass = 'low'
	return codeComplexity

def calculateVulnScore(funcInfo):
	#Weights for each feature assigned here
	w_cyclomaticNum = 0.0457
	w_loopNum = 0.0452
	w_localPtrVars = 0.0541
	w_pointerArgs = 0
	# w_isReturningPointers = 1
	w_height = 0.0572
	w_conditions = 0.1116
	w_cmps = 0.0634
	w_jmps = 0.0514
	w_nestingDegree = 0.0657
	w_ptrAssn = 0.0367
	w_paramList = 0.0541
	w_localVars = 0.0611
	w_SLOC = 0.0605
	w_ALOC = 0.0811
	w_callees = 0.0751
	w_callers = 0.0631


	vulnScore = (w_callees * funcInfo.callees) + (w_callers * funcInfo.callers) \
	+ (w_localVars * funcInfo.localVars) + (w_SLOC * funcInfo.SLOC) + (w_ALOC * funcInfo.ALOC) \
	+ (w_paramList * funcInfo.paramList) + (w_cyclomaticNum * funcInfo.cyclomaticNum) \
	+ (w_loopNum * funcInfo.loopNum) + (w_localPtrVars * funcInfo.localPtrVars) \
	# + (w_pointerArgs * funcInfo.pointerArgs)
	+ (w_height * funcInfo.height) \
	+ (w_conditions * funcInfo.conditions) + (w_cmps * funcInfo.cmps) + (w_jmps * funcInfo.jmps) \
	+ (w_nestingDegree * funcInfo.nestingDegree) + (w_ptrAssn * funcInfo.ptrAssn)

	return vulnScore



def getNestingDegree(astGtraph):
	return nx.dag_longest_path_length(astGtraph)
