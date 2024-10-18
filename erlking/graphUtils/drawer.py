from neo4j import GraphDatabase
from neo4j.graph import Node, Relationship
import pygraphviz as pgv
# from graphviz import Source
from networkx.drawing.nx_agraph import write_dot
import os
import sys
import networkx as nx
from joern.all import JoernSteps
import time
sys.path[0:0] = ['.', '..']
from mylogging.erlLogger import mylogger
import logging
mylogger = logging.getLogger('ek.gu')


class drawer(object):
	def __init__(self, dbcon, sbList=None, cg=None):
		self.dbcon = dbcon
		self.sbList = sbList
		self.cg = cg
		self.netG = nx.MultiDiGraph()
		self.G = pgv.AGraph(strict=False, directed=True)

	def graph_from_neo4j(self, edges, kind=None):
		# TODO: edge and node key must be a str
		# TODO: use only one of pgv or nx and convert them to other one
		def add_node(node):
			# Adds node id it hasn't already been added
			u = node.ref.split('/')[1]
			label = "%s\n%s\n%s" % (u, node.properties['code'], node.properties['type'])
			# mylogger.info(node.properties)
			if ('location' in node.properties):
				label = "[%s]%s\n%s\n%s" % (u, node.properties['location'], node.properties['code'], node.properties['type'])
			# 	u = node.properties['location'].split(':')[0]
			if ( 'address' in node.properties):

				u = node.properties['tid']
				# mylogger.info("%s <<<< %s" % (u, type(u)))
				label="%s\n%s" % (node.properties['address'], node.properties['insn'])
			# else:
				# u = 0
				# u = node.ref.split('/')[1]

			if self.G.has_node(u):
				return
			# label = "%s\n%s\n%s" % (node.properties['location'].split(':')[0], node.properties['code'], node.properties['type'])
			
			self.netG.add_node(u, labels=label, key=u)
			self.G.add_node(u, label=label, key=u)

		def add_edge(relation, kind=None):
			# Adds edge if it hasn't already been added.
			# Make sure the nodes at both ends are created
			# for node in (relation.start_node, relation.end_node):
			#     add_node(node)
			# Check if edge already exists
			u = relation.start_node.ref.split('/')[1]
			v = relation.end_node.ref.split('/')[1]
			if (kind == "src2line"):
				v = relation.end_node.properties['tid']
				eid = relation.ref.split('/')[1]
				# if self.G.has_edge(u, v, key=eid):
				# 	return
				# If not, create it
				self.netG.add_edge(u, v, key=eid, labels=relation.type, properties=relation.properties)
				self.netG.add_edge(v, u, key='r_'+str(eid), labels=relation.type, properties=relation.properties)	
				self.G.add_edge(u, v, label=relation.type, color='blue', style='dotted')
				self.G.add_edge(v, u, label=relation.type, color='blue', style='dotted')
			else:
				eid = relation.ref.split('/')[1]
				# if self.G.has_edge(u, v, key=eid):
				# 	return
				# If not, create it
				self.netG.add_edge(u, v, key=eid, labels=relation.type, properties=relation.properties)	
				self.G.add_edge(u, v, label=relation.type, color='red')

	    # def _getEdges(self, function_id, type):

	    #     query = """queryNodeIndex('functionId:%s AND isCFGNode:True').outE('%s')""" % (function_id, type)
	    #     return j.runGremlinQuery(query)

		for edge in edges:
				# Parse node
			add_node(edge.start_node)
			add_node(edge.end_node)
			# try:
			# 	print("[%s] %s -> %s [%s]" % (edge.start_node.ref, edge.start_node.properties['location'], edge.end_node.properties['location'], edge.end_node.ref))
			# except:
			# 	None
			# Parse link
			add_edge(edge, kind)

	def draw(self, funcName):
		pathHome = os.getenv("HOME")
		pathFile = os.path.join(pathHome, "logs", "%s_src_bin_cfg.dot" % str(funcName))
		self.G.write(pathFile)
		# nx.nx_pydot.write_dot(self.netG, pathFile)

	def getNxGraph(self):
		return self.netG

	def resetNxGraph(self):
		self.netG = nx.MultiDiGraph()

	'''
	This method should provide the CFG / DDG or both in networkx graph using source CPG (Neo4j).
	One use case is to get forward/backward slicing given a line.
	lineAsNodeID=True not recommended as single line can consist multiple statements and would yield incorrect graph.
	also it is recommended to pass the funcID as there can be multiple functions by the same name. 
	'''
	def getSrcGraph(self, graphType, funcName, funcID=None, lineInLabel=False, lineAsNodeID=False):

		graph = nx.DiGraph()
		if funcID is None:
			q_getFunctionID = "getFunctionsByName('%s').id" % funcName
			funcID = self.dbcon.runGremlinQuery(q_getFunctionID)[0]
		cpgEdges = []

		if graphType == 'cfg':
			q_getEdges = "queryNodeIndex('functionId:%s AND isCFGNode:True').outE('FLOWS_TO')" % funcID
		elif graphType == 'ddg':
			q_getEdges = "queryNodeIndex('functionId:%s AND isCFGNode:True').outE('REACHES')" % funcID
		elif graphType == 'all':
			q_getEdges = "queryNodeIndex('functionId:%s AND isCFGNode:True').outE('FLOWS_TO')" % funcID
			cpgEdges = self.dbcon.runGremlinQuery(q_getEdges)
			q_getEdges = "queryNodeIndex('functionId:%s AND isCFGNode:True').outE('REACHES')" % funcID
		elif graphType == 'ast':
			q_getEdges = "g.v(%d).functionToAST().astNodes.outE('IS_AST_PARENT').dedup" % int(funcID)
		else:
			return None
		cpgEdges += self.dbcon.runGremlinQuery(q_getEdges)

		if cpgEdges == []:
			print("No function found")

		for edge in cpgEdges:
			lineColor = 'blue' if edge.rel.type == 'FLOWS_TO' else 'red'
			toID = edge.end_node.ref.split('/')[1]
			toCode = edge.end_node.properties['code']

			fromID = edge.start_node.ref.split('/')[1]
			fromCode = edge.start_node.properties['code']

			toLine = edge.end_node.properties['location'].split(':')[0] if 'location' in  edge.end_node.properties else -1
			fromLine = edge.start_node.properties['location'].split(':')[0] if 'location' in  edge.start_node.properties else 0

			if lineAsNodeID:
				fromID = fromLine
				toID = toLine
			# if 'location' in  edge.end_node.properties and 'location' in  edge.start_node.properties:
			# 	toLine = edge.end_node.properties['location'].split(':')[0]
			# 	fromLine = edge.start_node.properties['location'].split(':')[0]
			# else:
			# 	continue
			if not lineInLabel:
				fromLabel = str(fromCode)
				toLabel = str(toCode)
			else:
				fromLabel = str(fromID)+': \n'+str(fromCode)
				toLabel = str(toID)+': \n'+str(toCode)

			graph.add_node(fromID, label=fromLabel, style='filled', fillcolor='green')
			graph.add_node(toID, label=toLabel, style='filled', fillcolor='green')
			graph.add_edge(fromID, toID, label=edge.rel.type, color=lineColor)

		# print(graph.edges)
		return graph

	'''
	Given a function and line this should consider all backward paths from the entry
	and find all dependencies of nodeIdOfLine among them.
	Line can have many corresponding nodes, therefore the exact nodeID is expected.
	Forward slicing should work if you consider the inverse graph.
	'''
	def backwardSlicing(self, funcName, nodeIdOfLine, funcID=None):
		# mylogger.trace("-----------")
		nodeIdOfLine = str(nodeIdOfLine)
		if funcID is None:
			q_getFunctionID = "getFunctionsByName('%s').id" % funcName
			funcID = self.dbcon.runGremlinQuery(q_getFunctionID)[0]

		backwardNodes = []

		cfg = self.getSrcGraph('cfg', None, funcID)

		#TODO: entry node should not neccesarily be the first node with in_degree = 0.
		#Haven't noticed a CFG with multiple nodes with in_degree = 0 though.
		entryNode = [node for node in cfg.nodes if cfg.in_degree(node) == 0][0]
		if nx.has_path(cfg, entryNode, nodeIdOfLine):
			for path in nx.all_simple_paths(cfg, entryNode, nodeIdOfLine):
				backwardNodes += path
		ddGraph = self.getSrcGraph('ddg', None, funcID)
		dependencyNodes = [nodeIdOfLine]
		stack = [nodeIdOfLine]
		visited = set()

		while stack:
			topStackNode = stack.pop()
			for u,v in ddGraph.in_edges(topStackNode):
				if u in visited or u not in backwardNodes:
					continue
				if u not in dependencyNodes:
					dependencyNodes.append(u)
				visited.add(u)
				stack.append(u)

				# for s,t in ddGraph.in_edges(u):
				# 	if s not in visited:
				# 		stack.append(s)

		# H = cfg.subgraph(dependencyNodes)
		return dependencyNodes

	def addSrcDDG(self, funcName, funcID = None):
		# os.system("echo 'getFunctionsByName(\"" + funcName + "\").id' | joern-lookup -g| tail -n 1 | joern-plot-proggraph -cfg > ~/logs/\"" + funcName+"\"_src_cfg.dot;")
		if funcID is None:
			# q_getFuncId = "getFunctionsByName('%s').id" % funcName
			q_getFuncId = "g.V().has('type','Function').filter{ it.name == '%s' }.id" % funcName
			mylogger.trace(q_getFuncId)
			function_id = self.dbcon.runGremlinQuery(q_getFuncId)[0]
		else:
			function_id = funcID
		if function_id != []:
			q_getSrcDDG = """queryNodeIndex('functionId:%s AND isCFGNode:True').outE('%s')""" % (function_id, 'REACHES')
			srcDDG = self.dbcon.runGremlinQuery(q_getSrcDDG)
			self.graph_from_neo4j(srcDDG)

	def addSrcCFG(self, funcName, funcID = None):
		# os.system("echo 'getFunctionsByName(\"" + funcName + "\").id' | joern-lookup -g| tail -n 1 | joern-plot-proggraph -cfg > ~/logs/\"" + funcName+"\"_src_cfg.dot;")
		if funcID is None:
			# q_getFuncId = "getFunctionsByName('%s').id" % funcName
			q_getFuncId = "g.V().has('type','Function').filter{ it.name == '%s' }.id" % funcName
			mylogger.trace(q_getFuncId)
			function_id = self.dbcon.runGremlinQuery(q_getFuncId)[0]
		else:
			function_id = funcID
		if function_id != []:
			q_getSrcCFG = """queryNodeIndex('functionId:%s AND isCFGNode:True').outE('%s')""" % (function_id, 'FLOWS_TO')
			srcCFG = self.dbcon.runGremlinQuery(q_getSrcCFG)
			self.graph_from_neo4j(srcCFG)

	def addSrcAST(self, funcName, funcID = None):
		# os.system("echo 'getFunctionsByName(\"" + funcName + "\").id' | joern-lookup -g| tail -n 1 | joern-plot-proggraph -cfg > ~/logs/\"" + funcName+"\"_src_cfg.dot;")
		if funcID is None:
			# q_getFuncId = "getFunctionsByName('%s').id" % funcName
			q_getFuncId = "g.V().has('type','Function').filter{ it.name == '%s' }.id" % funcName
			mylogger.trace(q_getFuncId)
			function_id = self.dbcon.runGremlinQuery(q_getFuncId)[0]
		else:
			function_id = funcID
		if function_id != []:
			q_getSrcAST = "g.v(%d).functionToAST().astNodes.outE('IS_AST_PARENT').dedup" % int(function_id)
			srcAST = self.dbcon.runGremlinQuery(q_getSrcAST)
			self.graph_from_neo4j(srcAST)			

	def addSrcBinEdge(self, funcName):
		q_getFuncId = "getFunctionsByName('%s').id" % funcName
		function_id = self.dbcon.runGremlinQuery(q_getFuncId)[0]
		q_getSrcBinEdges = "g.E().filter{ it.label == 'src2line'}.as('x').outV.filter{ it.functionId == %s }.back('x').dedup" % function_id
		# q_getSrcBinEdges = "g.E().as('x').outV.filter{ it.functionId == %s }.back('x').dedup" % function_id
		srcBinEdges = self.dbcon.runGremlinQuery(q_getSrcBinEdges)
		self.graph_from_neo4j(srcBinEdges, "src2line")

	def addBinCFG(self,funcName):

		for blkidx in self.sbList[funcName].blks:
			blk = self.sbList[funcName].blks[blkidx]
			for insidx in blk.insns:
				curNode = blk.insns[insidx]
				label="%s-%s\n%s" % (curNode.tid,curNode.insType ,curNode.insn)

				if(curNode.insType == 'Def'):
					# mylogger.info(" %s >>>> %s" % (curNode.address, type(curNode.address)))
					label="%s\n%s" % (curNode.address, curNode.insn)
					self.G.add_node(curNode.tid,label=label,color='blue', key=curNode.tid)
					# self.G.add_node(curNode.address,label=label, color='blue', key=curNode.address)
					self.netG.add_node(curNode.tid, labels=label, key=curNode.tid)
				elif(curNode.insType == 'Blk_entry' or curNode.insType == 'Connector'):
					self.G.add_node(curNode.tid,label=label,style='filled',fillcolor='yellow')
					self.netG.add_node(curNode.tid, labels=label, key=curNode.tid)
				else:
					self.G.add_node(curNode.tid,label=label,style='filled', fillcolor='red')
					self.netG.add_node(curNode.tid, labels=label, key=curNode.tid)
				for branch in curNode.targets:
					toNode = branch.target
					# if (toNode is not None):
					# 	self.G.add_edge(curNode.tid,toNode,color='green')
					# 	self.netG.add_edge(curNode.tid, toNode, key=toNode)	
					if(branch.branchType == 'Call'):
						self.G.add_edge(curNode.tid,branch.retID,color='blue')
						self.netG.add_edge(curNode.tid, branch.retID, label='falls', key=curNode)
					elif(toNode is not None):
						self.G.add_edge(curNode.tid,toNode,color='green')
						self.netG.add_edge(curNode.tid, toNode, label='falls' , key=toNode)	


		# graph.layout()
		# # graph.write(funcName + ".dot")
		# pathHome = os.getenv("HOME")
		# pathFile = os.path.join(pathHome, "logs", funcName +"_bin_cfg.dot")
		# graph.write(pathFile)
		

		# s = Source.from_file(funcName + ".dot")
		# s.view()
		# Use "dot -Tsvg funcName.dot -o cfg.svg; eog cfg.svg" in log folder of host
	def replace(self, pred, replaceBy):
		for e in self.G.in_edges(pred):
			self.G.add_edge(e[0], replaceBy, label=e.attr['label'])
		for e in self.G.out_edges(pred):
			if (e[1] != replaceBy):
				self.G.add_edge(replaceBy, e[1], label=e.attr['label'])
		self.G.remove_node(pred)


	def compareSrcBinCFG(self):
		for node in self.G.nodes():
			if (self.G.in_degree(node) == 1 and self.G.out_degree(node) == 1):
				# print(self.G.degree(node))
				prev = self.G.in_edges(node)[0][0]
				prevLabel = self.G.in_edges(node)[0].attr['label']
				nex = self.G.out_edges(node)[0][1]
				self.G.add_edge(prev, nex, label=prevLabel)
				self.G.remove_node(node)
			if( self.G.in_degree(node) == 0 or self.G.out_degree(node) == 0):
				self.G.remove_node(node)
			if (self.G.in_degree(node) == 1 and self.G.out_degree(node) > 0):
				prev = self.G.in_edges(node)[0][0]
				self.replace(prev, node)

	def drawCG(self):
		# mylogger.trace(type(self.cg))
		# graph = nx.DiGraph.reverse(self.cg)
		graph = self.cg
		pathHome = os.getenv("HOME")
		pathFile = os.path.join(pathHome, "logs", "CG.dot")
		write_dot(graph, pathFile)

	def generateCG(self):
		graph=pgv.AGraph(strict=False,directed=True)
		graphNodeID = None
		for sub in self.sbList:
			# mylogger.info("%s-%s" % (self.sbList[sub].id, self.sbList[sub].name))
			if self.sbList[sub] is not None:
				graphNodeID = self.sbList[sub].id
				graph.add_node(self.sbList[sub].id,label=self.sbList[sub].name,color='blue')
				for blkidx in self.sbList[sub].blks:
					blk = self.sbList[sub].blks[blkidx]
					mylogger.trace(blk)
					for insidx in blk.insns:
						curNode = blk.insns[insidx]
						mylogger.trace(curNode)
						label="%s-%s\n%s" % (curNode.tid,curNode.insType ,curNode.insn)

						for branch in curNode.targets:
							if(branch.branchType == 'Call'):
								graph.add_node(curNode.blk_id, label=label, color='blue')
								graph.add_edge(graphNodeID, curNode.blk_id, label=label, color='red')
								# graph.add_node(curNode.tid, label=label, color='blue')
								graph.add_edge(curNode.blk_id, branch.target, label='Return', color='green')
								graphNodeID = curNode.blk_id
								# mylogger.info("%s -> %s" % (curNode.tid, branch.target))
						# graphNodeID = curNode.blk_id
		graph.layout()
		# graph.write("CG.dot")
		pathHome = os.getenv("HOME")
		pathFile = os.path.join(pathHome, "logs", "CG.pdf")
		graph.write(pathFile)
		# s = Source.from_file("CG.dot")
		# s.view()
		# Use "dot -Tsvg CG.dot -o cg.svg; eog cg.svg" in log folder of host
