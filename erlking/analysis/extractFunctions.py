from joern.all import JoernSteps

db = JoernSteps()
db.setGraphDbURL('http://localhost:7474/db/data/')
db.connectToDatabase()

q_getFuncs = '''g.V().has('type','Function').dedup'''
funcs = db.runGremlinQuery(q_getFuncs)

# for func in funcs:
# 	funcId = func.ref.split('/')[1]
# 	funcName = func.properties['name']
# 	prog = {}
# 	if (funcName == 'test_rotate'):
# 		print("Function found")
# 		file = open("%s.c" % funcName,"w")
# 		q_getCodes = '''g.V().filter{ it.functionId == %s}.has('location').dedup''' % int(funcId)
# 		print(q_getCodes)
# 		codes = db.runGremlinQuery(q_getCodes)
# 		for code in codes:
# 			loc = code.properties['location'].split(':')[0]
# 			insn = code.properties['code']
# 			prog[loc] = insn
# 			# file.write("%s\n" % str(code.properties['code']))
# 		# file.close

# 		prog = dict(sorted(prog.items()))

# 		for k, v in prog.items(): print(k, v)


# g.V().filter{ it.functionId == 87300 }.outE('src2line').dedup		


for func in funcs:
	funcId = func.ref.split('/')[1]
	funcName = func.properties['name']
	file = open("%s_bin.txt" % funcName,"w")
	q_getEdges = '''g.V().filter{ it.functionId == %s }.outE('Goto').dedup	''' % int(funcId)
	edges = db.runGremlinQuery(q_getEdges)
	for edge in edges:
		file.write("%s\n" % str(edge))
	file.close()

for func in funcs:
	funcId = func.ref.split('/')[1]
	funcName = func.properties['name']
	file = open("%s_cdcpg.txt" % funcName,"w")
	q_getEdges = '''g.V().filter{ it.functionId == %s }.outE().dedup	''' % int(funcId)
	edges = db.runGremlinQuery(q_getEdges)
	for edge in edges:
		file.write("%s\n" % str(edge))
	file.close()


for func in funcs:
	funcId = func.ref.split('/')[1]
	funcName = func.properties['name']
	file = open("%s_cpg.txt" % funcName,"w")
	q_getEdges = '''g.v(%d).functionToAST().astNodes.outE('IS_AST_PARENT').dedup	''' % int(funcId)
	edges = db.runGremlinQuery(q_getEdges)
	q_getEdges = '''queryNodeIndex('functionId:%s AND isCFGNode:True').outE('FLOWS_TO').dedup	''' % funcId
	edges += db.runGremlinQuery(q_getEdges)
	q_getEdges = '''queryNodeIndex('functionId:%s AND isCFGNode:True').outE('REACHES').dedup	''' % funcId
	edges += db.runGremlinQuery(q_getEdges)
	for edge in edges:
		file.write("%s\n" % str(edge))
	file.close()		