README for VulGR datasets:

=== Usage ===

This folder contains the following comma separated text files 
(replace DS by the name of the dataset):

n = total number of nodes
m = total number of edges
N = number of graphs

(1) 	DS_A.txt (m lines) 
	sparse (block diagonal) adjacency matrix for all graphs,
	each line corresponds to (row, col) resp. (node_id, node_id)

(2) 	DS_graph_indicator.txt (n lines)
	column vector of graph identifiers for all nodes of all graphs,
	the value in the i-th line is the graph_id of the node with node_id i

(3) 	DS_graph_labels.txt (N lines) 
	class labels for all graphs in the dataset,
	the value in the i-th line is the class label of the graph with graph_id i

(4) 	DS_node_labels.txt (n lines)
	column vector of node labels,
	the value in the i-th line corresponds to the node with node_id i

There are OPTIONAL files following graph datasets similar to TUDatasets standard format which we have not generated (below files). We did not need in our research: 

(5) 	DS_edge_labels.txt (m lines; same size as DS_A_sparse.txt)
	labels for the edges in DD_A_sparse.txt 

(6) 	DS_edge_attributes.txt (m lines; same size as DS_A.txt)
	attributes for the edges in DS_A.txt 

(7) 	DS_node_attributes.txt (n lines) 
	matrix of node attributes,
	the comma seperated values in the i-th line is the attribute vector of the node with node_id i

(8) 	DS_graph_attributes.txt (N lines) 
	regression values for all graphs in the dataset,
	the value in the i-th line is the attribute of the graph with graph_id i


=== Description of the dataset === 

The VulGR dataset consists of 6 open source applications for the vulnerability detection. Each application has different number of vulnerable and no-vulnerable functions (graphs). The lables are 0 (non-vulnerable) and 1 (vulnerable). 

The source code for the applications are publicly available through Github for everybody for specific versions:


Node labels:

CompoundStatement
Statement
ExpressionStatement
ReturnStatement
ParameterList
Parameter
Identifier
ParameterType
FunctionDef
ReturnType
CFGExitNode
CFGEntryNode
IdentifierDeclStatement
IfStatement
IdentifierDecl
CallExpression
AssignmentExpr
Condition
SwitchStatement
IdentifierDeclType
Callee
ArgumentList
CastExpression
AndExpression
Argument
CastTarget
EqualityExpression
Label
Expression
PrimaryExpression
PtrMemberAccess
UnaryOp
UnaryOperator
ForStatement
GotoStatement
ForInit
IncDecOp
RelationalExpression
IncDec
SizeofExpr
AdditiveExpression
Sizeof
SizeofOperand
ConditionalExpression
BitAndExpression
BreakStatement
OrExpression
MemberAccess
ArrayIndexing
MultiplicativeExpression
ShiftExpression
WhileStatement
ElseStatement
ContinueStatement
UnaryExpression
InclusiveOrExpression
InitializerList
ClassDefStatement


Edge labels:

  Structure Type 	       Relations
====================      =======================================================================
Abstract Syntax Tree	-->   "IS_AST_PARENT_OF, IS_FUNCTION_OF_AST"
Control Flow Graph	-->   "FLOWS_TO, REACHES"
Data Flow Graph	-->   "USE, DEF"
Global Structure	-->   "IS_AST_PARENT_OF, IS_FUNCTION_OF_AST, IS_CLASS_OF, SRC2ASM, ASM2SRC"
Binary CFG 	        -->   "BIN_CFG"



=== Previous Use of the Dataset ===



=== References ===

