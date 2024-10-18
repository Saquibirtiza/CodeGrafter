import re
import bap
import logging

mylogger = logging.getLogger('ek.exp')


class RegVal(object):
	def __init__():
		self.base = None
		self.disp = None

#This class is in progress
class GenPurpRegs(object):
	def __init__(self):
		self.regs = {
		"RAX" : "Any",
		"RBX" : "Any",
		"RCX" : "Any",
		"RDX" : "Any",
		"RSI" : "Any",
		"RDI" : "Any"
		}
		self.temps = {}

	def __str__(self):
		# return str(self.__dict__)
		return "[ rax : %s, rbx : %s, rcx : %s, rdx : %s, rsi : %s, rdi : %s]" % (self.regs['RAX'], self.regs['RBX'], self.regs['RCX'], self.regs['RDX'], self.regs['RSI'], self.regs['RDI'])
	def __repr__(self):
		# return str(self.__dict__)
		return "[ rax : %s, rbx : %s, rcx : %s, rdx : %s, rsi : %s, rdi : %s]" % (self.regs['RAX'], self.regs['RBX'], self.regs['RCX'], self.regs['RDX'], self.regs['RSI'], self.regs['RDI'])  


class BapExpr(object):
	'''
	Reg values of each instruction is determined by
	previous instruction reg values.
	'''
	def resolveInsn(self, bapDef, prevDefRegs=GenPurpRegs()):
		#In-progress
		l_reg = bapDef.lhs.name
		r_effect = bapDef.rhs
		if (hasattr(bapDef.rhs,'expr')):
			r_effect = bapDef.rhs.expr
			
		elif (hasattr(bapDef.rhs,'idx')):
			r_effect = bapDef.rhs.idx
		
		if (l_reg in prevDefRegs.regs):
			# mylogger.info("Insn:%s rhs_effect: %s" % (bapDef.attrs['insn'], r_effect))
			# mylogger.info("Old %s value:%s" % (l_reg, prevDefRegs.regs[l_reg]))	
			prevDefRegs.regs[l_reg] = self.evalExpr_rec(r_effect, prevDefRegs, False)
			# mylogger.info("New %s value:%s" % (l_reg, prevDefRegs.regs[l_reg]))
		elif(l_reg.startswith('#')):
			# mylogger.info("Insn:%s rhs_effect: %s" % (bapDef.attrs['insn'], r_effect))
			# mylogger.info("Old %s value:%s" % (l_reg, prevDefRegs.regs[l_reg]))	
			prevDefRegs.temps[l_reg] = self.evalExpr_rec(r_effect, prevDefRegs, False)
			# mylogger.info("New %s value:%s" % (l_reg, prevDefRegs.temps[l_reg]))			

	
		return prevDefRegs

	'''
	Evaluate bap expression

	VSA from sigBIN
	---------------

{'regs': {'RCX': 'Any', 'RSI': 'RBP -50096', 'RBX': 'Any', 'RDX': 'RBP -49748', 'RDI': 'RBP -49748', 'RAX': 'RBP -50096'}}
	
	From Disassembly
   26830:	48 8b 85 58 3c ff ff 	mov    -0xc3a8(%rbp),%rax
   26837:	48 8d 90 54 01 00 00 	lea    0x154(%rax),%rdx
   2683e:	48 8b 85 50 3c ff ff 	mov    -0xc3b0(%rbp),%rax
   26845:	48 89 c6             	mov    %rax,%rsi
   26848:	48 89 d7             	mov    %rdx,%rdi
   2684b:	e8 20 19 fe ff       	callq  8170 <strcat@plt>


FUNCTION:> ---------[add_line_buffer]---------
ses 8 -0xc3a8
line 8 -0xc3b0


from assembly RDX = -0xc3a8(%rbp) + 0x154
				  RDI	  = -50088 + 340 = -49748
				  RSI = -50096

SIgbin output is correct

But dwarf of add_line_buffer
ses = -50104   -> ses->more_output = -50104 + 340 = -49764 ; RDI
line = -50112	; RSI

-----add_line_buffer-----
('more_output', '-0xc3c4', 4)
('line', '-0xc3c0', 8) = 50112
('ses', '-0xc3b8', 8) = 50104

('sav_row', '-0xc3ac', 4)
('sav_col', '-0xc3a8', 4)
('cur_row', '-0xc3a4', 4)
('cur_col', '-0xc3a0', 4)
('top_row', '-0xc39c', 4)
('bot_row', '-0xc398', 4)
('lines', '-0xc394', 4)
('pti', '-0xc390', 8)
('pto', '-0xc388', 8)
('linebuf', '-0xc380', 50000)

DW_CFA_offset: r6 (rbp) at cfa-16 ==> CFA = RBP + 16

In source

void add_line_buffer(
	struct session *ses, 
	char *line, 
	int more_output)
{
	char linebuf[STRING_SIZE];
	char *pti, *pto;
	int lines;
	int sav_row, sav_col, cur_row, cur_col, top_row, bot_row;
....
strcat(ses->more_output, line);
#char * strcat ( char * destination, const char * source ); RDI,RSI

#define LIST_MAX                        20
#define STRING_SIZE                  50000

struct session
{
	struct session        * next;				8
	struct session        * prev;				8
	struct map_data       * map;				8
	z_stream              * mccp;
	char                 ** buffer;
	char                  * name;
	char                  * class;
	FILE                  * logfile;
	FILE                  * logline;
	struct listroot       * list[LIST_MAX];
	struct listroot       * history;
	int                     rows;
	int                     cols;
	int                     top_row;
	int                     bot_row;
	int                     cur_row;
	int                     sav_row;
	int                     cur_col;
	int                     sav_col;
	int                     scroll_max;
	int                     scroll_row;
	int                     scroll_line;
	int                     scroll_base;
	int                     fgc;
	int                     bgc;
	int                     vtc;
	int                     socket;
	int                     telopts;
	int                     flags;
	char                  * host;
	char                  * port;
	long long               connect_retry;
	int                     connect_error;			19x8 = 152 13x8 = 104
	char                    more_output[STRING_SIZE];
	char                    color[100];
	long long               check_output;
};



from DWARF

< 1><0x0000176b>    DW_TAG_subprogram
                      DW_AT_external              yes(1)
                      DW_AT_name                  add_line_buffer
                      DW_AT_decl_file             0x00000001 /home/shamila/projects/tt/src/buffer.c
                      DW_AT_decl_line             0x00000052
                      DW_AT_prototyped            yes(1)
                      DW_AT_low_pc                0x0002673b
                      DW_AT_high_pc               <offset-from-lowpc>1396
                      DW_AT_frame_base            len 0x0001: 9c: DW_OP_call_frame_cfa
                      DW_AT_GNU_all_tail_call_sites yes(1)
                      DW_AT_sibling               <0x00001859>
< 2><0x00001788>      DW_TAG_formal_parameter
                        DW_AT_name                  ses
                        DW_AT_decl_file             0x00000001 /home/shamila/projects/tt/src/buffer.c
                        DW_AT_decl_line             0x00000052
                        DW_AT_type                  <0x000008f3>
                        DW_AT_location              len 0x0004: 91c8f87c: DW_OP_fbreg -50104
< 2><0x00001798>      DW_TAG_formal_parameter
                        DW_AT_name                  line
                        DW_AT_decl_file             0x00000001 /home/shamila/projects/tt/src/buffer.c
                        DW_AT_decl_line             0x00000052
                        DW_AT_type                  <0x00000093>
                        DW_AT_location              len 0x0004: 91c0f87c: DW_OP_fbreg -50112
< 2><0x000017a8>      DW_TAG_formal_parameter
                        DW_AT_name                  more_output
                        DW_AT_decl_file             0x00000001 /home/shamila/projects/tt/src/buffer.c
                        DW_AT_decl_line             0x00000052
                        DW_AT_type                  <0x00000062>
                        DW_AT_location              len 0x0004: 91bcf87c: DW_OP_fbreg -50116
< 2><0x000017b8>      DW_TAG_variable
                        DW_AT_name                  linebuf
                        DW_AT_decl_file             0x00000001 /home/shamila/projects/tt/src/buffer.c
                        DW_AT_decl_line             0x00000054
                        DW_AT_type                  <0x00000a97>
                        DW_AT_location              len 0x0004: 9180f97c: DW_OP_fbreg -50048        
	


	Therefore session->more_output is found at memory location (RBP -50104) + 340
	'''

	'''
	[movq -0x8(%rbp), %rdx] Var("RDX", Imm(0x40)) := Load(Var("mem", Mem(0x40, 0x8)), PLUS(Var("RBP", Imm(0x40)), Int("18446744073709551608", 0x40)), LittleEndian(), 0x40)
		==> RDX = RBP + two's complement(18446744073709551608) = RBP - 0x8
	[movq %rax, %rdi] Var("RDI", Imm(0x40)) := Var("RAX", Imm(0x40))
		==> RDI = RAX
	[movl $0x90, %edi] Var("RDI", Imm(0x40)) := Int(0x90, 0x40)
		==> RDI = 0x90
	[leaq -0x20(%rbp), %rcx] Var("RCX", Imm(0x40)) := LOW(0x40, PLUS(Var("RBP", Imm(0x40)), Int("18446744073709551584", 0x40)))
		==> RCX = RBP - 0x20		
	'''	

	def evalExpr_rec(self, effect, prevDefRegs, isBinOp=False):
		if(hasattr(effect,'constr') and (effect.constr == 'Var')):
			if (effect.name in prevDefRegs.regs):
				return prevDefRegs.regs[effect.name]
			elif(effect.name in prevDefRegs.temps):
				return prevDefRegs.temps[effect.name]
			else:	return effect.name
		if(hasattr(effect,'constr') and (effect.constr == 'Int')):
			if(isBinOp):	return str(twos_comp(effect.value, 64)).rstrip('L')
			else:	return hex(effect.value)
		if(hasattr(effect,'constr') and ((effect.constr == 'Load') or (effect.constr == 'UNSIGNED') or (effect.constr == 'SIGNED') or 
			(effect.constr == 'LOW') or (effect.constr == 'HIGH'))):
			return self.evalExpr_rec(effect.arg[1], prevDefRegs)
		if(hasattr(effect,'constr') and (effect.constr == 'PLUS')):
			res = "%s + %s" % (self.evalExpr_rec(effect.arg[0], prevDefRegs, True), self.evalExpr_rec(effect.arg[1], prevDefRegs, True))
			return evalValue(res)
		if(hasattr(effect,'constr') and (effect.constr == 'MINUS')):
			res = "%s - %s" % (self.evalExpr_rec(effect.arg[0], prevDefRegs, True), self.evalExpr_rec(effect.arg[1], prevDefRegs, True))
			return evalValue(res)
		# return "UnKnown"	
		return "any"

	def evalExpr(self, effect, prevDefRegs=None):
		#TODO: This is a very inefficient method. Proper expression evaluator must be implemented.
		# print(effect)
		tmp_reg = None
		tmp_value = None
		newEffect = 'UnKnown'
		# nEffect = RegVal()
		# mylogger.info("Effect's RHS: %s" % effect)
		if(hasattr(effect,'constr') and (effect.constr == 'PLUS' or effect.constr == 'MINUS')):
			#rhs_effect = MINUS(Var("RSI", Imm(0x40)), Var("RDI", Imm(0x40)))
			#rhs_effect = PLUS(Var("RBP", Imm(0x40)), Int("18446744073709551544", 0x40))
			
			#TODO: define the output effect object
			# if(hasattr(effect.lhs,'expr')):
			# 	l_reg = effect.lhs.expr.name
			# else:
			# 	l_reg = effect.lhs.name
			operator = 'UnKnown'
			if( effect.constr == 'PLUS'):
				operator = '+'
			if(effect.constr == 'MINUS'):
				operator = '-'
			# mylogger.info(" %s %s %s" % (effect.lhs, operator, effect.rhs))
			tmp_reg = effect.lhs
			tmp_value = effect.rhs
			if( hasattr(effect.lhs,'name')):
				tmp_reg = effect.lhs.name
			if( effect.rhs.constr == 'Int'):
				tmp_value = str(twos_comp(effect.rhs.value,64)).rstrip('L')
			if (tmp_reg in prevDefRegs.regs):
				tmp_reg = prevDefRegs.regs[tmp_reg]
			newEffect = "%s %s %s" % (tmp_reg,operator,tmp_value)
			t_reg = newEffect.split()[0]
			offset = 0
			for m in re.finditer('\S+', newEffect):
				offset = offset + getIntVal(m.group(0))		
			newEffect = "%s %s" % (t_reg, offset)	
			mylogger.info("Arithmatic effect %s" % newEffect)
		if(hasattr(effect,'constr') and (effect.constr == 'Var')):
			#rhs_effect = Var("RDX", Imm(0x40))
			newEffect = "%s" % effect.name
			mylogger.info("Var %s" % newEffect)
			if (effect.name in prevDefRegs.regs):
				newEffect = prevDefRegs.regs[effect.name]
			mylogger.info("VAR changed to %s" % newEffect)
		if(hasattr(effect,'constr') and (effect.constr == 'Load')):
			#rhs_effect = Load(Var("mem", Mem(0x40, 0x8)), Int(0x202114, 0x40), LittleEndian(), 0x20) 
			#rhs_effect = Load(Var("mem", Mem(0x40, 0x8)), PLUS(Var("RBP", Imm(0x40)), Int("18446744073709551596", 0x40)), LittleEndian(), 0x20)
			if(hasattr(effect,'idx') and (effect.idx.constr == 'Int')):
				newEffect = hex(effect.idx.value)
			else:
				newEffect = effect
			mylogger.info("Load effect %s" % newEffect)
		return newEffect

	'''
	Each Block has its final reg values saved.
	THe previous blks reg values are passed as an argument
	and based on that, reg values of current blk should be
	determined. 
	'''
	def resolveBlk(self, curBlkRegs, prevBlkRegs=None):
		genPurpReg = GenPurpRegs()

		return genPurpReg.regs

'''
compute the 2's complement of int value val
works for both integers and hex

e.g.: 	:> hex_string = hex(18446744073709501528).rstrip('L')
		:> hex(twos_comp(int(hex_string,16), 64))
		:> ==> '-0xc3a8L'

		:> hex_string = hex(0x154)
		:> hex(twos_comp(int(hex_string,16), 64))
		:> ==> '0x154'			

'''
def twos_comp(val, bits):

	if (val & (1 << (bits - 1))) != 0: # if sign bit is set e.g., 8bit: 128-255
		val = val - (1 << bits)        # compute negative value
	return val


def getIntVal(st):
	try:
		s = int(st)
		return s
	except:
		return 0

def evalValue(st):
	operator = None
	value = 0
	regs = None 
	for elem in st.split(' '):
		if (elem == '+' or elem == '-'):
			operator = elem
		elif (elem == 'any'):
			return 'any'
		else:
			try:
				value = eval("%s %s %s" % (value, operator, int(elem)))
			except:
				if(regs is None):
					regs = elem
				else:
					regs = "%s + %s" % (regs, elem)
	return "%s + %s" % (regs, value)	
