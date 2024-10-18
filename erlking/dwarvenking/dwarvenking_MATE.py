# -------------------------------------------------------------------------------
# elftools example: dwarvenking.py
# Dependency: pip install pyelftools
# Input : DWARF Compile UNit
# Output : List of UnrolledVarInfo
# usage:        dk = DWARFKing(<ELF_file>)
#               unrolledInfo = dk.processDWARF()
# scw130030@utdallas.edu
# -------------------------------------------------------------------------------

from struct import *
import sys
import re

from elftools.common.py3compat import bytes2str
from elftools.dwarf.dwarf_expr import DW_OP_opcode2name
from typing import List
from tob_chess_utils.dwarf import UnrolledFieldName, UnrolledField, FieldOffset, UnrolledTypeInfo
from .logging import make_logger

logger = make_logger(__name__)

def hex_sub(from_val, init_val):
    return hex(from_val - init_val)


def hex_addition(from_val, init_val):
    return hex(from_val + init_val)


def sortByLocation(unrolledList):
    sortedList = unrolledList[:]
    sortedList.sort(key=lambda c: c.cfa_offset, reverse=True)
    return sortedList


def decode_seq(seq, length):
    """ This function takes integer array and the length of operands
		first element is the opcode and number of elements specified by the length is decoded
		Usage:
		arr = [145, 180, 127]
		print(decode_seq(arr,len(arr)))
	"""
    op = seq[0]
    opname = DW_OP_opcode2name[op]
    revlist = seq[1:length][::-1]
    code = ""
    for item in revlist:
        code = code + (hex(item)).lstrip("0x")
    # Returning decoded opcode and the parameters
    pattern = re.compile("DW_OP_.*breg.*")

    if pattern.match(opname):
        return opname, hex(decode_leb128(code))
    else:
        return opname, hex(int(code, 16))


def decode_leb128(byte_str):
    value = bin(0)[2:].zfill(7)
    byte_stream = bytearray.fromhex(byte_str)
    for b in byte_stream:
        b_bin = bin(b)[2:].zfill(8)
        mask = bin(int("0x7f", 16))[2:].zfill(8)
        value = bin((int(value, 2) << 7) | (int(b_bin, 2) & int(mask, 2)))
    newValue = int(value, 2) - 0b1
    new_b_bin = bin(newValue)[2:]
    newValue = newValue ^ int(len(new_b_bin) * "1", 2)
    return -newValue


class DIErecord:
    def __init__(self, die):
        self.die = die
        self.refType = None
        self.size = None
        self.type = None
        self.length = None


class StructRecord(object):
    def __init__(self):
        self.members = []
        self.die = None
        self.visited = 0


class DWARVENking(object):
    # Constructor
    def __init__(self, elfFile):
        self._dieGraph = {}
        self._structList = {}
        self._unrolledTypeDic = {}
        self._topCUoffset = None
        self._processDWARF(elfFile)

    #Return DataStructure
    def getUnrolledTypeInfo(self):
    	return self._unrolledTypeDic

    def _processDWARF(self, elfFile):
        """
			for each compilation unit dwarf are processed
		"""
        if not elfFile.has_dwarf_info():
            raise Exception("{} file has no DWARF information".format(elfFile))
        dwarfinfo = elfFile.get_dwarf_info()

        for CU in dwarfinfo.iter_CUs():
            top_DIE = CU.get_top_DIE()
            self._topCUoffset = CU.cu_offset
            self._resetLocals()
            self._processCompileUnit(top_DIE)

    def _resetLocals(self):
        self._dieGraph = {}
        self._structList = {}

    # Variable information are recorded for each compile unit
    def _processCompileUnit(self, top_DIE):
        """
        Transform the flat tree into a graph like list representation
        To assist recursively traverse through graph and update variable info
        NO NEED TO TRAVERSE BEYOND A POINTER
        """
        logger.vprint(f"DWARVENking:  Processing {top_DIE.get_full_path()} file")

        self._record_die_rec(top_DIE)

        self._update_die_graph()

        self._record_structs_rec(top_DIE)

        self._read_vars_rec(top_DIE)

    def _read_vars_rec(self, cur_die):
        """
        Recursively reading variables in each function which doesn't have an abstract origin
        """
        if cur_die.tag == "DW_TAG_subprogram" and (
            "DW_AT_abstract_origin" not in cur_die.attributes
        ):
            #Function name can be mangled or found in specialized DIE
            if "DW_AT_linkage_name" in cur_die.attributes:
                funcName = bytes2str(cur_die.attributes["DW_AT_linkage_name"].value)
            elif "DW_AT_name" in cur_die.attributes:
                funcName = bytes2str(cur_die.attributes["DW_AT_name"].value)
            else:
                funcSpecialization = hex(cur_die.attributes["DW_AT_specification"].value)
                funcName = bytes2str(
                    self._dieGraph[funcSpecialization].die.attributes["DW_AT_name"].value
                )
            logger.vprint(f"DWARVENking: <Function: {funcName}>")
            self._unrolledTypeDic[funcName] = []    #Initializing a variable list 
            for child in cur_die.iter_children():
                #Consider variable which is not external and hve a location
                if child.tag == "DW_TAG_variable" and ("DW_AT_external" not in child.attributes):
                    if ("DW_AT_location" in child.attributes) and (
                        child.attributes["DW_AT_location"].form == "DW_FORM_exprloc"
                    ):
                        relOffset = hex_sub(
                            child.offset, self._topCUoffset
                        )  # Get the offset of die relative to top_die (CU)
                        dieRecord = self._dieGraph[relOffset]
                        locationArr = child.attributes["DW_AT_location"].value
                        location = decode_seq(locationArr, len(locationArr))
                        if location[0] == "DW_OP_fbreg":  # We eveluate DW_OP_fbreg addresses only
                            varName = bytes2str(child.attributes["DW_AT_name"].value)
                            varSize = dieRecord.size
                            cfaOffset = location[1]
                            field_offsets = []
                            if dieRecord.refType in self._structList:
                                structRecord = self._structList[dieRecord.refType]
                                logger.vprint(
                                    f"DWARVENking: <Struct{varName} found at {relOffset} with size {varSize}"
                                )

                                field_offsets = self._read_structs_rec(structRecord, cfaOffset, varName,[])
                            else:                                
                                logger.vprint(
                                    f"<DWARVENking: Variable {varName} found at {relOffset} with size {varSize}"
                                )
                                None

                            self._unrolledTypeDic[funcName].append(UnrolledTypeInfo(varName,varSize,field_offsets))
                        else:
                            None  # DW_OP_addr is an constant address.
        else:
            for child in cur_die.iter_children():
                self._read_vars_rec(child)

    def _read_structs_rec(self, structRecord, cfaOffset, parentName, fieldOffsetList=[]):
        """
        Recursively read struct elements and return a list of unrolled struct members
        """
        for member in structRecord.members:

            relOffset = hex_sub(member.offset, self._topCUoffset)
            memberRecord = self._dieGraph[relOffset]
            memberSize = memberRecord.size
            refType = memberRecord.refType
            memberLoc = member.attributes["DW_AT_data_member_location"].value
            memberOffset = hex_addition(memberLoc, int(cfaOffset, 16))
            memberName = parentName + "." + bytes2str(member.attributes["DW_AT_name"].value)

            unrolledFieldName = UnrolledFieldName(parentName,bytes2str(member.attributes["DW_AT_name"].value))

            unrolledField = UnrolledField(unrolledFieldName,memberSize)

            fieldOffset = FieldOffset(memberOffset,unrolledField)

            fieldOffsetList.append(fieldOffset)
            if refType in self._structList and (self._structList[refType].visited == 0):
                memStructRecord = self._structList[refType]
                self._structList[refType].visited = 1
                logger.vprint(f"DWARVENking: <Struct{memberName}> found at {memberOffset} with size {memberSize}")
                self._read_structs_rec(memStructRecord, memberOffset, memberName, fieldOffsetList)
            else:
                logger.vprint(f"DWARVENking: <Not a Struct{memberName}> at {memberOffset} with size {memberSize}")
                None
            self._reset_structList()
        return fieldOffsetList

    def _reset_structList(self):
        """
			Reset visited flag from all records
		"""
        for struct in self._structList:
            self._structList[struct].visited = 0

    def _record_die_rec(self, cur_die):
        """
			Recording all DIE units with ref type and sizes if available
		"""
        offsetHX = hex_sub(
            cur_die.offset, self._topCUoffset
        )  # Get the offset of die relative to top_die (CU)
        die_record = DIErecord(cur_die)

        if "DW_AT_byte_size" in cur_die.attributes:
            die_record.size = cur_die.attributes["DW_AT_byte_size"].value  # decimal
        if cur_die.tag == "DW_TAG_pointer_type" or cur_die.tag == "DW_TAG_subprogram":
            die_record.refType = None
        elif "DW_AT_type" in cur_die.attributes:
            die_record.refType = hex(
                cur_die.attributes["DW_AT_type"].value
            )  # unlike offset attribute type is relative
        if cur_die.tag == "DW_TAG_array_type":
            die_record.type = "array"
            for child in cur_die.iter_children():
                if child.tag == "DW_TAG_subrange_type" and "DW_AT_upper_bound" in child.attributes:
                    die_record.length = child.attributes["DW_AT_upper_bound"].value + 1
                elif child.tag == "DW_TAG_subrange_type" and "DW_AT_count" in child.attributes:
                    die_record.length = child.attributes["DW_TAG_subrange_type"].value
        if cur_die.tag == "DW_TAG_pointer_type":
            die_record.type = "pointer"
        
        self._dieGraph[offsetHX] = die_record

        for die in cur_die.iter_children():
            self._record_die_rec(die)

    def _update_die_graph(self):
        """
			Bottom-up approach to update die graph
			TODO: to reduce running time use a flag to mark visited record and check before iterate
		"""
        for item in self._dieGraph:
            if self._dieGraph[item].refType is not None:
                record = self._update_die_rec(self._dieGraph[item].refType)
                if record is not None:
                    self._dieGraph[item].type = record[2]
                    self._dieGraph[item].size = record[1]
                    self._dieGraph[item].refType = record[0]

    def _record_structs_rec(self, die):
        """
			 Recording all structs
		"""
        relOffset = hex_sub(die.offset, self._topCUoffset)  # Getting the relative offset
        newStructRecord = StructRecord()
        if die.tag == "DW_TAG_structure_type":
            newStructRecord.die = die
            for child in die.iter_children():
                if child.tag == "DW_TAG_member":
                    newStructRecord.members.append(child)
            self._structList[relOffset] = newStructRecord
        else:
            for child in die.iter_children():
                self._record_structs_rec(child)

    def _update_die_rec(self, ref):
        # Base case is refType is None
        if self._dieGraph[ref].refType is None:
            if "DW_AT_name" in self._dieGraph[ref].die.attributes:
                name = bytes2str(self._dieGraph[ref].die.attributes["DW_AT_name"].value)
                return ref, self._dieGraph[ref].size, name
            else:
                return ref, self._dieGraph[ref].size, None
        else:
            record = self._update_die_rec(self._dieGraph[ref].refType)
            if self._dieGraph[ref].die.tag != "DW_TAG_array_type":
                self._dieGraph[ref].type = record[2]
                self._dieGraph[ref].refType = record[0]
                self._dieGraph[ref].size = record[1]
                retREF = record[0]
            else:
                self._dieGraph[ref].type = "array"
                retREF = ref
                self._dieGraph[ref].size = record[1] * int(self._dieGraph[ref].length or 1)

            return retREF, self._dieGraph[ref].size, self._dieGraph[ref].type
