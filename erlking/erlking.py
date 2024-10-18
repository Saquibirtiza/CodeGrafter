import os
import subprocess
from joern.all import JoernSteps
from sigbin.sigbin import sigBIN
from dwarvenking.dwarvenking import DWARVENking
from checker.checker import Checker
from castle.castle import Castle
from graphUtils.drawer import drawer
from termcolor import colored

from mylogging.erlLogger import mylogger
import datetime
import pickle
import multiprocessing
import gc
# from memory_profiler import profile

from py2neo.packages.httpstream import http
# http.socket_timeout = 9999
http.socket_timeout = 1000 * 60 * 2

targets = []
erlk_home = "/home/utd"
# erlk_home = "/home/utd/proj/erlking"
tmp_home = os.getenv('HOME')
home = "/home/utd/erlking_v2"
target_home = os.path.join(erlk_home,'targets')
sw_home = os.path.join(erlk_home,'sw')


class ERLking(object):
	def __init__(self):
		self._poiList = []	#List of POI messages
		self._intro()
		self._start_menu_rec()

	def getPOIList(self):
		return self._poiList

	def _start_menu_rec(self):
		self._menu_selectTarget()
		try:
			self._process()
		except Exception:
			mylogger.debug(colored("Something went wrong. Please look at erlking.log for more details",'red'))
			mylogger.error(colored("Fatal: Erlking stopped",'red'), exc_info=True)
			mem_usage = subprocess.check_output(['bash','-c', 'free -m'])
			mylogger.trace(colored("Memory Usage:\n %s" % mem_usage,'cyan'))
			self._start_menu_rec()
	# def main():
	# 	analyzeFunc('ex1','runServer')

	def analyzeFunc(targetBin, funcName):
		mylogger.info("Shutting down neo4j instance")
		os.system('pkill neo4j; pkill java')

		target_path = os.path.abspath("%s/%s" % (target_home, targetBin))
		db_path = os.path.abspath("%s/%s/db" % (target_home, targetBin))
		os.system('bash %s/scripts/config.sh set "%s/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.database.location" "%s"' % (erlk_home, sw_home, db_path))
		mylogger.info("Starting neo4j DB")
		os.system('%s/neo4j-community-2.1.5/bin/neo4j console >/dev/null 2>&1 & sleep 20' % sw_home)

		mylogger.info("Creating DB Connection")
		db_conn = self._getDBConnection()

		if(os.path.isfile(os.path.join(target_path,'DK.pkl'))):
			dk_read = open('%s/DK.pkl' % target_path,'rb')
			varLayout = pickle.load(dk_read)
			dk_read.close()	
			Checker(db_conn, None, varLayout, funcName)
		else:
			mylogger.info("No DK.pkl found")



	def _process(self):

		target = int(input("\nPlease select target number from the menu to analyze : "))
		if (target == 0):
			mylogger.status("STOPPED : ek")
			# for poi in self._poiList:
			# 	mylogger.trace(poi)
			None
		elif (target not in range(1,len(targets))):
			mylogger.debug("Invalid Selection")
		else:
			mylogger.trace("Target %s selected" % targets[target])
			mylogger.info("Shutting down neo4j instance")
			mylogger.status("RESTARTING : neo4j")
			os.system('pkill neo4j; pkill java')

			os.system('rm -rf %s/neo4j-community-2.1.5/data/*' % (sw_home))

			target_path = os.path.abspath("%s/%s" % (target_home, targets[target]))
			src_path = os.path.abspath("%s/%s/src" % (target_home, targets[target]))
			bin_path = os.path.abspath("%s/%s/bin" % (target_home, targets[target]))
			db_path = os.path.abspath("%s/%s/db" % (target_home, targets[target]))

			os.system('bash %s/scripts/config.sh set "%s/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.database.location" "%s"' % (erlk_home, sw_home, db_path))

			option_db = 1	#Set default option to be to 2

			if len(os.listdir(db_path)) != 0:
				self._menu_createDB(target_path)
				option_db = int(input("\nPlease select a number : "))

			if( option_db == 1):
				mylogger.trace("Removing Old DB")
				os.system('rm -rf %s/.joernIndex' % (src_path))
				mylogger.info("Running Joern")
				os.system('cd %s; java -jar %s/joern/joern-0.3.1/bin/joern.jar .' % (src_path, sw_home))
				os.system('rm -rf %s/db/* && cp -R %s/.joernIndex/* %s/db/' % (target_path,src_path,target_path))
			elif( option_db == 2):
				mylogger.info("Using existing Src DB")
				os.system('rm -rf %s/db/* && cp -R %s/.joernIndex/* %s/db/' % (target_path,src_path,target_path))
			elif( option_db == 0):
				self._start_menu_rec()
			else:
				None
			if( option_db != 0):
				mylogger.info("Starting neo4j DB")
				os.system('%s/neo4j-community-2.1.5/bin/neo4j console >/dev/null 2>&1 & sleep 20' % sw_home)
				# subprocess.run(["ls","foo bar"], check=True)
				mylogger.status("STARTED : neo4j")
				mylogger.info("Getting DB Connection")
				db_conn = self._getDBConnection()

				if( option_db == 1 or option_db == 2):
					(binPath, _, binFile) = next(os.walk(bin_path))
					target_bin = os.path.join(binPath,binFile[0])	#If more than one file is present all must be processed
					
					manager = multiprocessing.Manager()
					parallelOutDict = manager.dict()

					# worker(module, parallelOutDict, target_bin, db_conn=None, target_path):
					p2 = multiprocessing.Process(target=worker, args=('sb', parallelOutDict, target_bin, db_conn, target_path))
					p2.start()
					p1 = multiprocessing.Process(target=worker, args=('dk', parallelOutDict, target_bin, None, target_path))
					p1.start()

					p2.join()			
					p1.join()

					sb_data = parallelOutDict['sb']
					sbProg = sb_data[0]
					sbCFG = sb_data[1]
					sbCG = sb_data[2]
					demangledFuncInfoList = sb_data[3]
					sbBAPSubList = sb_data[4]

					dk_data = parallelOutDict['dk']
					varLayout = dk_data[0]
					retList = dk_data[1]


				elif(option_db == 3):
					if(os.path.isfile(os.path.join(target_path,'DK.pkl')) and os.path.isfile(os.path.join(target_path,'SB.pkl'))):
						dk_read = open('%s/DK.pkl' % target_path,'rb')
						dk_data = pickle.load(dk_read)
						varLayout, retList = dk_data
						dk_read.close()

						sb_read = open('%s/SB.pkl' % target_path,'rb')
						sb_data = pickle.load(sb_read)
						sbProg, sbCFG, sbCG, demangledFuncInfoList, sbBAPSubList = sb_data
						sb_read.close()

					else:
						None
				else:
					None
					# sb_read = open('%s/SB.pkl' % target_path,'rb')
					# sb_data = pickle.load(sb_read)
					# sbProg, sbCFG, sbCG = sb_data
					# sb_read.close()

				# mylogger.trace(retList)
				# mylogger.info("---Calling Castle---")
				self.runCastle(db_conn, retList, demangledFuncInfoList, sbCG, varLayout)
				# for funcInfo in demangledFuncInfoList:
				# 	mylogger.info(funcInfo)
				# mylogger.trace(retList)
				if(option_db != 0 and varLayout is not None):
					self.runChecker(sbProg, db_conn, sb_data, varLayout, targets[target], retList, demangledFuncInfoList)

	def runCastle(self, db_conn, retList, demangledFuncInfoList, sbCG, varLayout):
		cs = Castle(db_conn, retList, demangledFuncInfoList, sbCG, varLayout)
		updatedRetList = cs.getRetList()

	def runChecker(self, sbProg, db_conn, sb_data, varLayout, target, retList, demangledFuncInfoList):
		ch = Checker(sbProg, db_conn, sb_data, varLayout, retList, demangledFuncInfoList)
		self._menu_analysis()
		option_analysis = int(input("\nPlease select a number : "))
		if (option_analysis == 1):
			mylogger.status("RUNNING : insec_call")
			self._poiList.append(ch.insecure_call())
			mylogger.info("Stopping insecure call analysis for %s\n" % target)
			mylogger.status("COMPLETED : insec_call")
			# mylogger.trace(self._poiList)
			self.runChecker(sbProg, db_conn, sb_data, varLayout, target, retList, demangledFuncInfoList)
		elif (option_analysis == 2):
			mylogger.status("RUNNING : check_boil")
			self._poiList.append(ch.checkBOILs())
			mylogger.info("Stopping check BOIL analysis for %s\n" % target)
			mylogger.status("COMPLETED : check_boil")
			# mylogger.trace(self._poiList)
			self.runChecker(sbProg, db_conn, sb_data, varLayout, target, retList, demangledFuncInfoList)
		elif (option_analysis == 3):
			mylogger.status("RUNNING : insec_paths")
			self._poiList.append(ch.insecure_paths())
			mylogger.info("Stopping insecure path analysis for %s\n" % target)
			mylogger.status("COMPLETED : insec_paths")
			# mylogger.trace(self._poiList)
			self.runChecker(sbProg, db_conn, sb_data, varLayout, target, retList, demangledFuncInfoList)
		elif (option_analysis == 4):
			plot = drawer(db_conn, sb_data[4], sb_data[2])
			fName = str(input("\nFunction name : "))
			plot.addSrcCFG(fName)
			plot.addSrcAST(fName)
			plot.addBinCFG(fName)
			plot.addSrcBinEdge(fName)
			plot.addSrcDDG(fName)
			# plot.compareSrcBinCFG()
			plot.draw(fName)
			# plot.drawCG()
			# mylogger.info("Stopping plot of %s for %s\n" % (fName, target))
			self.runChecker(sbProg, db_conn, sb_data, varLayout, target, retList, demangledFuncInfoList)
		elif (option_analysis == 5):
			mylogger.status("RUNNING : check_for")
			self._poiList.append(ch.checkForConditions())
			mylogger.info("Stopping FOR condition analysis for %s\n" % target)
			mylogger.status("COMPLETED : check_for")
			# mylogger.trace(self._poiList)
			self.runChecker(sbProg, db_conn, sb_data, varLayout, target, retList, demangledFuncInfoList)
		elif (option_analysis == 6):
			mylogger.status("RUNNING : check_ptrs")
			self._poiList.append(ch.pointerCheck())
			mylogger.info("Stopping pointer check analysis for %s\n" % target)
			mylogger.status("COMPLETED : check_ptrs")
			# mylogger.trace(self._poiList)
			self.runChecker(sbProg, db_conn, sb_data, varLayout, target, retList, demangledFuncInfoList)
		elif (option_analysis == 7):
			mylogger.status("Printing function List")
			ch.printFuncList(target)
			mylogger.info("Stopping printing function for %s\n" % target)
			mylogger.status("COMPLETED : print_funcs")
			self.runChecker(sbProg, db_conn, sb_data, varLayout, target, retList, demangledFuncInfoList)
		elif (option_analysis == 8):
			mylogger.status("RUNNING : effected_sinks")
			self._poiList.append(ch.effected_sinks())
			mylogger.info("Stopping effected sink analysis for %s\n" % target)
			mylogger.status("COMPLETED : effected_sinks")
			# mylogger.trace(self._poiList)
			self.runChecker(sbProg, db_conn, sb_data, varLayout, target, retList, demangledFuncInfoList)	
		else:
			self._start_menu_rec()


	def _intro(self):
		mylogger.debug("<<[[ " + colored('ERL','green') + "ki" + colored("ng",'yellow') + " (UTD) ]]>>")

	def _menu_selectTarget(self):
		index = 0
		targets.append("Exit")
		mylogger.debug("")
		for d in os.listdir('%s/targets' % erlk_home):
		# for p,d,f in os.walk("../targets"):
			index = index+1
			targets.append(d)
			mylogger.debug("%d: %s" % (index,d))	
		mylogger.debug("%d: %s" % (0,"Exit"))

	def _menu_createDB(self, target_path):
		mylogger.debug("")
		mylogger.debug("%d: %s" % (1,"Recreate Full CPG (SRC and BIN)"))
		mylogger.debug("%d: %s" % (2,"Recreate Bin CPG"))
		if(os.path.isfile(os.path.join(target_path,'DK.pkl'))):
			mylogger.debug("%d: %s" % (3,"Use Existing CPG"))
		mylogger.debug("%d: %s" % (0,"Back"))		

	def _menu_analysis(self):
		mylogger.debug("%d: %s (%s)" % (1, "Effected variables", "Variables affected by insecure functions"))
		mylogger.debug("%d: %s (%s)" % (2, "Check BOILs", "Buffer overflow inducible loops"))
		mylogger.debug("%d: %s (%s)" % (3, "Insecure Paths", "From external input sources to sensitive sinks"))
		mylogger.debug("%d: %s (%s)" % (4, "Plot", "Plots specified function"))
		mylogger.debug("%d: %s (%s)" % (5, "Check ForConditions", "UpBound check for For-condition used as indices"))
		mylogger.debug("%d: %s (%s)" % (6, "Pointer Check", "Null dereferences and use after free"))
		mylogger.debug("%d: %s (%s)" % (7, "Print Function List", "Printing function info List"))
		mylogger.debug("%d: %s (%s)" % (8, "Effected Sinks", "Sensitive sinks with threshold height"))
		mylogger.debug("%d: %s" % (0, "Back"))

	def _getDBConnection(self):


		mylogger.info('Connecting to database...')
		j = JoernSteps()
		j.setGraphDbURL('http://localhost:7474/db/data/')
		j.connectToDatabase()
		return j

def worker(module, parallelOutDict, target_bin, db_conn, target_path):
	mylogger.info("Module %s called" % module)
	if module == 'sb':
		mylogger.status("RUNNING : sb")
		tsb1 = datetime.datetime.now()
		sb = sigBIN(target_bin,db_conn)
		demangledFuncInfoList = sb.extractFuncInfo()
		sb.generateCPG(demangledFuncInfoList)
		updatedDemangledFuncInfoList = sb.getUpdatedFuncList()
		sbProg = sb.prog
		sbCFG = sb.getCFG()
		sbBAPSubList = sb.getBAPSubList()
		sbCG = sb.getCG()
		# sbFuncList = sb.getFuncList()
		sb_data = (sbProg, sbCFG, sbCG, updatedDemangledFuncInfoList, sbBAPSubList)
		parallelOutDict[module] = sb_data
		sb_write = open('%s/SB.pkl' % target_path,'wb')
		pickle.dump(sb_data, sb_write)
		sb_write.close()
		tsb2 = datetime.datetime.now()
		mylogger.info("Exec time sigBIN: %s" % (tsb2 - tsb1))
		mylogger.status("COMPLETED : sb")
	if module == 'dk':
		mylogger.status("RUNNING : dk")
		tdk1 = datetime.datetime.now()
		dk = DWARVENking(target_bin)
		varLayout = dk.getUnrolledInfo()
		retList = dk.getRetList()
		dk_data = (varLayout, retList)
		parallelOutDict[module] = dk_data
		dk_write = open('%s/DK.pkl' % target_path,'wb')
		pickle.dump(dk_data, dk_write)
		dk_write.close()
		tdk2 = datetime.datetime.now()
		mylogger.info("Exec time DWARVENking: %s" % (tdk2 - tdk1))
		mylogger.status("COMPLETED : dk")
	gc.collect()

def main():
	ek = ERLking()
	# ek.getPOIList()

if __name__ == '__main__':
	main()
