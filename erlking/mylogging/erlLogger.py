# erlLogger.py
import os
import logging
from mylogging.myFilter import MyFilter 

# Create a custom logger
# logger = logging.getLogger(__name__)

TRACE_LEVEL_NUM = 25 
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")
def trace(self, message, *args, **kws):
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        # Yes, logger takes its '*args' as 'args'.
        self._log(TRACE_LEVEL_NUM, message, args, **kws) 
logging.Logger.trace = trace

STATUS_LEVEL_NUM = 100
logging.addLevelName(STATUS_LEVEL_NUM, "STATUS")
def status(self, message, *args, **kws):
	if self.isEnabledFor(STATUS_LEVEL_NUM):
		# Yes, logger takes its '*args' as 'args'.
		self._log(STATUS_LEVEL_NUM, message, args, **kws)
logging.Logger.status = status
logging.STATUS = STATUS_LEVEL_NUM

POI_LEVEL_NUM = 120
logging.addLevelName(POI_LEVEL_NUM, "POI")
def poi(self, message, *args, **kws):
	if self.isEnabledFor(POI_LEVEL_NUM):
		# Yes, logger takes its '*args' as 'args'.
		self._log(POI_LEVEL_NUM, message, args, **kws)
logging.Logger.poi = poi
logging.POI = POI_LEVEL_NUM

mylogger = logging.getLogger('ek')
mylogger.setLevel(logging.DEBUG)

# Create handlers
cmdHandler = logging.StreamHandler()
pathHome = os.getenv("HOME")
pathLogFile = os.path.join(pathHome, "logs/erlking.log")
pathPidFile = os.path.join(pathHome, "logs/erlking.pid")
pathPOIFile = os.path.join(pathHome, "logs/poi.csv")

fileHandler = logging.FileHandler(pathLogFile)
pidHandler = logging.FileHandler(pathPidFile, mode='w')
poiHandler = logging.FileHandler(pathPOIFile, mode='w')
# fileHandler = logging.FileHandler('/home/utd/tmp/erlking.log')
# cmdHandler.setLevel(logging.DEBUG)
cmdHandler.addFilter(MyFilter(logging.INFO))
fileHandler.setLevel(logging.INFO)
pidHandler.setLevel(logging.STATUS)
poiHandler.setLevel(logging.POI)

# Create formatters and add it to handlers
# cmdFormat = logging.Formatter('[%(name)s] - (%(levelname)s) : %(message)s')
pidFormat = logging.Formatter('[%(process)d : %(processName)s] %(message)s')
cmdFormat = logging.Formatter('%(message)s')
poiFormat = logging.Formatter('%(message)s')
fileFormat = logging.Formatter('%(asctime)s : [%(process)d - %(name)s] - (%(levelname)s) : %(message)s')

cmdHandler.setFormatter(cmdFormat)
fileHandler.setFormatter(fileFormat)
pidHandler.setFormatter(pidFormat)
poiHandler.setFormatter(poiFormat)

# Add handlers to the logger
mylogger.addHandler(cmdHandler)
mylogger.addHandler(fileHandler)
mylogger.addHandler(pidHandler)
mylogger.addHandler(poiHandler)
