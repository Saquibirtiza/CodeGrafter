import os,sys,daemon,io
import requests,zipfile
import time
from datetime import datetime
import subprocess
import paho.mqtt.client as mqtt
import jsonschema
import json
import uuid
import sqlite3
import traceback
import yaml
import multiprocessing

import logging

sys.path[0:0] = ['/home/utd/erlking/']
#from mylogging.erlLogger import mylogger

from py2neo.packages.httpstream import http
http.socket_timeout = 9999

import erlking
from sigbin.sigbin import sigBIN
from dwarvenking.dwarvenking import DWARVENking
from checker.checker import Checker
from castle.castle import Castle
from messages.messages import POIRecord
from joern.all import JoernSteps


target_dir = '/home/utd/targets'
jsonschema_dir = '/home/utd/config'

process_terminated_error = '''Analysis process terminated unexpectedly.  Potential out-of-memory error.
'''

def getDBConnection(instance, logger):
    logger.info('Connecting to database instance %d...' % instance)
    j = JoernSteps()
    if instance == 1:
      j.setGraphDbURL('http://localhost:8471/db/data/')
    elif instance == 2:
      j.setGraphDbURL('http://localhost:8472/db/data/')
    elif instance == 3:
      j.setGraphDbURL('http://localhost:8473/db/data/')
    elif instance == 4:
      j.setGraphDbURL('http://localhost:8474/db/data/')
    else:
      j.setGraphDbURL('http://localhost:8475/db/data/')
    j.connectToDatabase()
    return j

class ChessDatabase():
  def __init__(self,logger):
    self.logger = logger
    self.logger.info('Connecting to persistent database...')
    self.cdb = None
    while self.cdb is None:
      try:
        self.cdb = sqlite3.connect('/home/utd/db/chess.db')
      except:
        self.logger.exception('Error connecting to persistent db.')
      if self.cdb is None:
        print('Error connecting to persistent db, retrying...')
        time.sleep(5)
    while not self.createTables():
      time.sleep(5)
  # Create initial tables for persistent chess db
  def createTables(self):
    challenges_table = '''CREATE TABLE IF NOT EXISTS challenges(
                            id text PRIMARY KEY,
                            name text NOT NULL,
                            status text NOT NULL,
                            hints text NOT NULL)'''
    blobs_table = '''CREATE TABLE IF NOT EXISTS blobs(
                            name text PRIMARY KEY,
                            target text NOT NULL,
                            challenge text NOT NULL,
                            FOREIGN KEY(challenge) REFERENCES challenges(id))'''
    pois_table = '''CREATE TABLE IF NOT EXISTS pois(
                      uuid text PRIMARY KEY,
                      challenge text NOT NULL,
                      severity text NOT NULL,
                      type text NOT NULL,
                      file text NOT NULL,
                      line integer NOT NULL,
                      func text NOT NULL,
                      code text NOT NULL,
                      title text NOT NULL,
                      description text NOT NULL,
                      ranking integer NOT NULL,
                      complexity integer NOT NULL,
                      id integer NOT NULL,
                      binary text NOT NULL,
                      details text NOT NULL,
                      offset text NOT NULL,
                      funcAddr text NOT NULL,
                      FOREIGN KEY(challenge) REFERENCES challenges(id))'''
    errors_table = '''CREATE TABLE IF NOT EXISTS errors(
                      challenge text NOT_NULL,
                      error text NOT NULL)'''
    votes_table = '''CREATE TABLE IF NOT EXISTS votes(
                      challenge text NOT NULL,
                      poi text NOT NULL,
                      who text NOT NULL,
                      vote integer NOT NULL,
                      FOREIGN KEY(challenge) REFERENCES challenges(id),
                      PRIMARY KEY (challenge, poi, who))'''
    notes_table = '''CREATE TABLE IF NOT EXISTS notes(
                      challenge text NOT NULL,
                      poi text NOT NULL,
                      who text NOT NULL,
                      note text NOT NULL,
                      FOREIGN KEY(challenge) REFERENCES challenges(id),
                      PRIMARY KEY (challenge, poi, who))'''
    # May also be considered targets, but I think we have
    # more than one definition of "target" in the chess system
    # now (the targets with corresponding blobs, and target
    # bins inside each blob)
    #blobs_table = '''CREATE TABLE IF NOT EXISTS blobs(
    #                        id integer PRIMARY KEY,
    #                        name text NOT NULL'''
    try:
      self.cdb.cursor().execute(challenges_table)
      self.cdb.cursor().execute(blobs_table)
      self.cdb.cursor().execute(pois_table)
      self.cdb.cursor().execute(errors_table)
      self.cdb.cursor().execute(votes_table)
      self.cdb.cursor().execute(notes_table)
    except:
      print("Error initializing persistent db!")
      self.logger.exception('Error initializing persistent db!')
      return False
    return True
    
  def getChallenges(self):
    cur = self.cdb.cursor()
    cur.execute('SELECT * FROM challenges')
  
    rows = cur.fetchall()
    challenges = {}
    for row in rows:
      print('Loading challenge %s from chess db...' % row[1])
      cur.execute('SELECT count(*) FROM pois WHERE challenge = ?',(row[0],))
      count = cur.fetchall()
      # Failures are not stored in the database, so that we get 3 tries
      # every time we restart the system.
      challenges[row[0]] = {'name':row[1],'status':row[2],
                            'failures':0}
      # If a challenge loaded from the database was processing, then the
      # process may have been killed in the middle, so revert status to
      # queued in memory so we can actually process it
      processing_statuses = ['initializing','analyzing source',
                             'analyzing binary','generating POIs']
      if challenges[row[0]]['status'] == 'not supported':
        pass
      elif challenges[row[0]]['status'] in processing_statuses:
        challenges[row[0]]['status'] = 'queued'
      else:
        challenges[row[0]]['status'] = 'restoring'
    return challenges

  def addChallenge(self, ch_id, challenge):
    sql = ''' INSERT INTO challenges(id,name,status,hints) 
              VALUES(?,?,?,?)'''
    cur = self.cdb.cursor()
    cur.execute(sql,(ch_id, challenge['name'], challenge['status'],''))
    self.cdb.commit()

  def addBlob(self, blob, target_id, ch_id):
    sql = ''' INSERT OR REPLACE INTO blobs(name,target,challenge) 
              VALUES(?,?,?)'''
    cur = self.cdb.cursor()
    cur.execute(sql,(blob, target_id, ch_id))
    self.cdb.commit()

  def updateChallengeStatus(self, ch_id, status):
    sql = ''' UPDATE challenges SET status = ? WHERE id = ? '''
    cur = self.cdb.cursor()
    cur.execute(sql, (status,ch_id))
    self.cdb.commit()

  def updateChallengeHints(self, ch_id, hints):
    sql = ''' UPDATE challenges SET hints = ? WHERE id = ? '''
    cur = self.cdb.cursor()
    cur.execute(sql, (hints,ch_id))
    self.cdb.commit()

  def getChallengeStatus(self, ch_id):
    cur = self.cdb.cursor()
    cur.execute('SELECT status FROM challenges WHERE id = ?',(ch_id,))
    status = cur.fetchall()[0][0]
    return status

  def addPois(self, ch_id, pois):
    sql = ''' INSERT INTO pois(uuid,challenge,severity,type,
                               file,line,func,code,
                               title,description,ranking,complexity,id,binary,details,
                               offset,funcAddr)
                               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) '''
    cur = self.cdb.cursor()
    for poi in pois:
      if poi.line is None:
        print("WARNING: POI doesn't have a line number: %s" % poi)
        self.logger.error("WARNING:  POI doesn't have a line number: %s" % poi)
        poi.line = -1
      else:
        poi.line = int(poi.line[:poi.line.find(':')])
      if poi.offset is None:
        poi.offset = 'unknown'
      if type(poi.code) is list:
        print("WARNING: POI's code field is a list: %s" % poi)
        self.logger.error("WARNING: POI's code field is a list: %s" % poi)
        poi.code = ';'.join(poi.code)
      cur.execute(sql, (poi.uuid,ch_id,poi.severity,poi.type,
                        poi.file,poi.line,poi.func,poi.code,
                        poi.title,poi.description,poi.vulnScore,
                        poi.codeComplexity,poi.id,poi.binary,poi.details,
                        poi.offset,poi.funcAddr))
      self.cdb.commit()

  def clearPois(self, ch_id):
    # Delete all POIs for a specific challenge from the database.
    # This is done to avoid duplicate POIs in case an analysis failed in the middle
    # of producing POIs, and we are retrying it.
    # Also delete votes and notes corresponding to that challenge, as we are
    # deleting the POIs they reference.
    sql = '''DELETE FROM pois WHERE challenge=? '''
    sql2 = '''DELETE FROM votes WHERE challenge=? '''
    sql3 = '''DELETE FROM notes WHERE challenge=? '''
    cur = self.cdb.cursor()
    cur.execute(sql, (ch_id,))
    cur.execute(sql2, (ch_id,))
    cur.execute(sql3, (ch_id,))
    self.cdb.commit()

  def addError(self, ch_id, error):
    sql = ''' INSERT INTO errors(challenge,error) VALUES(?,?) '''
    cur = self.cdb.cursor()
    cur.execute(sql, (ch_id,error))
    self.cdb.commit()

  def clearErrors(self, ch_id):
    sql = '''DELETE FROM errors WHERE challenge=? '''
    cur = self.cdb.cursor()
    cur.execute(sql, (ch_id,))
    self.cdb.commit()

  def getErrorCount(self,ch_id):
    cur = self.cdb.cursor()
    cur.execute('SELECT count(*) FROM errors WHERE challenge = ?',(ch_id,))
    count = cur.fetchall()[0][0]
    return count

special_errors = ['Challenge metadata is too old.','but only ELF binaries are supported.','Binary path does not exist:','Source path does not exist:','No challenge bin present in']
def is_special_error(text):
  for e in special_errors:
    if e in text:
      return True
  return False
def is_unsupported_error(text):
  if special_errors[1] in text:
    return True
  return False

def send_status_message(ch_name, target_id, status):
  print('Sending status message for %s: %s' % (ch_name, status))
  if target_id is not None:
    requests.post('http://challenge-broker:5001/v1/system_status',json={
                  'status_message': '%s: %s' % (ch_name,status),
                  'target_id': target_id,
                  'tool_name': 'Erlking',})
  requests.post('http://challenge-broker:5001/v1/system_status',json={
                'status_message': '%s: %s' % (ch_name,status),
                'tool_name': 'Erlking',})

# Builds the source database for a target.
# This assumes a fresh database is being created and that
# there was no database there previously, as this is only
# to be called on freshly extracted targets!
def build_src_db(target_name,src_path,logger):
    if not os.path.isdir(src_path):
      logger.error("[Target %s] Source path not present!  Abandoning analysis." % target_name)
      raise FileNotFoundError('Source path does not exist: %s' % src_path)
    logger.info("[Target %s] Running Joern" % target_name)
    os.system('cd %s; java -jar %s/joern/joern-0.3.1/bin/joern.jar .' % (src_path, erlking.sw_home))

def find_challenge_bins(target_name,target_path,bin_path,logger):
    yaml_file = '%s/%s/chess_challenge.yaml'%(target_dir,target_name)
    target_bins = []
    if os.path.exists(yaml_file):
      with open(yaml_file) as f:
        meta = yaml.load(f)
        print('challenge metadata: %s' % meta)
        meta_ver = meta['chess_challenge_metadata'].split('.')
        if int(meta_ver[0]) == 0 and int(meta_ver[1]) < 5:
            logger.error("[Target %s] Challenge metadata too old.  Need version 0.5.0 or greater." % target_name)
            raise TypeError('Challenge metadata is too old.  Need version 0.5.0 or greater, but version is %s.' % meta['chess_challenge_metadata'])
        if 'targets' in meta:
          invalid_bin_found = False
          invalid_bin_type = None
          for target in meta['targets']:
            if target['runtime']['type'] != 'ELF':
              # If there are some target runtimes that are not ELF files, then do not
              # produce an error.  Only if NO valid binaries are found shall we give an error,
              # in which we will give the type of the last invalid runtime found.
              invalid_bin_found = True
              invalid_bin_type = target['runtime']['type']
              continue
            target_bins.append(['%s/%s/%s' % (target_dir, target_name, target['runtime']['path']), target['runtime']['path']])
          if len(target_bins) == 0 and invalid_bin_found:
            # Give an error if we encountered no valid binaries and encountered at least
            # one invalid runtime.
            # If we found no invalid runtimes, but the length of target_bins is still 0,
            # then we will give an error at the end of this function.
            logger.error("[Target %s] Only ELF runtime files supported." % target_name)
            raise TypeError('Target runtime is %s, but only ELF binaries are supported.' % invalid_bin_type)
    else:
      if not os.path.isdir(bin_path):
        logger.error("[Target %s] Binary path not present!  Abandoning analysis." % target_name)
        raise FileNotFoundError('Binary path does not exist: %s' % bin_path)
      (binPath, _, binFile) = next(os.walk(bin_path))
      # Find files ending in .bin
      target_bin = None
      for fn in binFile:
          if fn.endswith('.bin'):
              target_bins.append([os.path.join(binPath,fn), 'challenge_bin/build/%s' % fn])
    if len(target_bins) == 0:
        logger.error("[Target %s] No binaries in challenge!  Abandoning analysis." % target_name)
        raise FileNotFoundError('No challenge bin present in %s' % bin_path)
    print("[Target %s] Found binary path(s): %s" % (target_name,target_bins))
    return target_bins

def build_bin_db(target_name,target_bin,src_path,db_path,db_instance,logger):
    logger.info("[Target %s] Analyzing binary at %s" % (target_name, target_bin))
    print("[Target %s] Analyzing binary at %s" % (target_name, target_bin))
    logger.info("[Target %s] Shutting down neo4j instance %d" % (target_name, db_instance))
    os.system("kill -9 $(ps -ef | grep '%s/neo4j' | grep -v grep | awk '{print $2}')" % db_instance)
    # Inexplicably, on my machine the neo4j server encounters a java error 
    # during shutdown:
    # NoSuchMethodError sun.misc.Cleaner sun.nio.ch.DirectBuffer.cleaner()
    # This does not happen on all machines, and killing the java process
    # does actually allow the server to shut down gracefully if it doesn't
    # encounter this error.
    # However, since the server hits an error, it doesn't clean up the 
    # database properly, and all attempts to restart the server lead to a
    # silent error.  I therefore just delete the database contents here
    # so that the server can start up again.
    os.system('rm -r %s/%s/neo4j-community-2.1.5/data/*'%(erlking.sw_home,db_instance))
    os.system('bash %s/scripts/config.sh set "%s/%s/neo4j-community-2.1.5/conf/neo4j-server.properties" "org.neo4j.server.database.location" "%s"' % (erlking.erlk_home, erlking.sw_home, db_instance, db_path))
    os.system('rm -rf %s; mkdir -p %s; cp -R %s/.joernIndex/* %s' % (db_path,db_path,src_path,db_path))
    logger.info("[Target %s] Starting neo4j DB" % target_name)
    os.system('%s/%s/neo4j-community-2.1.5/bin/neo4j console > logs/neo4j.log 2>&1 & sleep 20' % (erlking.sw_home, db_instance))
    logger.info("[Target %s] Getting DB Connection" % target_name)
    db_conn = getDBConnection(db_instance,logger)
    logger.info("[Target %s] Running DWARVENking" % target_name)
    dk = DWARVENking(target_bin)
    logger.info("[Target %s] Running sigBIN" % target_name)
    sb = sigBIN(target_bin,db_conn)
    return (db_conn,dk,sb)

def runCastle(db_conn, retList, demangledFuncInfoList, sbCG, varLayout):
    cs = Castle(db_conn, retList, demangledFuncInfoList, sbCG, varLayout)
    return cs.getRetList()

def run_analysis(analysis, args):
    return analysis(*args)

def run_checker(target_name,ch_id,db_conn,cdb,dk,sb,mqttc,bin_name,logger):
  # runChecker(sbProg, db_conn, sb_data, varLayout, targets[target], retList, demangledFuncInfoList)
    # TODO: Run checker in background and send results to GUI
    logger.info("[Target %s] Running Checker" % target_name)
    print("[Target %s] Running Checker" % target_name)
    varLayout = dk.getUnrolledInfo()
    oldRetList = dk.getRetList()
    demangledFuncInfoList = sb.extractFuncInfo()
    sb.generateCPG(demangledFuncInfoList)
    updatedDemangledFuncInfoList = sb.getUpdatedFuncList()
    sbProg = sb.prog
    sbCFG = sb.getCFG()
    sbCG = sb.getCG()
    sbBAPSubList = sb.getBAPSubList()
    sb_data = (sbProg, sbCFG, sbCG, updatedDemangledFuncInfoList, sbBAPSubList)
    pois = []
    retList = runCastle(db_conn, oldRetList, demangledFuncInfoList, sbCG, varLayout)
    ch = Checker(sbProg, db_conn, sb_data, varLayout, retList, demangledFuncInfoList)
    analyses = [(ch.insecure_call, [], 'Insecure Call'),
                (ch.checkBOILs, [], 'BOIL'),
                (ch.insecure_paths, [], 'Insecure Path'),
                (ch.checkForConditions, [], 'For Conditions'),
                (ch.effected_sinks, [], 'For Effected Sink'),]
    #            (ch.pointerCheck, [], 'Pointer Check'),]
    # Update the challenge-level input source hints
    cdb.updateChallengeHints(ch_id,ch.getInputSources())
    logger.info("[Target %s] Starting analyses." % target_name)
    print("[Target %s] Starting analyses." % target_name)
    for analysis in analyses:
        try:
            pois = run_analysis(analysis[0], analysis[1])
            if pois is not None:
              for poi in pois:
                poi.binary = bin_name
                if poi.code is None:
                  poi.code = ''
              cdb.addPois(ch_id,pois)
              publish_pois(target_name,mqttc,pois,logger)
              logger.info("[Target %s] %s analysis complete." % (target_name, analysis[2]))
              print("[Target %s] %s analysis complete." % (target_name, analysis[2]))
              print('Resulting POIs: %d' % len(pois))
              print(str(pois).encode('utf-8', errors='replace'))
            else:
              print("[Target %s] %s analysis complete." % (target_name, analysis[2]))
              print('No POIs were found.')
        except:
            exc_text = 'Error during %s analysis:\n%s' % (analysis[2], traceback.format_exc())
            print(exc_text)
            # This error won't stick around because I clear all errors if the overall analysis for
            # a challenge completes successfully.  Since each of these analyses are no longer a
            # fatal error, then it appears to complete successfully, leaving the error only in the
            # logs.  In some ways this may be better, because a single failed analysis won't show
            # up in the UI after all analyses have completed.  However, it will show up temporarily
            # while the remaining analyses are running.
            cdb.addError(ch_id,exc_text)

def analyze_target(ch_id,target,mqttc,cdb,db_instance,logger):
    target_name = target['blob_name']
    challenge_name = target['challenge_name']
    target_id = target['id']
    POIRecord.reset() # Reset POI ID counter
    target_path = '%s/%s' % (target_dir,target_name)
    target_src_path = '%s/%s/challenge_src' % (target_dir,target_name)
    target_bin_path = '%s/%s/challenge_bin/build/' % (target_dir,target_name)
    db_path = os.path.abspath("%s/db" % (target_path))
    bins = find_challenge_bins(target_name, target_path, target_bin_path, logger)
    cdb.updateChallengeStatus(ch_id,'analyzing source')
    send_status_message(challenge_name,target_id,'analyzing source')
    build_src_db(target_name,target_src_path,logger)
    # Clear any POIs that previously existed for this challenge.
    logger.info("[Target %s] Clearing any old POIs for target." % target_name)
    cdb.clearPois(ch_id)
    for binary in bins:
      cdb.updateChallengeStatus(ch_id,'analyzing binary')
      send_status_message(challenge_name,target_id,'analyzing binary')
      (db,dk,sb) = build_bin_db(target_name,binary[0],target_src_path,db_path,db_instance,logger)
      cdb.updateChallengeStatus(ch_id,'generating POIs')
      send_status_message(challenge_name,target_id,'generating POIs')
      run_checker(target_name,ch_id,db,cdb,dk,sb,mqttc,binary[1],logger)

def process_target(ch,ch_id,target,mqttc,db_instance,logger):
  cdb = None
  target_name = target['blob_name']
  challenge_name = target['challenge_name']
  target_id = target['id']
  try:
   cdb = ChessDatabase(logger)
   analyze_target(ch_id,target,mqttc,cdb,db_instance,logger)
   cdb.updateChallengeStatus(ch_id,'complete')
   send_status_message(challenge_name,target_id,'complete')
   # Since this challenge succeeded, delete error info so that it
   # will not be restored as "error" status if the server is restarted
   cdb.clearErrors(ch_id)
   print("[Target %s] All analyses complete!" % target_name)
  except:
    print('Exception encountered while processing %s!' % ch['name'])
    # logger.exception(e)
    logger.exception('Exception encountered while processing %s!' % ch['name'])
    try:
      exc_text = traceback.format_exc()
      exc_split = exc_text.split('\n')
      if is_special_error(exc_split[-2]):
        # Special exceptions forego the traceback and only give the
        # error message.
        exc_text = exc_split[-2] + '\n'
      else:
        exc_text = ''.join(traceback.format_exc())
      print(exc_text)
      cdb.addError(ch_id,exc_text)
      if is_unsupported_error(exc_text):
        cdb.updateChallengeStatus(ch_id,'not supported')
        send_status_message(challenge_name,target_id,'not supported')
      else:
        cdb.updateChallengeStatus(ch_id,'error')
        send_status_message(challenge_name,target_id,'error')
    except:
      print('Exception trying to set challenge %s status!' % ch['name'])
      logger.exception('Exception trying to set challenge %s status!' % ch['name'])
  

def init_logger():
    log_name = 'erlking-chess'
    logger = logging.getLogger(log_name)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - [%(process)d:%(name)s] - %(levelname)s - %(message)s")
    fh = logging.FileHandler('/home/utd/logs/erlking-chess.log')
    fh.setLevel(logging.NOTSET)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    return logger

def get_blob(target,ch_name,logger,cdb):
    blob_id = target['blob_id']
    target_id = target['id']
    blob_name = '%s-%s' % (ch_name,blob_id)
    blob_resp = requests.get('http://challenge-broker:5001/v1/blobs/%s/data'%blob_id)
    # Get zipped blob containing challenge contents
    zio = io.BytesIO(blob_resp.content)
    zif = zipfile.ZipFile(zio)
    # Extract blob to targets directory
    zif.extractall('%s/%s' % (target_dir,blob_name))
    logger.debug('Extracted blob to %s/%s' % (target_dir,blob_name))
    cdb.addBlob(blob_name,target_id,target['challenge_id'])
    return blob_name

# Currently unused, but in case a target doesn't come with a compiled version,
# leave this here
def compile_target(target_name,logger):
    challenge_src_path = '%s/%s/challenge_src' % (target_dir,target_name)
    # Remove -Werror flag from makefile
    makefile_contents = ''
    with open('%s/Makefile' % challenge_src_path,'r') as makefile:
        makefile_contents = makefile.read()
        makefile_contents = makefile_contents.replace('-Werror','')
    with open('%s/Makefile' % challenge_src_path,'w') as makefile:
        makefile.write(makefile_contents)
    # Build binary
    subprocess.run('make',cwd=challenge_src_path)
    logger.debug('Compiled target in %s' % challenge_src_path)

def convert_poi_to_json(poi):
    data = {}
    data['identifier'] = poi.uuid
    data['challenge'] = poi.challenge
    data['target'] = poi.target
    data['timestamp'] = datetime.fromtimestamp(time.time()).isoformat()
    data['actor'] = {}
    data['actor']['name'] = 'ERLking'
    data['actor']['actor_type'] = 'CRS'
    data['poi_type'] = poi.type
    data['title'] = poi.title
    data['description'] = poi.description
    data['priority'] = poi.severity
    data['tags'] = []
    # TODO: populate tags

    # Insights
    insight = {}
    insight['nodes'] = []
    insight['edges'] = []

    # Create single node for POI for now
    # TODO: create nodes/edges depending on POI
    node = {}
    node['identifier'] = str(uuid.uuid4())
    node['node_type'] = 'src_location'
    node['description'] = poi.description
    location = {}
    location['file_path'] = 'challenge_src/%s' % poi.file
    location['src_location'] = {}
    # Get only line number, not column number or characters
    if type(poi.line) is str:
      location['src_location']['start_line'] = int(poi.line[:poi.line.find(':')])
    else:
      location['src_location']['start_line'] = -1
    node['location'] = location
    insight['nodes'].append(node)

    # Add insight object
    data['insight'] = insight
    return data

def publish_pois(challenge,mqttc,pois,logger):
    # TODO: Have the challenge field populated by the checker
    for poi in pois:
      poi.challenge = challenge
    jpois = map(convert_poi_to_json,pois)
    # Optional importing of jsonschema for pois.
    schema = None
    with open('%s/poi.json'%jsonschema_dir,'r') as f:
        schema = json.loads(f.read())
    for jpoi in jpois:
        # Optional validation step.  Good for testing, but should not
        # be done in normal operation.
        logger.info('Attempting to validate:\n%s'%jpoi)
        jsonschema.validate(instance=jpoi, schema=schema)
        identifier = jpoi['identifier']
        jpoi = json.dumps(jpoi).encode('utf-8')
        # Publish the poi
        mqttc.publish('public/aptima/POI/%s'%identifier, payload=jpoi, qos=1, retain=True)
    logger.info("[Challenge %s] Published POIs"%challenge)

def main():
  logger = init_logger()
  try:
    os.mkdir(target_dir)
  except FileExistsError:
    # This exception is ok
    pass
  cdb = ChessDatabase(logger)
  challenges = cdb.getChallenges()
  mqttc = mqtt.Client()
  # Once we have an API for others to request things from us,
  # This is how we can subscribe to topics and respond to
  # messages on those topics.
  #mqttc.on_connect = on_connect_callback
  #mqttc.on_message = on_message_callback
  while True:
    try:
      mqttc.connect('mosquitto', 1883, 60)
      mqttc.loop_start()
      break
    except:
      print( 'Error connecting to mqtt server.  Retrying in 30 seconds...' )
      logger.exception( 'Error connecting to mqtt broker.  Retrying in 30 seconds...' )
      time.sleep(30)
  poll_counter = 0
  active_challenges = []
  available_db_instances = [1,2,3,4,5]
  while True:
    print('Polling challenge broker (%d)...' % poll_counter)
    logger.debug('Polling challenge broker (%d)...' % poll_counter)
    poll_counter += 1
    # Get list of challenges
    try:
      challenges_resp = requests.get('http://challenge-broker:5001/v1/challenges')
      targets_resp = requests.get('http://challenge-broker:5001/v1/targets')
    except:
      print('Error contacting challenge broker.  Retrying in one minute...')
      logger.exception('Error contacting challenge broker.  Retrying in one minute...')
      time.sleep(60)
      continue
    # If any request had an error code, sleep for a while and try again
    if challenges_resp.status_code != 200 or \
        targets_resp.status_code != 200:
      time.sleep(60)
      continue
    new_challenge = False
    for challenge in challenges_resp.json():
      ch_name = challenge['name']
      ch_id = challenge['id']
      # If we have not encountered this challenge before
      if not ch_id in challenges:
        new_challenge = True
        logger.debug('New challenge: %s' % ch_name)
        print('New challenge: %s' % ch_name)
        challenges[ch_id] = {'name':ch_name,'status':'queued',
                             'failures':0}
        try:
          # Add challenge to chess db
          cdb.addChallenge(ch_id,challenges[ch_id])
        except:
          print('Exception while adding %s to db!' % ch_name)
          logger.exception('Exception while adding %s to db!' % ch_name)
    for ch_id, ch in challenges.items():
      if not new_challenge and ch['status'] == 'error' and ch['failures'] < 3:
        print('Requeueing failed challenge after finding no new ones.')
        logger.debug('Requeueing failed challenge after finding no new ones.')
        try:
          cdb.updateChallengeStatus(ch_id,'queued')
          challenges[ch_id]['status'] = 'queued'
        except:
          print('Exception trying to set challenge %s status!' % ch['name'])
          logger.exception('Exception trying to set challenge %s status!' % ch['name'])
      elif ch['status'] == 'queued':
        try:
          target_found = False
          # Loop through targets associated with this challenge
          for target in targets_resp.json():
            if target['challenge_id'] == ch_id and target['parent_id'] == None:
              target_found = True
              # Download blob associated with target and save
              # its name here so it's faster to look up later
              target['blob_name'] = get_blob(target,ch['name'],logger,cdb)
              # Check if we have a free database instance.
              # If not, attempt to join one of the existing processes until one succeeds,
              # with a one-minute timeout each time.  If we have confirmed one has terminated, set our
              # status for that challenge
              if len(available_db_instances) == 0:
                for pind in range(len(active_challenges)-1,-1,-1):
                  proc = active_challenges[pind]
                  proc[1].join(60)
                  if proc[1].exitcode is not None:
                    print('Analysis process exited with code %d.' % proc[1].exitcode)
                    status = cdb.getChallengeStatus(proc[0])
                    available_db_instances.append(proc[2])
                    # Check status of challenge, since it was set in a separate process, and set local vars
                    if status == 'not supported':
                      challenges[proc[0]]['status'] = 'not supported'
                      challenges[proc[0]]['failures'] += 3
                    elif status == 'error':
                      challenges[proc[0]]['status'] = 'error'
                      challenges[proc[0]]['failures'] += 1
                    elif status == 'complete':
                      challenges[proc[0]]['status'] = 'complete'
                    else:
                      print( "[1] Unexpected status '%s' encountered for challenge %s.  Setting internally as error..." % 
                              (status,challenges[proc[0]]['name']))
                      cdb.addError(proc[0], process_terminated_error)
                      cdb.updateChallengeStatus(proc[0],'error')
                      send_status_message(ch['name'],target['id'],'error')
                      challenges[proc[0]]['status'] = 'error'
                      challenges[proc[0]]['failures'] += 1
                    # Remove challenge from list, freeing up a slot for another one
                    del active_challenges[pind]
                    # Now that we found a challenge that has completed, we can start analyzing one in that slot
                    break
              if len(available_db_instances) > 0:
                # Prepare for analysis
                print('Starting analysis on challenge %s\n' % ch['name'])
                cdb.updateChallengeStatus(ch_id,'initializing')
                send_status_message(ch['name'],target['id'],'initializing')
                challenges[ch_id]['status'] = 'initializing'
                db_instance = available_db_instances.pop()
                p = multiprocessing.Process(target=process_target, args=(ch,ch_id,target,mqttc,db_instance,logger))
                active_challenges.append([ch_id,p,db_instance])
                # Run analysis on resulting target
                p.start()
              else:
                print('No available db instances to process %s.  Will retry later.' % ch['name'])
          if not target_found:
            print('No target found for challenge!  Will retry later.')
            logger.warning('No target found for challenge!  Will retry later.')
            cdb.updateChallengeStatus(ch_id,'queued')
            challenges[ch_id]['status'] = 'queued'
        except:
        # except Exception as e:
          print('Severe exception encountered while processing %s!' % ch['name'])
          # logger.exception(e)
          logger.exception('Severe exception encountered while processing %s!' % ch['name'])
          try:
            exc_text = traceback.format_exc()
            print(exc_text)
            cdb.addError(ch_id,exc_text)
            cdb.updateChallengeStatus(ch_id,'error')
            challenges[ch_id]['status'] = 'error'
            challenges[ch_id]['failures'] += 1
          except:
            print('Exception trying to set challenge %s status!' % ch['name'])
            logger.exception('Exception trying to set challenge %s status!' % ch['name'])
      elif ch['status'] == 'restoring':
        # This challenge has already been processed by erlking, but the system
        # has been restarted since that time.  Attempt to restore some of the
        # data lost because of a restart, like the blob contents. 
        try:
          for target in targets_resp.json():
            if target['challenge_id'] == ch_id and target['parent_id'] == None:
              get_blob(target,ch['name'],logger,cdb)
              print('Restored blob contents for %s' % ch['name'])
          err_count = cdb.getErrorCount(ch_id)
          if err_count != 0:
            cdb.updateChallengeStatus(ch_id,'error')
            challenges[ch_id]['status'] = 'error'
          else:
            cdb.updateChallengeStatus(ch_id,'complete')
            challenges[ch_id]['status'] = 'complete'
          print('Restored status for %s' % ch['name'])
        except:
          print('Exception trying to restore challenge %s!' % ch['name'])
          logger.exception('Exception trying to restore challenge %s!' % ch['name'])
    # Wait for a still-processing challenge to complete.
    if len(active_challenges) > 0:
      for pind in range(len(active_challenges)-1,-1,-1):
        proc = active_challenges[pind]
        proc[1].join(2)
        if proc[1].exitcode is not None:
          print('Analysis process exited with code %d.' % proc[1].exitcode)
          status = cdb.getChallengeStatus(proc[0])
          available_db_instances.append(proc[2])
          # Check status of challenge, since it was set in a separate process, and set local vars
          if status == 'not supported':
            challenges[proc[0]]['status'] = 'not supported'
            challenges[proc[0]]['failures'] += 3
          elif status == 'error':
            challenges[proc[0]]['status'] = 'error'
            challenges[proc[0]]['failures'] += 1
          elif status == 'complete':
            challenges[proc[0]]['status'] = 'complete'
          else:
            print( "[2] Unexpected status '%s' encountered for challenge %s.  Setting internally as error..." % 
                    (status,challenges[proc[0]]['name']))
            cdb.addError(proc[0], process_terminated_error)
            cdb.updateChallengeStatus(proc[0],'error')
            challenges[proc[0]]['status'] = 'error'
            challenges[proc[0]]['failures'] += 1
          # Remove challenge from list, freeing up a slot for another one
          del active_challenges[pind]
          break
    print('All known challenges processed or processing.  Sleeping for one minute...')
    logger.debug('All known challenges processed or processing.  Sleeping for one minute...')
    time.sleep(60)


if __name__ == "__main__":
    #with daemon.DaemonContext():
    main()
