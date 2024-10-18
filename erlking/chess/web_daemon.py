from http.server import BaseHTTPRequestHandler, HTTPServer
import sqlite3,time,os,sys
from http import cookies
from urllib.parse import urlparse, parse_qs, urlencode, unquote_plus
import json
import urllib.request
import urllib.error
import hashlib

hostname = '0.0.0.0'
hostport = 2009 

SNIPPET_SIZE = 5

# The path to the source dir must be identical to that in chess daemon
target_src_dir = '/home/utd/targets/%s/challenge_src/%s'
target_root_dir = '/home/utd/targets/%s/%s'

page = '''<html><head><title>ERLking Status</title></head>
<body><p>%s</p></body></html>
'''

challenge_template = '''
      <tr>
        <td><a href="/challenge/%s">%s</a></td>
        <td>%s</td>
        <td>%s</td>
      </tr>'''

poi_table_template = '''
  <h4>%s Points of Interest<span id="hiddencount">%s</span></h4>
  <div>
  <span class="dropdown">
    <a class="button">Sort by...</a>
    <span class="dropdown-content" id="sortdropdown">
      <a class="currentsort">Ranking</a>
      <a>Title</a>
      <a>Description</a>
      <a>File</a>
      <a>ID</a>
      <a>Function</a>
      <a>Code Complexity</a>
    </span>
  </span>
  <span class="u-pull-right">
    <input id="hidedownvoted" type="checkbox" %s> Hide downvoted POIs</input>
  </span>
  </div>
  <!-- <a hidden class="button">&#x25bc;</a> -->
  <div hidden class="spinner" id="spinner"></div>
  <div class="tablerownoline u-full-width">
    <div class="one-and-a-half columns">&nbsp</div>
    <div class="three columns"><b>Title</b></div>
    <div class="five columns"><b>Description</b></div>
    <div class="two columns"><b>File</b></div>
    <div class="half-of-a column"><b>ID</b></div>
  </div>
  <div id="poitable">
  %s
  </div>
  '''

poi_template = '''
      <details class="%s" style="%s">
      <div hidden class="poiranking">%s</div>
      <summary class="%s">
      <div class="tablerow">
        <div class="one-and-a-half columns">
            <a class="button vote upvote %s" title="upvote">&#x25b2;</a>
            <span class="poiuserranking">%s</span>
            <a class="button vote downvote %s" title="downvote">&#x25bc;</a>
            <span class="votepadding"></span> 
        </div>
        <div class="three columns poititle">%s</div>
        <div class="five columns poidescription">%s</div>
        <div class="two columns poisourcefile">%s</div>
        <div class="half-of-a column poiid">%s</div>
      </div>
      </summary>
      <div class="tablerownoline %s">
        <div class="seven columns poifunction">Function %s, line <span class="poisourceline">%s</span>:</div>
        <div class="binaryname u-pull-right">
          %s
        </div>
        <div class="twelve columns"><pre><code class="lang-cpp">loading...</code></pre></div>
        <div class="twelve columns"><small><i>%s</i></small></div>
        <div class="row">
          <div class="three columns poicomplexity">
            Code Complexity: %s
          </div>
          <div class="three columns poioffset">
            Binary Offset: %s
          </div>
          <div class="u-pull-right">
            <span hidden class="success">&#10004</span>
            <span hidden class="failure">&#10008</span>
            <a class="button blaze %s" title="Send to Blaze">Send to Blaze</a>
            <a class="button" href="angr://?action=open_source_file&target_uuid=%s&challenge_name=%s&source_file=challenge_src/%s&line_number=%s&position=0&editor=vscode">Open In VSCode</a>
            <a class="button notes"><span class="notes-icon">&#9998;<span></a>
          </div>
        </div>
        <div hidden class="notes-editor">
          <form class="notes-form">
            <div class="row">
              <div class="eleven columns"><input class="twelve columns" type="text" placeholder="Type notes here..."></div>
              <div class="u-pull-right"><button class="button notes-submit">Submit</button></div>
            </div>
          </form>
        </div>
        <div class="notes-area">
        </div>
      </div>
      </details>'''

error_template = '''
      <h4>Error Info</h4>
      <pre><code>%s</code></pre>'''

challenge_hints_template = '''
  <p><small><b>Input hints: </b><i>%s</i></small></p>'''

cdb = None

class ChessDatabase():
  def __init__(self):
    self.cdb = None
    while self.cdb is None:
      try:
        self.cdb = sqlite3.connect('/home/utd/db/chess.db')
      except:
        pass
      if self.cdb is None:
        print('Web Server: Error connecting to db...')
        time.sleep(5)

  def loadChallenges(self):
    cur = self.cdb.cursor()
    cur.execute('SELECT * FROM challenges')
  
    rows = cur.fetchall()
    challenges = {}
    for row in rows:
      cur.execute('SELECT count(*) FROM pois WHERE challenge = ?',(row[0],))
      count = cur.fetchall()[0][0]
      challenges[row[0]] = {'name':row[1],'status':row[2],'pois':str(count)}
    return challenges

  def loadChallengeHints(self,ch_id):
    cur = self.cdb.cursor()
    cur.execute('SELECT hints FROM challenges WHERE id = ?',(ch_id,))
    res = cur.fetchall()
    if len(res) > 0:
      return res[0][0]
    return ''

  def loadPois(self,ch_id):
    cur = self.cdb.cursor()
    cur.execute('SELECT * FROM pois WHERE challenge = ? ORDER BY ranking DESC',(ch_id,))
    pois = cur.fetchall()
    return pois

  def loadPoi(self,ch_id,poi_id):
    cur = self.cdb.cursor()
    cur.execute('SELECT * FROM pois WHERE challenge = ? AND id = ?',(ch_id,poi_id))
    poi = cur.fetchall()[0]
    return poi

  def loadVotes(self,ch_id,poi_id):
    cur = self.cdb.cursor()
    cur.execute('SELECT SUM(vote) FROM votes WHERE challenge = ? AND poi = ?',(ch_id,poi_id))
    res = cur.fetchall()
    if len(res) > 0 and res[0][0] is not None:
      return res[0][0] 
    return 0

  def loadUserVote(self,ch_id,poi_id,who):
    cur = self.cdb.cursor()
    cur.execute('SELECT vote FROM votes WHERE challenge = ? AND poi = ? AND who = ?',(ch_id,poi_id,who))
    res = cur.fetchall()
    if len(res) > 0:
      return res[0][0]
    return 0

  # TODO: Right now there's nothing enforcing that the client is sending a valid POI number,
  # so a malicious entity could add votes for huge numbers of fake POIs per challenge.
  # This wouldn't happen if I considered the poi id as part of the POI's primary key, and
  # then added the POI id as a foreign key of the votes table.
  def castVote(self,ch_id,poi_id,who,vote):
    sql = ''' INSERT OR REPLACE INTO votes(challenge,poi,who,vote) 
              VALUES(?,?,?,?)'''
    cur = self.cdb.cursor()
    cur.execute(sql,(ch_id, poi_id, who, vote))
    self.cdb.commit() 

  def sendNote(self,ch_id,poi_id,who,note):
    sql = ''' INSERT OR REPLACE INTO notes(challenge,poi,who,note)
              VALUES(?,?,?,?)'''
    cur = self.cdb.cursor()
    cur.execute(sql,(ch_id, poi_id, who, note))
    self.cdb.commit()

  def removeNote(self,ch_id,poi_id,who):
    sql = '''DELETE FROM notes WHERE challenge=? AND poi=? AND who=?'''
    cur = self.cdb.cursor()
    cur.execute(sql,(ch_id, poi_id, who))
    self.cdb.commit()

  def loadNotes(self,ch_id,poi_id):
    cur = self.cdb.cursor()
    cur.execute('SELECT who,note FROM notes WHERE challenge = ? AND poi = ?',(ch_id,poi_id))
    notes = cur.fetchall()
    return notes

  def loadError(self,ch_id):
    cur = self.cdb.cursor()
    cur.execute('SELECT error FROM errors WHERE challenge = ?',(ch_id,))
    errors = cur.fetchall()
    error = ''
    for err in errors:
      error += ''.join(err)
    return error

  def loadBlob(self, ch_id):
    cur = self.cdb.cursor()
    cur.execute('SELECT name,target FROM blobs WHERE challenge = ?',(ch_id,))
    res = cur.fetchall()
    blob = None
    if len(res) > 0:
      blob = res[0]
    return blob

def get_page(fname):
  fname = '/home/utd/erlking/chess/%s' % fname
  with open(fname, 'rb') as f:
    return f.read()

class ChessServer(BaseHTTPRequestHandler):

  def __init__(self, request, client_address, server):
    self.login = None
    self.username = None
    super().__init__(request, client_address, server)

  def check_login(self):
    # Set login cookie (expires when user closes the browser)
    # If the login value is an empty string, then we still send it to the client
    # to set the cookie, but they will already be effectively logged out.
    if self.login is not None:
      self.send_header('Set-Cookie', 'erlking_username=%s; Path=/' % self.login)
      self.username = self.login 
      # If login value was an empty string, then user is logged out
      if self.username == '':
        self.username = None
        
  def check_username(self):
    # Check for cookie with logged in username
    if 'Cookie' in self.headers and 'erlking_username' in self.headers['Cookie']:
      cookie = cookies.SimpleCookie()
      cookie.load(self.headers['Cookie'])
      self.username = cookie['erlking_username'].value
      # Even if cookie is present, if username is empty string, that means user is logged out
      if self.username == '':
        self.username = None

  def check_hidedownvoted(self):
    # Check whether to hide downvoted POIs
    if 'Cookie' in self.headers and 'hidedownvoted' in self.headers['Cookie']:
      cookie = cookies.SimpleCookie()
      cookie.load(self.headers['Cookie'])
      if cookie['hidedownvoted'].value == 'yes':
        return True
    return False

  # Customized logging method
  def log_message(self, format, *args):
    sys.stderr.write("%s%s - - [%s] %s\n" %
                     (self.address_string(),
                      '' if self.username is None else ' (%s)'%self.username,
                      self.log_date_time_string(),
                      format%args))

  def do_POST(self):
    content_length = int(self.headers['content-length'])
    content = self.rfile.read(content_length)
    if content.startswith(b'username='):
      # Decode as code page 437 to just get the characters as-is
      self.login = content[9:].decode('cp437')
      if self.login != '':
        print('Client logging in as "%s"' % content[9:].decode('cp437'))
      else:
        self.check_username()
        print('Client "%s" logging out' % self.username )
    elif content.startswith(b'notes='):
      request = self.requestline.split(' ')[1]
      self.check_username()
      if request.startswith('/notes/') and self.username is not None:
        parsed = urlparse(request)
        ch_id = parsed.path.split('/')[-2]
        poi_id = parsed.path.split('/')[-1]
        note = unquote_plus(content[6:].decode('utf-8'))
        if( note != "" ):
          cdb.sendNote(ch_id,poi_id,self.username,note)
        else:
          cdb.removeNote(ch_id,poi_id,self.username)
    self.do_GET()

  def do_GET(self):
    request = self.requestline.split(' ')[1]
    self.check_username()
    if request == '/css/normalize.css':
      self.send_response(200)
      self.send_header('Content-type', 'text/css')
      self.end_headers()
      page = get_page('css/normalize.css')
      self.wfile.write(page)
    elif request == '/css/skeleton.css':
      self.send_response(200)
      self.send_header('Content-type', 'text/css')
      self.end_headers()
      page = get_page('css/skeleton.css')
      self.wfile.write(page)
    elif request == '/css/custom.css':
      self.send_response(200)
      self.send_header('Content-type', 'text/css')
      self.end_headers()
      page = get_page('css/custom.css')
      self.wfile.write(page)
    elif request == '/images/favicon.png':
      self.send_response(200)
      self.send_header('Content-type', 'image/png')
      self.end_headers()
      page = get_page('images/favicon.png')
      self.wfile.write(page)
    elif request.startswith('/source/'):
      challenges = cdb.loadChallenges()
      parsed = urlparse(request)
      ch_id = parsed.path.split('/')[-1]
      params = parse_qs(parsed.query)
      blob = cdb.loadBlob(ch_id)
      blob_name = None
      if blob is not None:
        blob_name = blob[0]
      if not 'file' in params or '..' in params['file'] or blob_name is None:
        # Requested file not found error page
        self.send_response(404)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write('Requested file does not exist.'.encode('utf-8'))
      else:
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        fname = target_src_dir % (blob_name,params['file'][0])
        fline = None
        # A line number of -1 indicates an internal error when generating the POI
        if 'line' in params and params['line'][0] == '-1':
          error_message = '''Cannot display source snippet because the specific line number could not be automatically determined.
You may be able to infer the source line from the POI description, filename, and function name.'''
          self.wfile.write(error_message.encode('utf-8'))
          return
        if 'line' in params and params['line'][0].isnumeric():
          fline = int(params['line'][0])
          if fline >= SNIPPET_SIZE:
            fline -= SNIPPET_SIZE
          else:
            fline = 0
        print('Request for file source: %s' % (fname))
        if os.path.exists(fname):
          with open(fname, 'r', errors='replace') as f:
            text = ''
            if fline is not None:
              texts = f.readlines()
              if fline+SNIPPET_SIZE*2 < len(texts):
                texts = texts[fline:fline+SNIPPET_SIZE*2]
                # Somewhat hackish insertion of line numbers
                texts = ['%d\t%s' % (fline+i+1,t) for i,t in enumerate(texts)] 
                text = ''.join(texts)
              else:
                texts = texts[fline:]
                # Somewhat hackish insertion of line numbers
                texts = ['%d\t%s' % (fline+i+1,t) for i,t in enumerate(texts)] 
                text = ''.join(texts)
            else:
              text = f.read()
            self.wfile.write(text.encode('utf-8'))
        else:
          self.wfile.write('Requested file does not exist.'.encode('utf-8'))
    elif request.startswith('/vote/'):
      challenges = cdb.loadChallenges()
      parsed = urlparse(request)
      ch_id = parsed.path.split('/')[-1]
      params = parse_qs(parsed.query)
      if self.username is not None and ch_id in challenges and 'poi' in params and \
                                   ('upvote' in params or 'downvote' in params or 'novote' in params):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        # TODO: Is it safe to send the poi number with no filtering to the DB?
        if 'upvote' in params:
          cdb.castVote(ch_id,params['poi'][0],self.username,1)
        elif 'downvote' in params:
          cdb.castVote(ch_id,params['poi'][0],self.username,-1)
        else:
          cdb.castVote(ch_id,params['poi'][0],self.username,0)
        self.wfile.write(str(cdb.loadVotes(ch_id,params['poi'][0])).encode('utf-8'))
      else:
        # Requested file not found error page
        self.send_response(404)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write('?'.encode('utf-8'))
    elif request.startswith('/notes/'):
      challenges = cdb.loadChallenges()
      parsed = urlparse(request)
      ch_id = parsed.path.split('/')[-2]
      poi_id = parsed.path.split('/')[-1]
      if ch_id in challenges and self.username is not None:
        self.send_response(200)
        self.send_header('Content-type', 'text/json')
        notes = cdb.loadNotes(ch_id,poi_id)
        result = {'notes':[]}
        for note in notes:
          if note[0] == self.username:
            result['yours'] = note[1]
          result['notes'].append([note[0],note[1]])
        self.wfile.write(json.dumps(result).encode('utf-8'))
      else:
        # Requested file not found error page
        self.send_response(404)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write('?'.encode('utf-8'))
    elif request.startswith('/blaze/'):
      challenges = cdb.loadChallenges()
      parsed = urlparse(request)
      ch_id = parsed.path.split('/')[-2]
      poi_id = parsed.path.split('/')[-1]
      poi = cdb.loadPoi(ch_id,poi_id)
      try:
        blob = cdb.loadBlob(ch_id)
        blob_name = None
        if blob is not None:
          blob_name = blob[0]
        if blob_name is None:
          raise Exception
        # Open target binary file, using the path derived from the blob name and the bin path from the POI
        with open(target_root_dir%(blob_name,poi[13]),'rb') as f:
          # Get md5 hash of target binary
          h = hashlib.md5()
          h.update(f.read())
          offset = poi[15]
          # Change unknown offsets to 0 for blaze, pointing to the start of
          # the function since we don't know the exact address
          if offset == 'unknown':
            offset = 0
          # Send request to Blaze
          request_text = 'http://blaze:6681/poi'
          request_params = {'binaryHash':h.hexdigest(), 'funcAddr':poi[16], 'instrOffset':offset, 'name':poi[8], 'description':poi[9]}
          request_params = urlencode(request_params)
          print('Sending request to Blaze: %s' % '%s?%s' % (request_text,request_params) )
          response = urllib.request.urlopen('%s?%s' % (request_text,request_params), data=None, timeout=0.5)
          print('Response from Blaze: %s %s' % (response.status,response.info().as_string()) )
          self.send_response(response.status)
          self.send_header('Content-type', 'text/plain')
          self.end_headers()
      except urllib.error.URLError as e:
        print('Request to Blaze returned an error: %s' % e.reason)
        if hasattr(e,'code'):
          self.send_response(e.code)
        else:
          self.send_response(500)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
      except:
        print('An unknown error occurred while sending request to Blaze.')
        self.send_response(500)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
    elif request.startswith('/status/'):
      challenges = cdb.loadChallenges()
      parsed = urlparse(request)
      ch_id = parsed.path.split('/')[-1]
      if ch_id in challenges:
        self.send_response(200)
        self.send_header('Content-type', 'text/json')
        pois = cdb.loadPois(ch_id)
        poilist = {}
        for poi in pois:
          votes = cdb.loadVotes(ch_id, poi[12]);
          poilist[poi[12]] = votes
        self.wfile.write(json.dumps(poilist).encode('utf-8'))
      else:
        # Requested file not found error page
        self.send_response(404)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write('Challenge not found.'.encode('utf-8'))
    elif request.startswith('/challenge/'):
      challenges = cdb.loadChallenges()
      ch_id = request.split('/')[-1]
      if not ch_id in challenges:
        # Challenge not found error page
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        page = get_page('html/404.html')
        self.wfile.write(page)
      else:
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.check_login()
        self.end_headers()
        # If not logged in, send login page instead of challenge info
        if self.username is None:
          page = get_page('html/login.html')
          page = page.decode('utf-8')
          self.wfile.write(page.encode('utf-8'))
          return
        page = get_page('html/challenge.html')
        page = page.decode('utf-8')
        ch = challenges[ch_id]
        pois = cdb.loadPois(ch_id)
        blob_target = None
        if len(pois) > 0: 
          blob = cdb.loadBlob(ch_id)
          if blob is not None:
            blob_target = blob[1]
        poi_entries = []
        poi_table = ''
        counter = 0
        hidden_count = 0
        # Check whether to hide downvoted POIs
        hidedownvoted = self.check_hidedownvoted()
        for poi in pois:
          # Mark current vote in UI for each POI
          vote = cdb.loadUserVote(ch_id, poi[12], self.username)
          upvote = ''
          downvote = ''
          userscore = ''
          poitop = ''
          hide_text = ''
          if vote > 0:
            upvote = 'currentvote'
          elif vote < 0:
            downvote = 'currentvote'
          votes = cdb.loadVotes(ch_id, poi[12]);
          # POIs with low user score have lower opacity
          if votes < 0:
            userscore = 'lowscore'
            if hidedownvoted:
              hide_text = 'display: none;'
              hidden_count += 1
          # Highlight top 20% of POIs using automatic ranking.  They are already sorted by ranking. */
          if counter < len(pois)*0.2:
            poitop = 'poitop'
          # Replace line number of -1 with zero when generating angr management link
          poi_entries.append(poi_template % (userscore,hide_text,poi[10],poitop,
                                             upvote,votes,downvote,
                                             poi[8],poi[9],poi[4],poi[12],poitop,
                                             poi[6],poi[5],poi[13],poi[14],poi[11],poi[15],
                                             'disabled-button' if poi[16] == '0' else '',
                                             blob_target,ch['name'],poi[4],
                                             0 if poi[5] == -1 else poi[5]))
          counter += 1
        if len(poi_entries) > 0:
          # Only display POI table if there is at least one POI
          poi_table = poi_table_template % (len(poi_entries),
                                            ' (%d hidden)' % hidden_count if hidedownvoted else '', 
                                            'checked' if hidedownvoted else '', 
                                            ''.join(poi_entries))
        hints = cdb.loadChallengeHints(ch_id)
        if hints != '':
          hints = challenge_hints_template % hints
        error = cdb.loadError(ch_id)
        if error != '':
          # Display error info if there are any errors
          error = error_template % error
        page = page % (ch['name'],ch_id,self.username,ch['name'],
                       ch['status'],poi_table,hints,error)
        self.wfile.write(page.encode('utf-8'))
    else:
      self.send_response(200)
      self.send_header('Content-type', 'text/html')
      self.check_login()
      self.end_headers()
      if self.username is not None:
        page = get_page('html/index.html')
        page = page.decode('utf-8')
        challenges = cdb.loadChallenges()
        ch_entries = []
        for ch_id, ch in challenges.items():
          ch_entries.append(challenge_template % 
                            (ch_id,ch['name'],ch['status'],ch['pois']))
        page = page % (self.username, ''.join(ch_entries))
      else:
        page = get_page('html/login.html')
        page = page.decode('utf-8')
      self.wfile.write(page.encode('utf-8'))

server = HTTPServer((hostname, hostport), ChessServer)

time.sleep(1)

cdb = ChessDatabase()

print("ERLking Chess Web Server Online")

try:
  server.serve_forever()
except KeyboardInterrupt:
  pass

print("ERLking Chess Web Server Exited")
