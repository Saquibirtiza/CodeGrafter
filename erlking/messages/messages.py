import uuid

class AffectedRecord(object):
	def __init__(self, affector, affected, offset):
		self.affector = affector
		self.affected = affected
		self.offset = offset
		self.location = None
	def __str__(self):
		return str(self.__dict__)
	def __repr__(self):
		return str(self.__dict__)

class POIRecord(object):
	count = 0

	@classmethod
	def incr(self):
		self.count += 1
		return self.count

	@classmethod
	def reset(self):
		self.count = 0

	def __init__(self, severity, file, line, typeOfAnalysis, func=None, code=None, challenge='CHALLENGE SHOULD BE REQUIRED', \
		target='', title='Default title', description='Default description', details='', vulnScore=0, \
		codeComplexity=0, offset=None, funcAddr=0x0):
		self.id = self.incr()
		self.uuid = str(uuid.uuid4())
		self.challenge = challenge
		self.target = target
		self.severity = severity.upper()
		self.type = typeOfAnalysis
		self.file = file
		self.line = line
		self.offset = offset #offset within the function
		self.funcAddr = funcAddr
		self.func = func
		self.code = code
		self.title = title
		self.description = description
		self.vulnScore = vulnScore
		self.codeComplexity = codeComplexity
		self.details = details

	def __key(self):
		return (self.type, self.file, self.line)
	def __hash__(self):
		return hash(self.__key())
	def __eq__(self, other):
		if isinstance(other, POIRecord):
			return self.__key() == other.__key()
		return NotImplemented
	def __str__(self):
		return str(self.__dict__)
	def __repr__(self):
		return str(self.__dict__)
