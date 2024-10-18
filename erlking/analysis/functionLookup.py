import subprocess
import os
import argparse



parser = argparse.ArgumentParser(description='Return the function names corresponding to reported line')
# parser.add_argument('integers', metavar='N', type=int, nargs='+',
#                     help='an integer for the accumulator')
# parser.add_argument('--sum', dest='accumulate', action='store_const',
#                     const=sum, default=max,
#                     help='sum the integers (default: find the max)')

parser.add_argument('file', type=str, help='Analysis record file')
parser.add_argument('--t', type=str, help='Analysis type')

args = parser.parse_args()
analysisFile = args.file
analysisType = args.t
# print(analysisType)

if (analysisType == 'cpp'):
	fileinfo = subprocess.check_output("cat %s | grep error| cut -d '[' -f2 | cut -d ']' -f1" % "*cppcheck.txt", shell=True).decode()
	seperator = ':'
elif (analysisType == 'ff'):
	fileinfo = subprocess.check_output("cat %s | grep ':  \['| grep -v 'ruleset' | awk -F':' '{print $1,$2}'" % "*flawfinder.txt", shell=True).decode()		
	seperator = ' '
else:
	print("Not a valid type. Try 'cpp' or 'ff'.")
	exit()	

funcSet = set()
for fi in fileinfo.splitlines():
	# print(fi)
	f_item = fi.split(seperator)
	fileName = f_item[0]
	lineNumber = f_item[1]
	# print(fileName)
# subprocess.check_output(['ls', '-l'])
# output = subprocess.check_output(['ctags', '-x', '--c-types=f', fileName]).decode()
# output = os.system('ctags -x --c-types=f %s | sort -k3 -n' % fileName)
	output = subprocess.check_output("ctags -x --c-types=f %s | sort -k3 -n -r | awk -F' ' '{print $1,$3}'" % fileName, shell=True).decode()

	# print(output.splitlines())

	for st in output.splitlines():
		item = st.split(' ')
		func = item[0]
		line = item[1]
		if int(line) < int(lineNumber):
			print(func, fileName, lineNumber)
			funcSet.add(func)
			break

for e in sorted(funcSet):
	print(e)			