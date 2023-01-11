import sys
import pdb
import re

from typing import Callable

jumpOpcodes = ['jne', 'jeq', 'jlo', 'jhs', 'jn', 'jge', 'jl', 'jmp']
twoOpOpcodes = ['!!!', '!!!', '!!!', '!!!', 'mov', 'add', 'addc', 'subc', 'sub', 'cmp', 'dadd', 'bit', 'bic', 'bis', 'xor', 'and']
oneOpOpcodes = ['rrc', 'swpb', 'rra', 'sxt', 'push', 'call', 'reti']
emulatedOpcodes = {
'ret' : 'mov @sp+, pc',
'clrc' : 'bic #1, sr',
'setc' : 'bis #1, sr',
'clrz' : 'bic #2, sr',
'setz' : 'bis #2, sr',
'clrn' : 'bic #4, sr',
'setn' : 'bis #4, sr',
'dint' : 'bic #8, sr',
'eint' : 'bis #8, sr',
'nop'  : 'mov r3, r3', #Any register would do the same
'br'   : 'mov {reg}, pc',
'pop'  : 'mov @sp+, {reg}',
'rla'  : 'add {reg}, {reg}',
'rlc'  : 'addc {reg}, {reg}',
'inv'  : 'xor #0xffff, {reg}',
'clr'  : 'mov #0, {reg}',
'tst'  : 'cmp #0, {reg}',
'dec'  : 'sub #1, {reg}',
'decd' : 'sub #2, {reg}',
'inc'  : 'add #1, {reg}',
'incd' : 'add #2, {reg}',
'adc'  : 'addc #0, {reg}',
'dadc' : 'dadd #0, {reg}',
'sbc'  : 'subc #0, {reg}',
'jnc'  : 'jlo {reg}', #jlo, jhs are aliases of jnc, jc
'jnz'  : 'jne {reg}', #jnz, jz are aliases of jne, jeq
'jc'   : 'jhs {reg}',
'jz'   : 'jeq {reg}',
}

def bitrep(number, bits = 16):
	"""Converts to binary form, fixing leading zeroes."""
	mask = int('0b' + '1' * bits, 2)
	binstr = str(bin(number & mask))[2:]
	#negative = binstr[0] == '-'
	bitcount = len(binstr)
	leading0s = bits - bitcount
	return ('0' * leading0s) + binstr

def hexrep(number, zeroes = 4):
	"""Converts to hex form, fixing leading zeroes."""
	mask = int('0b' + '1' * (zeroes * 4), 2)
	hexstr = hex(number & mask)[2:]
	hexcount = len(hexstr)
	leading0s = zeroes - hexcount
	return ('0' * leading0s) + hexstr

class IllegalOpcodeException(Exception):
	"""
	`IllegalOpcodeException` is raised when an opcode mnemonic is not found in the opcode map
	"""
	def __init__(self, opcode):
		self.opcode = opcode

class AlreadyDefinedLabelException(Exception):
	"""
	`AlreadyDefinedLabelException` is raised when a label is defined multiple times in the same source file.
	Since labels are resolved after compilation, it cannot be known whether you intend to reference a past
	or future definition of a label.
	"""
	def __init__(self, label):
		self.label = label

class InvalidDirectiveException(Exception):
	"""
	`InvalidDirectiveException` is raised when a .directive is used which does not have an implementation.
	"""
	def __init(self, directive: str):
		self.directive = directive

class IllegalAddressingModeException(Exception):
	"""
	`IllegalAddressingModeException` is raised when the operand of an instruction is specified with an
	unrepresentable addressing mode.
	"""
	def __init__(self, adrmodeSrc, adrmodeDest):
		if adrmodeDest == 3:
			self.error = "\
Cannot use indirect with post-increment form for destination register. \
Because immediates are encoded as @pc+, immediates cannot be used for destinations \
(consider using & absolute addressing form instead)"
		#This might be wrong.
		elif adrmodeSrc != 0 and adrmodeDest != 0:
			self.error = "Cannot have a memory access in both source and destination"

class IllegalOffsetException(Exception):
	"""
	`IllegalOffsetException` is raised when a jump offset cannot be encoded.
	Jump offsets are a 12 bit signed integer representing the number of processor words to jump.
	As such, they can only encode jump offsets from -0x400 to +0x3ff
	"""
	def __init__(self, offset):
		self.offset = offset
		if offset % 2 != 0:
			self.error = "Cannot have odd offset: " + self.offset
		elif offset < -1022 or offset > 1024:
			self.error = "Offset too large for jump instruction. Boundaries are -1022 bytes through \
1024 bytes. Offset: " + self.offset

class InvalidRegisterException(Exception):
	"""
	`InvalidRegisterException` is raised when a register isn't one of
	[`pc`, `sp`, `sr`, `cg`, `r0`, ..., `r15`]
	"""
	def __init__(self, register: str):
		self.register = register

preprocessorHooks = []
"""
`preprocessorHooks` are functions which take a line from the source file, and return a line.
All registered hooks are called for each line of the source file.

Registering a `preprocessorHook` shall be done through the `registerPreprocessorHook` function.

Their signature is as follows:
```py
hook(instruction_line: str) -> str:
```
"""

postprocessorHooks = []
"""
postprocessorHooks are functions which act on the output stream as a monolithic entity.
Each postprocessorHook is called exactly once per source file, after assembly and before output.

Registering a `postprocessorHook` shall be done through the `registerPostprocessorHook` function.

Their signature is as follows:
```py
hook():
"""

PC = 0  #Incremented by each instruction, incremented in words NOT bytes
labels = {} #Label name and its PC location
"""
`labels` are a label name, followed by a the address of the label relative to the loadaddr
"""
defines = {} #Define name and its corresponding value
"""
`defines` are a search string and a replace string.

Example:
```MSProbe
.define foo bar
```
defines: {"foo": "bar"}
"""
jumps = {} #PC location of jump and its corresponding label
"""
`jumps` are the address of a jump instruction and its corresponding label
During jump resolution, each jump in jumps is modified with a relative offset
Example jump:
{0: "loop"}
"""
output = [] #Output hex

def asmMain(assembly, outfile=None, silent=False):
	lineNumber = 0
	global PC #Get PC

	outFP = open(outfile, 'w') if outfile else None

	if not assembly:
		#Provide a prompt for entry
		instructions = ''
		ins = ''
		print('Input assembly. Terminate input with the ".end" directive.')
		while True:
			ins = sys.stdin.readline()
			if ins == '.end\n':
				break
			instructions = instructions + ins
	else:
		with open(assembly) as fp:
			instructions = fp.read()


	for ins in instructions.splitlines():
		#Strip leading and trailing whitespace
		ins = ins.strip()
		ins = re.split(r'\s*[/;]', ins)[0] #Remove comments
		#Skip empty lines or lines beginning with a comment
		if len(ins) == 0 or ins.startswith((';', '//')):
			continue

		#Handle .directives
		if ins.startswith('.'):
			#Allow
			if ins.startswith(".define"):
				registerDefine(ins)
			continue

		#Handle preprocessor substitution hooks
		for hook in preprocessorHooks:
			ins = hook(ins)

		#Handle label registration
		if ':' in ins:
			try:
				registerLabel(ins)
			except AlreadyDefinedLabelException as exp:
				print('Label "' + exp.label + '" at line number ' + str(lineNumber + 1) + ' already defined')
				sys.exit(-1)
		else:
			try:
				assemble(ins)
			except IllegalOpcodeException as exp:
				highlight = ins.replace(exp.opcode, f"[{exp.opcode}]")
				print(f'Invalid opcode found on line {lineNumber + 1}: "{highlight}"')
				sys.exit(-1)
			except IllegalAddressingModeException as exp:
				print(f'Addressing mode error found on line {lineNumber + 1}: "{exp.error}"')
				sys.exit(-1)
			except IllegalOffsetException as exp:
				print(f'Invalid jump offset error found on line {lineNumber + 1}: "{exp.error}"')
				sys.exit(-1)
			except InvalidRegisterException as exp:
				highlight = ins.replace(exp.register, f"[{exp.register}]");
				print(f'Invalid register mneumonic on line {lineNumber + 1}: "{highlight}"',
					   'Valid registers are pc, sp, sr, cg, or r0-r15.', sep="\n")
				sys.exit(-1)

		lineNumber += 1

	#Handle postprocessor hooks.
	#These functions manipulate the raw output data, and perform tasks such as link resolution
	for postprocessorHook in postprocessorHooks:
		postprocessorHook()

	#Output the object as hex
	for i in output:
		if not silent:
			print(hexrep(i), end='', file=sys.stdout)# + ' (' + bitrep(i, 16) + ')')
		if outFP:
			print(hexrep(i), end='', file=outFP)
	print('') #End hex representation with a newline
	if outFP:
		outFP.close()

def registerPreprocessorHook(hook: Callable):
	if hook not in preprocessorHooks:
		preprocessorHooks.append(hook)

def registerPostprocessorHook(hook: Callable):
	if hook not in postprocessorHooks:
		postprocessorHooks.append(hook)

def processDirectives(ins: str) -> str:
	pass

def resolveJumps():
	"""Resolve pending jumps in the jumps list"""
	global labels, jumps, output
	#Resolve jump labels
	for pc, label in jumps.items():
		try:
			labelpos = labels[label]
		except KeyError:
			print(f'Label "{label}" does not exist, but a jump instruction attempts to jump to it')
			sys.exit(-1)
		#Modify the jump instruction
		#Get in little-endian format
		ins = hexrep(output[pc])
		ins = int(ins[2:4] + ins[0:2], 16)
		ins = [bit for bit in bitrep(ins, 16)]
		offset = (labelpos - pc) * 2 #Words versus bytes
		#Jump offsets are multiplied by two, added by two (PC increment), and sign extendedB
		ins[6:] = bitrep((offset - 2) // 2, 10)
		#Output again in little endian
		strword = hexrep(int(''.join(str(e) for e in ins), 2), 4)
		output[pc] = int(strword[2:] + strword[0:2], 16)

#TODO: Resolve labels in calls

def registerLabel(ins: str):
	"""Registers a label for later replacement"""
	global labels #Get labels
	global PC #Get PC
	label, addr = ins.split(sep=':')
	if label in labels:
		raise AlreadyDefinedLabelException(label)
	registerPostprocessorHook(resolveJumps)

# -- Defines --
def resolveDefines(ins: str) -> str:
	global defines
	for define in defines:
		ins = ins.replace(define, defines[define])
	return ins

def registerDefine(ins: str):
	"""
	Registers a define for replacement on subsequent lines
	A define is of format
	```asm
	.define identifier text...
	"""
	global defines, preprocessorHooks
	if 'defines' not in globals():
		defines = {}
	#Define is of format .define [identifier] [any text]
	#Space(s) not required, but if spaces are not used, ':' or '=' must be used in its place
	define: tuple = re.match(r'.define\s*(\w+)[\s:=]+(.*)\s*', ins).groups()
	if define != ():
		label, replacement = define
		defines[label] = replacement
		registerPreprocessorHook(resolveDefines)

def registerJumpInstruction(PC, label):
	"""Defer jump offset calculation until labels are defined"""
	global jumps #Get jump instructions
	jumps[PC] = label

def assemble(ins):
	"""Assemble a single instruction, and append results to the output stream."""
	opcode, notUsed = getOpcode(ins)
	if opcode in jumpOpcodes:
		return assembleJumpInstruction(ins)
	elif opcode in oneOpOpcodes:
		return assembleOneOpInstruction(ins)
	elif opcode in twoOpOpcodes:
		return assembleTwoOpInstruction(ins)
	elif opcode in emulatedOpcodes:
		return assembleEmulatedInstruction(ins)
	else:
		raise IllegalOpcodeException(opcode)

def assembleEmulatedInstruction(ins):
	"""Assembles a zero- or one-operand 'emulated' instruction."""
	#Emulated instructions are either zero or one operand instructions.
	opcode, notUsed = getOpcode(ins)
	if '{reg}' in emulatedOpcodes[opcode]:
		register = ins[ins.find(' ') + 1 : ]
		ins = emulatedOpcodes[opcode].format(reg=register)
	else:
		ins = emulatedOpcodes[opcode]
	return assemble(ins)

def assembleOneOpInstruction(ins):
	"""Assembles a one-operand (format I) instruction."""
	out = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
	out[0:6] = '000100' #One op identifier

	opcode, byteMode = getOpcode(ins)
	out[6:9] = bitrep(oneOpOpcodes.index(opcode), 3)
	out[9] = bitrep(byteMode, 1)

	#Figure out where the operand is
	start = ins.find(' ') + 1
	reg = ins[start :]

	#We need to provide the opcode here to detect the push bug; see the function itself
	extensionWord, adrmode, regID = assembleRegister(reg, opcode=opcode)

	out[10:12] = bitrep(adrmode, 2)
	out[12:] = bitrep(regID, 4)
	appendWord(int(''.join(str(e) for e in out), 2))
	if extensionWord:
		appendWord(int(extensionWord, 16))

def assembleTwoOpInstruction(ins):
	"""Assembles a two-operand (format III) instruction."""
	out = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

	opcode, byteMode = getOpcode(ins)
	out[0:4] = bitrep(twoOpOpcodes.index(opcode), 4)
	out[9] = bitrep(byteMode, 1)

	#Find the location of the first operand
	start = ins.find(' ') + 1
	end = ins.find(',')
	regSrc = ins[start : end]

	extensionWordSrc, adrmodeSrc, regIDSrc = assembleRegister(regSrc)

	out[10:12] = bitrep(adrmodeSrc, 2)
	out[4:8] = bitrep(regIDSrc, 4)

	#Figure out where the comment is
	start = end + 2 #Right after the comma, and the space after the comma
	regDest = ins[start :]

	extensionWordDest, adrmodeDest, regIDDest = assembleRegister(regDest, isDestReg = True)

	out[8] = bitrep(adrmodeDest, 1)
	out[12:] = bitrep(regIDDest, 4)

	appendWord(int(''.join(str(e) for e in out), 2))
	if extensionWordSrc:
		appendWord(int(extensionWordSrc, 16))
	if extensionWordDest:
		appendWord(int(extensionWordDest, 16))

def assembleJumpInstruction(ins):
	"""Assembles a jump instruction. If the offset is supplied, it is assembled
	immediately. Otherwise, if a label is provided, resolution of the offset is delayed
	so that all labels can be read (including those further ahead in the instruction stream)."""
	out = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
	out[0:3] = '001' #Jump identifier
	opcode, byteMode = getOpcode(ins)

	if byteMode: #Cannot have "jmp.b", how does that even make sense
		raise IllegalOpcodeException(opcode + '.b')

	out[3:6] = bitrep(jumpOpcodes.index(opcode), 3)

	#Figure out where the operand is
	start = ins.find(' ') + 1
	dest = ''.join(ins[start :].split()) #Remove whitespace

	#Immediate offset
	char1 = dest[0]
	#Is this a number?
	if re.match(r'[+\-]?[0x|0b]?[0-9A-Fa-f]+', dest):
		offset = int(dest, 16)
		if offset % 2 != 0:
			raise IllegalOffsetException(offset)
		#Jump offsets are multiplied by two, added by two (PC increment), and sign extended
		out[6:] = bitrep((offset - 2) // 2, 10)
	else:
		registerJumpInstruction(PC, dest)

	appendWord(int(''.join(str(e) for e in out), 2))



def getRegister(registerName: str):
	"""Decodes special register names (or normal register names)."""
	registerName = registerName.strip().lower() #Strip leading and trailing whitespace, and convert to lowercase
	specialRegisterNames = {'pc': 0, 'sp': 1, 'sr': 2, 'cg': 3}
	if registerName in specialRegisterNames:
		return specialRegisterNames[registerName]
	elif registerName.startswith('r'):
		#FIXME: this allows registers with any integer name
		return int(registerName[1:]) #Remove 'r'
	else:
		raise InvalidRegisterException(registerName)


def getOpcode(ins: str):
	"""Returns the opcode and whether byte mode is being used."""
	#Split the opcode on characters that can't be used in an identifier
	#Example: [mov].b r15, r15
	opcode = re.split(r'[\.\W]', ins)[0]
	byteMode = False
	if '.b' in ins:
		byteMode = True
	return opcode, byteMode

def appendWord(word):
	"""Add a word to the output instruction stream, handling little endian format."""
	global PC #Get PC
	global output #Get output
	#Append in little-endian format
	strword = hexrep(word, 4)
	output.append(int(strword[2:] + strword[0:2], 16))
	PC += 1

def assembleRegister(reg, opcode=None, isDestReg = False):
	"""Assembles an operand, returning the extension word used (if applicable),
	the addressing mode, and the register ID."""
	extensionWord = None
	adrmode = 0
	regID = 0

	if '(' in reg: #Indexed mode (mode 1)
		extensionWord = reg[0 : reg.find('(')]
		adrmode = 1
		regID = getRegister(reg[reg.find('(') + 1 : reg.find(')')])
	elif '@' in reg and '+' in reg: #Indirect with post-increment mode (mode 3)
		#Destinations don't support indirect or indirect + post-increment.
		if isDestReg:
			raise IllegalAddressingModeException(0, reg)
		adrmode = 3
		regID = getRegister(reg[reg.find('@') + 1 : reg.find('+')])
	elif '@' in reg: #Indirect mode (mode 2)
		#Destinations don't support indirect or indirect + post-increment.
		#Indirect can be faked with an index of 0. What a waste.
		if isDestReg:
			adrmode = 1
			extensionWord = 0
		else:
			adrmode = 2
			regID = getRegister(reg[reg.find('@')+1 : ])
	elif '#' in reg: #Use PC to specify an immediate constant
		if isDestReg:
			raise IllegalAddressingModeException(0, reg)
		adrmode = 3
		regID = 0
		constant = reg[reg.find('#') + 1 :]

		#This might be an immediate constant supported by the hardware

		#A CPU bug prevents push #4 and push #8 with r2/SR encoding from working,
		#so one must simply use a 16-bit immediate there (what a waste, again)
		if constant == '4' and opcode != 'push':
			regID = 2
			adrmode = 2
		elif constant == '8' and opcode != 'push':
			regID = 2
			adrmode = 3
		elif constant == '0':
			regID = 3
			adrmode = 0
		elif constant == '1':
			regID = 3
			adrmode = 1
		elif constant == '2':
			regID = 3
			adrmode = 2
		elif constant == '-1' or constant.lower() == '0xffff':
			regID = 3
			adrmode = 3
		else:
			extensionWord = constant
	elif '&' in reg: #Direct addressing. An extension word is fetched and used as the raw address.
		regID = 2
		adrmode = 1
		extensionWord = reg[reg.find('&') + 1 : ]
	else: #Regular register access (mode 0)
		adrmode = 0
		regID = getRegister(reg)

	return extensionWord, adrmode, regID
