#!/usr/bin/env python3

#MSProbe- a simple, straightforward MSP430 disasembler in Python
#http://mspgcc.sourceforge.net/manual/x223.html

#The MSP430 is reallllly nice for writing a disassembler.
#2 byte instructions only (although you have to deal with immediates)
#And only 27 instructions (with emulated instructions, 54)

import argparse
import sys

PC = 0 #Incremented by each disassembled instruction, incremented in words NOT bytes
asm = []
output = {}

def main():

	global PC #Get PC

	parser = argparse.ArgumentParser()
	parser.add_argument('assembly', nargs='?', default='', help='Assembled code object. Encapsulate in quotes.')
	parser.add_argument('-l', '--loadaddr', default='', help='Base instruction pointer for disassembly.')
	parser.add_argument('-mc', '--microcorruptionparse', default='', help='File to read Microcorruption hex dumps from.')
	args = parser.parse_args()

	if len(sys.argv) == 1:
		#Interpret commands from standard input to allow running as a file without command line
		arguments = input("Enter args: ")
		args = parser.parse_args(arguments.split())

	if args.microcorruptionparse != '':
		with open(args.microcorruptionparse) as f:
			pcBase, strinput = microcorruptionparse(f.read())
	else:
		pcBase, strinput = int(args.loadaddr, 16), args.assembly



	strinput = ''.join(strinput.split()) #First, let's remove spaces.
	for i in range(0, len(strinput), 4):
		part1 = strinput[i] + strinput[i + 1]
		part2 = strinput[i + 2] + strinput[i + 3]
		#Append word in little-endian format
		asm.append(int((part2 + part1), 16))

	while PC <= len(asm) - 1: #array index<->array length so - 1
		ins = asm[PC]
		insptr = PC #PC, as a global, ends up being incremented in the disassemble function
		output[insptr] = (ins, disassemble(ins))

	for currentPC, (ins, disasm) in output.items():
		#Deal with xrefs
		#This is a simple disassembler, with no detailed information
		#journaled. Jumps are the only thing xref'd within the scope
		#of this project. So this is fine.

		if disasm[0] == 'j':
			pcOffset = int(disasm[4:], 16) // 2 #Words vs bytes
			#Instruction address to output
			xrefInsAddress = hexrep(pcBase + (pcOffset * 2) + (currentPC * 2))
			jmpxref = xrefInsAddress + ' <' + output[currentPC + pcOffset][1] + '>'
			#Write new final disassembly
			disasm = disasm[0:4] + jmpxref + ' {' + disasm[4:] + '}'

		#Append the instruction address
		insAddress = hexrep(pcBase + (currentPC * 2))
		disasm = insAddress + ': ' + disasm

		print(disasm)


registerNames = ['pc', 'sp', 'sr', 'cg', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

def bitrep(number, bits = 16):
	"""Converts to binary form, fixing leading zeroes."""
	binstr = str(bin(number))[2:] #Remove 0b
	bitcount = len(binstr)
	leading0s = bits - bitcount
	return ('0' * leading0s) + binstr

def hexrep(number, zeroes = 4):
	"""Converts to hex form, fixing leading zeroes."""
	hexstr = hex(number)[2:]
	hexcount = len(hexstr)
	leading0s = zeroes - hexcount
	return ('0' * leading0s) + hexstr

def microcorruptionparse(inp):
	"""Convenience function to strip unnecessary stuff from Microcorruption hex dumps."""
	loadaddr = int(inp[0:4], 16)
	output = ""
	for i in inp.splitlines():
		#We only care about the bytes.
		output = output + i[7 : 7 + 40]
	return (loadaddr, output)

def disassemble(instruction):
	"""Main disassembly, calls other disassembly functions given a 2-byte instruction."""
	#Let's start by getting the binary representation.
	#Need to invert bytes because little endian.
	ins = bitrep(instruction)
	#What kind of instruction are we dealing with?
	if ins[0:3] == '001':
		return disassembleJumpInstruction(ins)
	elif ins[0:6] == '000100':
	  	return disassembleOneOpInstruction(ins)
	else:
		return disassembleTwoOpInstruction(ins)

oneOpOpcodes = ['rrc', 'swpb', 'rra', 'sxt', 'push', 'call', 'reti']
def disassembleOneOpInstruction(ins):
	"""Given a one-operand (format I) instruction in a 16-bit string, output disassembly."""
	global PC #Get PC

	bytemode = '.b' if ins[9] == '1' else ''
	opcodeID = int(ins[6:9], 2)
	opcode = oneOpOpcodes[opcodeID]
	reg = int(ins[12:], 2)

	adrmode = int(ins[10:12], 2)
	regOutput, extensionWord = disassembleAddressingMode(reg, adrmode)

	PC += 1 + (1 if extensionWord else 0)

	return opcode + bytemode + ' ' + regOutput

jumpOpcodes = ['jne', 'jeq', 'jlo', 'jhs', 'jn ', 'jge', 'jl ', 'jmp']
def disassembleJumpInstruction(ins):
	"""Given a jump instruction (format II) in a 16-bit string, output disassembly."""
	global PC #Get PC

	condition = int(ins[3:6], 2) #Get condition code from bits
	#Sign extend
	offset = ins[6] * 6 + ins[6:]
	signSubtract = 65536 if offset[0] == '1' else 0 #Sign bit
	pcOffset = ((int(offset, 2) - signSubtract) * 2) + 2

	#Add a plus if it's not negative for readability
	plus = '+' if signSubtract == 0 else ''

	PC += 1

	return jumpOpcodes[condition] + ' ' + plus + hex(pcOffset)

#Two-operand opcodes start at 4 (0b0100)
twoOpOpcodes = ['!!!', '!!!', '!!!', '!!!', 'mov', 'add', 'addc', 'subc', 'sub', 'cmp', 'dadd', 'bit', 'bic', 'bis', 'xor', 'and']
def disassembleTwoOpInstruction(ins):
	"""Given a two-operand instruction (format III) in a 16-bit string, output disassembly."""
	global PC #Get PC

	bytemode = '.b' if ins[9] == '1' else ''
	opcodeID = int(ins[0:4], 2)
	opcode = twoOpOpcodes[opcodeID]

	srcReg = int(ins[4:8], 2)
	srcAdrMode = int(ins[10:12], 2)

	regOutputSrc, extWordSrc = disassembleAddressingMode(srcReg, srcAdrMode)
	PC += 1 if extWordSrc else 0

	dstReg = int(ins[12:], 2)
	dstAdrMode = int(ins[8], 2)

	regOutputDst, extWordDst = disassembleAddressingMode(dstReg, dstAdrMode)
	PC += 1 if extWordDst else 0

	PC += 1 #Instruction word

	finalins = opcode + bytemode + ' ' + regOutputSrc + ', ' + regOutputDst

	#Disassemble pseudo (emulated) instructions

	#These are the easy ones to catch
	finalins = 'ret' if finalins == 'mov @sp+, pc' else finalins

	#Status register twiddling
	finalins = 'clrc' if finalins == 'bic #1, sr' else finalins
	finalins = 'setc' if finalins == 'bis #1, sr' else finalins
	finalins = 'clrz' if finalins == 'bic #2, sr' else finalins
	finalins = 'setz' if finalins == 'bis #2, sr' else finalins
	finalins = 'clrn' if finalins == 'bic #4, sr' else finalins
	finalins = 'setn' if finalins == 'bis #4, sr' else finalins
	finalins = 'dint' if finalins == 'bic #8, sr' else finalins
	finalins = 'eint' if finalins == 'bic #8, sr' else finalins
	#nop = mov dst, dst
	finalins = 'nop' if opcode == 'mov' and regOutputSrc == regOutputDst else finalins

	#These ones require a small amount of effort because it uses any register.
	#All of these are one-operand instructions, so if we need to reassemble
	#the instruction, it'll simply follow the one-operand format.

	reassembleins = True
	usesDest = True

	#Branch. Requires a little bit of extra sanity checking
	#because it could get mistaken for ret
	if opcode == 'mov' and regOutputDst == 'pc' and finalins != 'ret': #br = mov src, pc
		opcode = 'br'
		usesDest = False #We're actually using src here

	#Pop. Could also get mistaken for ret.
	elif opcode == 'mov' and regOutputSrc == '@sp+' and finalins != 'ret': #pop = mov @sp+, dst
		opcode = 'pop'

	#Shift and rotate left

	elif opcode == 'add' and srcReg == dstReg: #rla = add dst, dst
		opcode = 'rla'
	elif opcode == 'addc' and srcReg == dstReg: #rlc = addc dst, dst
		opcode = 'rlc'

	#Common one-operand instructions

	elif opcode == 'xor' and regOutputSrc == '#0xffff {-1}': #inv = xor 0xffff, dst
		opcode = 'inv'
	#Extra sanity checking to prevent being mistaken for nop
	elif opcode == 'mov' and regOutputSrc == '#0' and regOutputDst != '#0': #clr = mov #0, dst
		opcode = 'clr'
	elif opcode == 'cmp' and regOutputSrc == '#0': #tst = cmp #0, dst
		opcode = 'tst'


	#Increment and decrement (by one or two)

	elif opcode == 'sub' and regOutputSrc == '#1': #dec = sub #1, dst
		opcode = 'dec'
	elif opcode == 'sub' and regOutputSrc == '#2': #decd = sub #2, dst
		opcode = 'decd'
	elif opcode == 'add' and regOutputSrc == '#1': #inc = add #1, dst
		opcode = 'inc'
	elif opcode == 'add' and regOutputSrc == '#2': #incd = add #1, dst
		opcode = 'incd'

	#Add and subtract only the carry bit:

	elif opcode == 'addc' and regOutputSrc == '#0': #adc = addc #0, dst
		opcode = 'adc'
	elif opcode == 'dadd' and regOutputSrc == '#0': #dadc = dadd #0, dst
		opcode = 'dadc'
	elif opcode == 'subc' and regOutputSrc == '#0': #sbc = subc #0, dst
		opcode = 'sbc'

	#The instruction is not an emulated instruction
	else:
		reassembleins = False

	if reassembleins:
		finalins = opcode + bytemode + ' ' + (regOutputDst if usesDest else regOutputSrc)

	return finalins


adrModes = ['{register}', '{index}({register})', '@{register}', '@{register}+']

def disassembleAddressingMode(reg, adrmode):
	"""Outputs disassembly of a register's addressing mode and whether an extension
	word was used (to update PC accordingly in the calling function),
	given the register number and addressing mode number."""

	#http://mspgcc.sourceforge.net/manual/x147.html

	extensionWord = False

	#r2 (status register) and r3 (CG) are encoded as constant registers
	if reg == 2:
		if adrmode == 0: #Normal access
			regOutput = adrModes[adrmode].format(register=registerNames[reg])
		elif adrmode == 1: #Absolute address using extension word
			regOutput = '&' + hex(asm[PC + 1]) #Get next word
			extensionWord = True
		elif adrmode == 2:
			regOutput = '#4'
		elif adrmode == 3:
			regOutput = '#8'

	elif reg == 3:
		if adrmode == 0:
			regOutput = '#0'
		elif adrmode == 1:
			regOutput = '#1'
		elif adrmode == 2:
			regOutput = '#2'
		elif adrmode == 3:
			#Just a little reminder that all bits set == -1
			regOutput = '#0xffff {-1}'

	elif adrmode == 0:
		regOutput = adrModes[adrmode].format(register=registerNames[reg])

	elif adrmode == 1:
		regOutput = adrModes[adrmode].format(register=registerNames[reg], index=hex(asm[PC + 1]))
		extensionWord = True
	
	elif adrmode == 2:
		regOutput = adrModes[adrmode].format(register=registerNames[reg])
	
	elif adrmode == 3 and reg == 0: #PC was incremented for a constant
		regOutput = '#' + hex(asm[PC + 1])
		extensionWord = True
	
	elif adrmode == 3:
		regOutput = adrModes[adrmode].format(register=registerNames[reg])

	return (regOutput, extensionWord)

if __name__ == '__main__':
	main()