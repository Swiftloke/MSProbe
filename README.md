# MSProbe- a simple, straightforward MSP430 assembler and disasembler in Python
MSProbe is a two-in-one assembler and disassembler for the MSP430 processor. The features of both are listed below:

The disassembler was originally written to push myself in a couple days. The feature set is reasonably small, but it is fleshed out enough to certainly provide a valuable aid.

* Full disassembly of any MSP430 code object provided in raw hex format, including proper decoding of SR and CG immediates, proper decoding of extension words, and auto-detection of emulated instructions
* On top of reading raw hex, MSProbe can also read hex dumps copy/pasted from the Microcorruption CTF (See below)
* Hex instructions can be read either from a file or from an interactive prompt at the command line.
* Jump instructions that "peek" at the instruction being jumped to, the address of the destination, and the jump offset
* Support for loading at a base address
* Support for writing to an output file

The assembler was written in about two weeks. The feature set is as follows:

* Full assembly of MSP430 assembly language, including:
* SR and CG immediates
* Jumping to labels and byte offsets
* Emulated instructions
* Extension words
* Byte mode
* Comments (both ';' and '//')
* Special register names (pc, sp, sr, cg)

Generally speaking, you can just write code and it will work. There are a few things worth mentioning for usage:
* Labels are defined on a single line by typing the label name and ending it with a colon (':').
* Jump instructions can jump either to a raw byte offset (what the MSP430 supports) or to a label, the offset of which will be resolved by the assembler. However, if the offset is odd or too large (the MSP430 supports a range of -1022 to +1024 bytes) an exception will be thrown.
* The MSP430 does not allow specifying a '#' form immediate constant as a destination. As an alternative, use the '&' form, like so: ``mov r8, &0x1337``
* Immediates and jump offsets are always in hex, even if a '0x' is not supplied.
* Comments can be written at any point after an instruction or label. They begin with ';' or '//', whichever you prefer (and the two forms can be used at different points in the same file)
* For a reference to MSP430 assembly language, see [here](http://mspgcc.sourceforge.net/manual/c68.html) through [here](http://mspgcc.sourceforge.net/manual/x223.html).



# Usage
No building is required, obviously. The command line arguments are as follows:

```
usage: msprobe.py [-h] [-l LOADADDR] [-o OUTPUT] [-s] {disasm,asm} ...

positional arguments:
  {disasm,asm}          Options for disassembly or assembly.
    disasm              File to read assembled code object from, in text hex
                        format. If not provided, a prompt will be provided to
                        read from sys.stdin. If -mc is provided, the file will
                        be parsed as a Microcorruption hex dump.
    asm                 File to read assembly code from. If not provided, a
                        prompt will be provided to read from sys.stdin.

optional arguments:
  -h, --help            show this help message and exit
  -l LOADADDR, --loadaddr LOADADDR
                        Base instruction pointer for (dis)assembly. The
                        default address is 0.
  -o OUTPUT, --output OUTPUT
                        File to output (dis)assembly to.
  -s, --silent          Do not output (dis)assembly to stdout.
```

If no command line arguments are provided, MSProbe will ask for them at runtime through sys.stdin. This allows for usage without having to open a command line. If "disasm" or "asm" are specified without a file to read from, a prompt will be opened. For disassembly, a code object in text hex will be expected. For assembly, one can write code line by line and end input by writing '.end'.

# Use cases
MSProbe may prove invaluable when tackling the [Microcorruption](https://microcorruption.com/login) Capture the Flag game, especially in certain levels where the disassembler and assembler provided is not sufficient (MSProbe's smart decoding of jump instructions will be especially useful in such cases). MSProbe can function as, and was written as, a complete replacement for the built-in disassembler/assembler.
In any other case where one needs to disassemble and assemble MSP430 code, MSProbe will be helpful.
It is also very well documented and commented, so anyone looking to write their own disassembler and/or assembler. may find MSProbe the best resource to set out with.
