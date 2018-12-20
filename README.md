# MSProbe- a simple, straightforward MSP430 disasembler in Python
This is a little disassembler I wrote to push myself in a couple days. It is extremely simple, and does exactly what it's supposed to. The feature list is short:

* Full disassembly of any MSP430 code object provided in raw hex format, including proper decoding of SR and CG immediates, proper decoding of extension words, and auto-detection of emulated instructions
* Jump instructions that "peek" at the instruction being jumped to, the address of the destination, and the jump offset
* Support for loading at a base address

Simple, and does exactly what it's supposed to do.

# Usage
No building is required, obviously. The command line arguments are as follows:

```
usage: msprobe.py [-h] [-b BASE] [assembly]

positional arguments:
  assembly              Assembled code object. Encapsulate in quotes.

optional arguments:
  -h, --help            show this help message and exit
  -b BASE, --base BASE  Base instruction pointer for disassembly.
```

If no command line arguments are provided, MSProbe will ask for code objects and the base pointer at runtime. This allows for usage without having to open a command line.

# Use cases
MSProbe may prove invaluable when tackling the [Microcorruption](https://microcorruption.com/login) Capture the Flag game, especially in certain levels where the disassembler provided is not sufficient (MSProbe's smart decoding of jump instructions will be especially useful in such cases).
In any other case where one needs to disassemble MSP430 code, MSProbe will be helpful.
It is also very well documented and commented, so anyone looking to write their own disassembler may find MSProbe the best resource to set out with.
