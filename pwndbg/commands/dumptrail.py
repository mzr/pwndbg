#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import gdb
import pwndbg.chain
import pwndbg.commands
import pwndbg.enhance
import pwndbg.file
import pwndbg.which
import pwndbg.wrappers.checksec
import pwndbg.wrappers.readelf
from pwndbg.color import message

parser = argparse.ArgumentParser(description='Show the state of the Global Offset Table')
parser.add_argument('filename', help='Filter results by passed name.',
                    type=str, nargs='?', default='')

from pwndbg.next import jumps

trails = {}

def dump_from_to(start, end, filename=None):
    iter_addr = start
    log = ""
    while iter_addr <= end:
        ins = pwndbg.disasm.one(iter_addr)
        # TUTAJ DUMPOWANIE
        #print('{}: {}'.format(hex(ins.address), ins.insn_name()))
        log += "0x%x:\t%s\t%s\n" %(ins.address, ins.mnemonic, ins.op_str)

        # TUTAJ DUMPOWANIE
        iter_addr = pwndbg.disasm.one(ins.next).address

    if filename:
        with open(filename, 'a') as f:
            f.write(log)
            f.write('\n')
    else:
        print(log)

def better_next_branch():
    ins = pwndbg.disasm.one(pwndbg.regs.pc)
    if set(ins.groups) & jumps:
        return ins
    return pwndbg.next.next_branch()

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def dumptrail(filename=''):
    current_addr = pwndbg.regs.rip

    nextjump_addr = better_next_branch().address
    dump_from_to(current_addr, nextjump_addr, filename=filename)
    return nextjump_addr

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def conttrail(filename=''):
    current_addr = pwndbg.regs.rip
    if current_addr not in trails:
        dumptrail(filename=filename)
        trails[current_addr] = 1
    pwndbg.next.break_next_branch()
    gdb.execute('stepi')


