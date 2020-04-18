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
parser.add_argument('name_filter', help='Filter results by passed name.',
                    type=str, nargs='?', default='')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def mprotect(name_filter=''):
    '''
    pushad
    mov eax, mprotect_syscall_num
    mov ebx, address_of_the_page
    mov ecx, size_of_the_page
    mov edx, permission_to_set
    int 0x80
    popad
    '''
    saved_rax = pwndbg.regs.rax
    saved_rbx = pwndbg.regs.rbx
    saved_rcx = pwndbg.regs.rcx
    saved_rdx = pwndbg.regs.rdx
    saved_rip = pwndbg.regs.rip

    # pwndbg.regs.eax = 0x7d # mprotect
    # pwndbg.regs.ebx = 0x400000
    # pwndbg.regs.ecx = 0x1000
    # pwndbg.regs.edx = 0x5 # PROT_READ|PROT_EXEC
    gdb.execute('set $rax=0x7d')
    gdb.execute('set $rbx=0x400000')
    gdb.execute('set $rcx=0x1000')
    gdb.execute('set $rdx=0x5')

    saved_instruction_2bytes = pwndbg.memory.read(pwndbg.regs.rip, 2)

    # int 0x80
    pwndbg.memory.write(pwndbg.regs.rip, b'\xcd\x80')

    gdb.execute('stepi')

    # now restore
    pwndbg.memory.write(saved_rip, saved_instruction_2bytes)

    gdb.execute('set $rax={}'.format(saved_rax))
    gdb.execute('set $rbx={}'.format(saved_rbx))
    gdb.execute('set $rcx={}'.format(saved_rcx))
    gdb.execute('set $rdx={}'.format(saved_rdx))
    gdb.execute('set $rip={}'.format(saved_rip))

    pwndbg.regs.rax = saved_rax
    pwndbg.regs.rbx = saved_rbx
    pwndbg.regs.rcx = saved_rcx
    pwndbg.regs.rdx = saved_rdx
    pwndbg.regs.rip = saved_rip


