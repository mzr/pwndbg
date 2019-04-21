#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb
from os import path

import pwndbg.commands

# http://truthbk.github.io/gdb-ld_preload-and-libc/

@pwndbg.commands.Command
def preload(lib):
    """Sets exec-wrapper to 'env LD_PRELOAD=[specified library]'"""

    if pwndbg.proc.alive:
        print("proc is already running.")
        return

    if path.exists(lib):
        abs_path = path.realpath(lib)
        cmd = "set exec-wrapper env 'LD_PRELOAD=%s'" % abs_path
        gdb.execute(cmd)
    else:
        print("Specified library doesn't exist.")


@pwndbg.commands.Command
def unload():
    """Unsets exec-wrapper"""
    gdb.execute("unset exec-wrapper")

@pwndbg.commands.Command
def show_preloaded():
    """Shows exec-wrapper"""
    gdb.execute('show exec-wrapper')
