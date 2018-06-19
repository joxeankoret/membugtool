#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Part of Nightmare Fuzzing Project
@author: joxean
"""

import os
import sys
import time
import thread

DEBUG = False

#-----------------------------------------------------------------------
def debug(msg):
  if DEBUG:
    log(msg)

#-----------------------------------------------------------------------
def log(msg):
  print "[%s %d:%d] %s" % (time.asctime(), os.getpid(), thread.get_ident(), msg)
  sys.stdout.flush()
