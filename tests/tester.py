#!/usr/bin/python

import sys
import time
import ConfigParser

from nfp_log import log, debug
from nfp_process import TimeoutCommand

#-----------------------------------------------------------------------
class CTester:
  def __init__(self, cfg_file):
    self.cfg_file = cfg_file
    self.pin_path = None
    self.tool_path = None
    self.test_cases = {}
    self.failed = False
    self.read_config()

  def read_config(self):
    parser = ConfigParser.SafeConfigParser()
    parser.optionxform = str
    parser.read(self.cfg_file)

    section = "Tester"
    sections = parser.sections()
    if section not in sections:
      raise Exception("Section %s does not exists in the given configuration file" % section)

    try:
      self.pin_path = parser.get(section, 'pin-path')
    except:
      raise Exception("No 'pin-path' specified!")

    try:
      self.tool_path = parser.get(section, 'tool-path')
    except:
      raise Exception("No 'tool-path' specified!")

    try:
      self.tool_name = parser.get(section, 'tool-name')
    except:
      raise Exception("No 'tool-name' specified!")

    try:
      self.testcases_directory = parser.get(section, 'test-cases-directory')
    except:
      raise Exception("No 'test-cases-directory' specified!")

    for section in sections:
      if section == "Tester":
        continue

      try:
        track_lines = parser.get(section, 'track-lines')
        track_return = parser.get(section, 'track-return')
        mitigate_lines = parser.get(section, 'mitigate-lines')
        mitigate_return = parser.get(section, 'mitigate-return')

        self.test_cases[section] = [track_lines, track_return, mitigate_lines, mitigate_return]
      except:
        print "Error reading test-case %s: %s" % (section, sys.exc_info()[1])

  def run_test(self, name, data):
    track_lines = int(data[0])
    track_return = int(data[1])
    mitigate_lines = int(data[2])
    mitigate_return = int(data[3])
    
    args = ["-track 1", "-track 1 -mitigate 1"]
    archs = ["ia32", "intel64"]
    for arch in archs:
      failed = False
      tmp_cmd = "%s/pin -t %s/obj-%s/%s" % (self.pin_path, self.tool_path, arch, self.tool_name)
      for arg in args:
        suffix = ""
        if arch == "ia32":
          suffix = "32"
        cmd = "%s %s -- %s/%s%s" % (tmp_cmd, arg, self.testcases_directory, name, suffix)
        debug("Running %s" % cmd)
        t = TimeoutCommand(cmd)
        code = t.run(get_output=True)
        stdout = t.stdout

        if arg.find("mitigate") == -1:
          if code != track_return:
            failed = True
            line = "*** TEST %s FAILED *** Different return code for tracker: got %d, expected %d"
            log(line % (repr(name), code, track_return))
            print "-"*80
            print repr(stdout)
            print "-"*80

          lines = stdout.count("\n")
          if lines != track_lines:
            failed = True
            line = "*** TEST %s FAILED *** Different number of lines for tracker: got %d, expected %d"
            log(line % (repr(name), lines, track_lines))
            print "-"*80
            print repr(stdout)
            print "-"*80
        else:
          if code != mitigate_return:
            failed = True
            line = "*** TEST %s FAILED *** Different return code for mitigator: got %d, expected %d"
            log(line % (repr(name), code, mitigate_return))
            print "-"*80
            print repr(stdout)
            print "-"*80

          lines = stdout.count("\n")
          if lines != mitigate_lines:
            failed = True
            line = "*** TEST %s FAILED *** Different number of lines for mitigator: got %d, expected %d"
            log(line % (repr(name), lines, mitigate_lines))
            print "-"*80
            print repr(stdout)
            print "-"*80

        if not failed:
          test_type = "tracker"
          if arg.find("mitigate") == -1:
            test_type = "mitigator"
          log("TEST %s FOR %s ARCH %s PASSED" % (repr(name), test_type, arch))
        else:
          self.failed = True

  def test(self):
    debug("Running tests...")
    for test in self.test_cases:
      data = self.test_cases[test]
      self.run_test(test, self.test_cases[test])
    debug("Done")

#-----------------------------------------------------------------------
def usage():
  print "Usage:", sys.argv[0], "<config file>"

#-----------------------------------------------------------------------
def main(cfg_file):
  tester = CTester(cfg_file)
  tester.test()
  if tester.failed:
    sys.exit(1)
  sys.exit(0)

if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main(sys.argv[1])
