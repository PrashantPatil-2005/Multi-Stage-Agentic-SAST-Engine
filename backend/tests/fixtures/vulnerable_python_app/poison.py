# This file must never be executed. It contains top-level code that would be
# harmful if run. The SAST engine must only parse it, never import or run it.
import sys
import os

flag = True
sys.exit(1)
os.remove("sast_should_never_run.txt")
