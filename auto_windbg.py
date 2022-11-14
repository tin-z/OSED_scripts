import argparse
import subprocess
import sys
import time

### adjust import modules
TMP_FOLDER="C:\\Temp"
SCR_FOLDER="C:\\scripts"
OSED_FOLDER="{}\\OSED_scripts".format(SCR_FOLDER)

sys.path.append(OSED_FOLDER)

import map_shared_mem_example as msh
from constants import powershell_path, windbg_path, prepend_cmd ,\
                      t_sleep_2



### example usage
# > C:\Python27\python.exe C:\scripts\OSED_scripts\auto_windbg.py -p syncbrs -s 'Sync Breeze Enterprise' -c "!teb"


### parse input
parser = argparse.ArgumentParser()
parser.add_argument("-s", "--service", help="Service to restart")
parser.add_argument("-p", "--proc_name", required=True, help=
  "Process name to attach with windbg\n" +\
  "If the process is dead then restart it using the argument '--service'\n" +\
  "If argument '--service' is not given, then use '--binary_path'")
parser.add_argument("-b", "--binary_path", help="Service to restart")
parser.add_argument("-c", "--commands", default="", help="Commands to execute after windbg has been launched")
#
args = parser.parse_args()
service = args.service
proc_name = args.proc_name
binary_path = args.binary_path
cmd = args.commands.strip()


### methods
def get_pid(proc_name):
  PID = -1
  ret = subprocess.check_output("{} (Get-Process {}).Id".format(powershell_path, proc_name), shell=True).strip()
  if not "Cannot find a process with the name" in ret :
    PID = int(ret)
  return PID

def restart_service(service):
  subprocess.call('{} "Restart-Service -Name \\"{}\\" "'.format(powershell_path, service), shell=True)


### Main
assert(proc_name != None)
PID = get_pid(proc_name)

if PID < 0 :
  if (service == None) :
    assert(binary_path != None)
    subprocess.Popen([binary_path])

  else :
    restart_service(service) 
    PID = get_pid(proc_name)

time.sleep(t_sleep_2)
PID = get_pid(proc_name)
if PID < 0 :
  print("[x] after restarting service/binary still no process-name '{}' was found ..quit".format(proc_name))
  sys.exit(-1)

if cmd == "" :
  cmd = prepend_cmd
else :
  cmd = prepend_cmd + "; " + cmd.replace("'","")

cmd = [windbg_path, "-p", str(PID), "-c", cmd]

print("[!] launched: {}".format(" ".join(cmd)))
subprocess.Popen(cmd)
print("[+] Done")

