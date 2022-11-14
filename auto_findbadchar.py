import argparse
import sys
import socket
import subprocess
import time
import re


DBG = False

### adjust import modules
TMP_FOLDER="C:\\Temp"
SCR_FOLDER="C:\\scripts"
OSED_FOLDER="{}\\OSED_scripts".format(SCR_FOLDER)

sys.path.append(OSED_FOLDER)

import map_shared_mem_example as msh
from constants import t_sleep, READY_OPCODE, CLEAN_OPCODE, HOST_REPLACE, PORT_REPLACE ,\
                      powershell_path, PY_PATH

auto_windbg_py = "{}\\auto_windbg.py".format(OSED_FOLDER)
compare_in_memory_py = "{}\\compare_in_memory.py".format(OSED_FOLDER)


try :
  fp = open("{}\\prefix.txt".format(TMP_FOLDER), "rb")
  HDR = fp.read()
  fp.close()
except :
  print("[!] Can't find 'prefix.txt' inside tmp folder '{}', instead using default prefix")
  output = [
    "POST /login HTTP/1.1" ,\
    "Host: {}:{}".format(HOST_REPLACE, PORT_REPLACE) ,\
    "User-Agent: Mozilla/5.0" ,\
    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ,\
    "Accept-Language: en-US,en;q=0.5" ,\
    "Accept-Encoding: gzip, deflate" ,\
    "Content-Type: application/x-www-form-urlencoded" ,\
    "Referer: http://{}:{}/login\r\n".format(HOST_REPLACE, PORT_REPLACE)
  ]
  HDR = "\r\n".join(output)


def check_blacklist_bytes(list_bytes):
  regular_hex_list = r"([ ,0-9\[\]xXA-f]+)"
  reg_now = regular_hex_list
  var_now = list_bytes
  if len(re.match(reg_now, var_now).groups()[0]) != len(var_now) :
    print("[x] Invalid blacklist bytes given ..quit")
    sys.exit(-1)
  ret = eval(var_now)
  gt_list = [str(x) for x in ret if x > 255]
  if gt_list :
    print("[x] Value greater than 255 ([{}]) was given inside the blacklist bytes list ..quit".format(",".join(gt_list)))
    sys.exit(-1)
  return ret


def make_request(HOST, PORT, append):
  buff = HDR.replace(HOST_REPLACE, HOST).replace(PORT_REPLACE, str(PORT))
  buff += append
  b = bytearray()
  b.extend(buff)
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((HOST,PORT))
  s.send(b)
  s.close()


def clear_shared_mem(pBuf):
  buff = bytearray(CLEAN_OPCODE + CLEAN_OPCODE)
  msh.write_msg(pBuf, buff, len(buff))


def read_msg(pBuf, size, prefix, ignore_ready_opcode=False):
  rets = ""
  size += len(READY_OPCODE) + len(prefix)
  if not ignore_ready_opcode :
    while True :
      rets = msh.read_msg(pBuf, size)
      if not rets.startswith("".join([chr(x) for x in READY_OPCODE])) :
          time.sleep(t_sleep)
      else :
        rets = rets[len(READY_OPCODE):]
        if not rets.startswith(prefix) :
          clear_shared_mem(pBuf)
          time.sleep(t_sleep)
        else :
          rets = rets[len(prefix):]
          break
  #
  clear_shared_mem(pBuf)
  return rets


def is_alive_proc(proc_name) :
  ret_val = False
  ret = subprocess.check_output("{} (Get-Process {}).Id".format(powershell_path, proc_name), shell=True).strip()
  if not "Cannot find a process with the name" in ret :
    ret_val = True
  return ret_val


def find_bad_char(HOST, PORT, cmd_exec, proc_name, prefix, blacklist_bytes):
  hMapFile, pBuf = msh.open_shared_mem(do_create=True)
  read_msg(pBuf, 0, prefix, ignore_ready_opcode=True)
  blacklist_char = set(blacklist_bytes)

  while True :

    valid_char = set([x for x in range(256)]) - blacklist_char
    if not is_alive_proc(proc_name) :
      print("[!] proc '{}' is dead ..restarting it".format(proc_name))
      subprocess.Popen(cmd_exec)
      print("[exec] ", cmd_exec)
      raw_input("press [enter] after all is ready")

    buff_now = bytearray(valid_char)
    buff_now_str = "".join([chr(x) for x in buff_now])

    # BEGIN
    content = "password=A&username=" + prefix + buff_now_str
    content_length = "Content-Length: {}\r\n".format(len(content))
    tmpData = content_length + "\r\n" + content
    # END

    make_request(HOST, PORT, tmpData)
    rets = read_msg(pBuf, len(buff_now), prefix)
    bad_byte = do_check(sent_buffer=buff_now_str, recv_buffer=rets)
    if bad_byte == None :
      break
    #
    blacklist_char.add(bad_byte)
    if DBG :
      print("[!] blacklist bytes now: ", blacklist_char)

  print("[+] Blacklist bytes result: [{}]".format(",".join([hex(x) for x in blacklist_char])))
  msh.remove_shared_mem(hMapFile, pBuf)


def do_check(sent_buffer="", recv_buffer="") :
  """
    As default this function do byte-a-byte comparison 
    of the sent and received data.

    returns a bad byte spotted, None if no bad bytes were found
  """
  if DBG :
    print("#### Comparing:")
    print("Sent:",sent_buffer)
    print("Received:",recv_buffer)
    print("")

  ret = None
  for i,x in enumerate(sent_buffer) :
    if x != recv_buffer[i] :
      ret = ord(x)
      print("Found bad byte '0x{:x}'".format(ret))
      break
  return ret



if __name__ == "__main__" :
  example_usage = \
    "Example usage:\n" \
    "C:\Python27\python.exe C:\scripts\OSED_scripts\\auto_findbadchar.py --host 127.0.0.1 " \
    "--port 80 -p syncbrs -s 'Sync Breeze Enterprise' --addr libpal+0x14ea6 --cmd \"poi(esp+0x8)\""

  parser = argparse.ArgumentParser(description="Find bad chars \"automatically\"\n{}".format(example_usage))
  #
  parser.add_argument("--host", default="127.0.0.1", help="Ip address target (default: 127.0.0.1)")
  parser.add_argument("--port", type=int, help="Port target (default: 80)")
  parser.add_argument("-s", "--service", help="Service to restart")
  parser.add_argument("-p", "--proc_name", required=True, help=
    "Process name to attach with windbg\n" +\
    "If the process is dead then restart it using the argument '--service'\n" +\
    "If argument '--service' is not given, then use '--binary_path'")
  parser.add_argument("-b", "--binary_path", help="Service to restart")
  parser.add_argument("--addr", required=True, help="Breakpoint address. Can be a constante or <module_name>+<offset> if aslr is present")
  parser.add_argument("--cmd", required=True, help="Windbg expression for retrieving the address where to compy from (e.g. poi(esp+0x10))")
  parser.add_argument("--prefix", default="OOOK", help="In order to be sure the msg was correctly sent, a prefix string is inserted with the input")
  parser.add_argument("--bad_bytes", default="[0, 0xa, 0xd]", help="Default blacklist bytes. Input is given as list (e.g. \"[0,0x1,100]\"")
  parser.add_argument("--debug", default=False, action="store_true", help="Enable debug mode (default: False)")
  args = parser.parse_args()
  # parse arguments
  args_out_l = ["--service", "--proc_name", "--binary_path"]
  args_out_l2 = []
  for x in args_out_l :
    y = x.split("--")[1]
    arg_y = getattr(args,y)
    if arg_y != None :
      args_out_l2.append(x)
      args_out_l2.append(arg_y)

  args_out_l2.append("-c")
  args_out_l2.append(
    "'!py {} --addr {} --cmd {}'".format(
      compare_in_memory_py,
      args.addr,
      args.cmd)
  )
  cmd_exec = [PY_PATH, auto_windbg_py] + args_out_l2
  blacklist_bytes = check_blacklist_bytes(args.bad_bytes)
  DBG = args.debug

  print("[!] start")
  valid_chars = find_bad_char(
    args.host, 
    args.port, 
    cmd_exec, 
    args.proc_name, 
    args.prefix,
    blacklist_bytes
  )
  print("[+] Done")


