import sys
import pykd
import argparse
import time

### adjust import modules
TMP_FOLDER="C:\\Temp"
SCR_FOLDER="C:\\scripts"
OSED_FOLDER="{}\\OSED_scripts".format(SCR_FOLDER)

sys.path.append(OSED_FOLDER)

import map_shared_mem_example as msh
from constants import READY_OPCODE, t_sleep, DBG


def eval_windbg(cmd) :
  rets = pykd.dbgCommand("? " + cmd)
  addr = int("0x" + rets.split("Evaluate expression: ")[1].split("=")[1].strip(), 16)
  return addr


class HitBP(pykd.eventHandler):

  def __init__(self, addr, cmd):
    if "+" in addr :
      addr = eval_windbg(addr)

    self.addr = addr
    self.cmd = cmd 
    self.hndl, self.pBuf = msh.open_shared_mem()
    self.bp_init = pykd.setBp(self.addr, self._callback)
  
  def _callback(self, bp) :
    if DBG :
      print("[hit] 0x{:x}".format(self.addr))
    stack_addr = eval_windbg(self.cmd)
    int_bytes = READY_OPCODE + pykd.loadBytes(stack_addr, msh.mem_size)
    stack_rets = bytearray(int_bytes)
    
    if DBG:
      print("writing from 0x{:x} to 0x{:x}".format(stack_addr, self.pBuf))
    
    while True :
      rets = msh.read_msg(self.pBuf, msh.mem_size)
      if rets.startswith("".join([chr(x) for x in READY_OPCODE])) :
        time.sleep(t_sleep)
      else :
        break
                         
    msh.write_msg(self.pBuf, stack_rets, len(stack_rets))
    return False
 

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Reach breakpoint address and save some memory data into a shared memory location")
  parser.add_argument("-a", "--addr", required=True, help="Breakpoint address. Can be a constant or <module_name>+<offset> if ASLR is present")
  parser.add_argument("-c", "--cmd", required=True, help="Windbg expression for retrieving the address of the buffer (e.g. poi(esp+0x10))")
 
  args=parser.parse_args() 
  addr = args.addr.strip()
  cmd = args.cmd.strip()
  if not "+" in addr :
    if addr.startswith("0x") :
      addr = int(addr, 16)
    else :
      addr = int(addr)

  hit_bp = HitBP(addr, cmd)
  pykd.go()


