

DBG = True

t_sleep = 0.3
t_sleep_2 = 1

READY_OPCODE = [1,3,3,7]
CLEAN_OPCODE = [0,0,0,0]

HOST_REPLACE="@@<HOST>@@"
PORT_REPLACE="@@<PORT>@@"

# powershell path
powershell_path = 'C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe'

# python path
PY_PATH = "C:\\Python27\\python.exe"

# windbg path
windbg_path = 'C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\windbg.exe'

# windbg commands prepended by auto_windbg.py
prepend_cmd = ".load pykd.pyd; .scriptload C:/scripts/narly.js"


