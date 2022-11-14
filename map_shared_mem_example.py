import ctypes
import sys

## refs
# - https://learn.microsoft.com/en-us/windows/win32/memory/creating-named-shared-memory
# - https://github.com/hakril/PythonForWindows/blob/c1aad71dd3ba9acb7fc0e159816edb194752693c/windows/generated_def/windef.py


### Constants
INVALID_HANDLE_VALUE = ctypes.c_int(0xffffffff)
PAGE_EXECUTE_READWRITE = ctypes.c_int(0x40)
PAGE_READWRITE = ctypes.c_int(0x04)

STANDARD_RIGHTS_REQUIRED = 0x000F0000
SECTION_QUERY = 0x0001
SECTION_MAP_WRITE = 0x0002
SECTION_MAP_READ = 0x0004
SECTION_MAP_EXECUTE = 0x0008
SECTION_EXTEND_SIZE = 0x0010
SECTION_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE |SECTION_MAP_READ |SECTION_MAP_EXECUTE |SECTION_EXTEND_SIZE
FILE_MAP_ALL_ACCESS = ctypes.c_int(SECTION_ALL_ACCESS)


### configurable vars
mem_name = "Global\\t1\0\0"
# python 2.7
b = bytearray()
b.extend(mem_name)
mem_name_c = (ctypes.c_char * len(b)).from_buffer(b)
mem_size = 512


### shared mem functions

class ShMemExp(Exception):
  def __init__(self, msg):
    super(Exception, self).__init__(msg)


def close_handle(hndl):
  ctypes.windll.kernel32.CloseHandle(hndl)


def unmap_view(ptr):
  ctypes.windll.kernel32.UnmapViewOfFile(ptr)


def open_shared_mem(do_create=False):
  """
    Open/Create shared memory <mem_name> (default: 'Global\\t1')

    return handler and address of the shared memory
  """
  BUF_SIZE = ctypes.c_int(mem_size)
  if do_create :
    hMapFile = ctypes.windll.kernel32.CreateFileMappingA(
      INVALID_HANDLE_VALUE,
      ctypes.c_int(0),
      PAGE_READWRITE,
      ctypes.c_int(0),
      BUF_SIZE,
      mem_name_c)
  else :
    hMapFile = ctypes.windll.kernel32.OpenFileMappingA(
      FILE_MAP_ALL_ACCESS,
      ctypes.c_int(0),
      mem_name_c)
  #
  if hMapFile == 0 :
    tmpMsg = "OPEN"
    if do_create :
      tmpMsg = "CREATE"
    raise ShMemExp("Could not {} file mapping object '{}' ..quit".format(tmpMsg, mem_name))
  #
  pBuf = ctypes.windll.kernel32.MapViewOfFile(
    hMapFile,
    FILE_MAP_ALL_ACCESS,
    ctypes.c_int(0),
    ctypes.c_int(0),
    BUF_SIZE)
  #
  if pBuf == 0 :
    close_handle(hMapFile)
    raise ShMemExp("MapViewOfFile failed! file mapping object '{}' ..quit".format(mem_name))
  #
  return hMapFile, pBuf


def remove_shared_mem(hMapFile, pBuf):
  """
    Remove shared memory
  """
  unmap_view(pBuf)
  close_handle(hMapFile)


def convert_buf_to_ptr(buff):
  # python 2.7
  b = buff
  if not isinstance(b, bytearray) :
    b = bytearray()
    b.extend(buff)
  return (ctypes.c_char * len(b)).from_buffer(b)


def write_msg(pBuf, buff, size):
  """
    Write buff (string) to pBuf by using ctypes.memmove

  """
  buff_c = convert_buf_to_ptr(buff)
  ctypes.memmove(pBuf, buff_c, size)


def read_msg(pBuf, size):
  """
    Return pBuf content as string object
  """
  buff_c = convert_buf_to_ptr("\00"*size)
  ctypes.memmove(buff_c, pBuf, size)
  return buff_c.raw


if __name__ == "__main__" :
  print("Test")
  hMapFile, pBuf = open_shared_mem(do_create=True)
  hMapFile_2, pBuf_2 = open_shared_mem(do_create=False)
  tmpMsg = "Message send test\n\0"
  write_msg(pBuf, tmpMsg, len(tmpMsg))
  rets = read_msg(pBuf_2, len(tmpMsg))
  print("Msg sent: {}".format(tmpMsg))
  print("Msg recv: {}".format(rets))
  print("Info:")
  print(hMapFile, pBuf)
  print(hMapFile_2, pBuf_2)
  print("")
  remove_shared_mem(hMapFile, pBuf)
  remove_shared_mem(hMapFile_2, pBuf_2)


