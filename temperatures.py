"""Read-only Apple SMC temperatures. No fan/power writes or privileged helper.

Protocol reference: macmon 6300c4f89bc73c9e2dba505bc61bc0ffc27cface,
src/sources.rs. M2 sensor-key mapping: Stats
d51378c2238d1c4148792a914b220d6ca1eca466, Modules/Sensors/values.swift.
Only this verified M2-family mapping is used; unknown platforms stay unavailable.
"""
import ctypes as C
import math
import struct
import time

CPU_KEYS=('Tp1h','Tp1t','Tp1p','Tp1l','Tp01','Tp05','Tp09','Tp0D','Tp0X','Tp0b','Tp0f','Tp0j')
GPU_KEYS=('Tg0f','Tg0j')

class _Version(C.Structure):
    _fields_=[('major',C.c_uint8),('minor',C.c_uint8),('build',C.c_uint8),('reserved',C.c_uint8),('release',C.c_uint16)]
class _Limits(C.Structure):
    _fields_=[('version',C.c_uint16),('length',C.c_uint16),('cpu',C.c_uint32),('gpu',C.c_uint32),('memory',C.c_uint32)]
class _Info(C.Structure):
    _fields_=[('size',C.c_uint32),('type',C.c_uint32),('attributes',C.c_uint8)]
class _Data(C.Structure):
    _fields_=[('key',C.c_uint32),('version',_Version),('limits',_Limits),('info',_Info),
              ('result',C.c_uint8),('status',C.c_uint8),('command',C.c_uint8),('argument',C.c_uint32),('data',C.c_uint8*32)]

def summarize(readings,at=None,error=None):
    """Reject sentinel/malformed values. Report only explicitly mapped sensors."""
    groups={}
    for group,keys in [('cpu',CPU_KEYS),('gpu',GPU_KEYS)]:
        # M2 CPU sensors can return broken sub-10 C values: Stats readers.swift
        # at the pinned revision above. Omit them instead of showing stale data.
        minimum=10 if group=='cpu' else 0
        items=[dict(key=k,celsius=float(readings[k])) for k in keys
               if isinstance(readings.get(k),(float,int)) and math.isfinite(readings[k]) and
               0<readings[k]<=150 and readings[k]>=minimum]
        values=[s['celsius'] for s in items]
        groups[group+'_c']=sum(values)/len(values) if values else None
        groups[group+'_max_c']=max(values) if values else None
        groups[group+'_sensors']=items
    return dict(at=time.time() if at is None else at,source='Apple SMC · read only',error=error,**groups)

def model_name():
    libc=C.CDLL(None,use_errno=True);size=C.c_size_t()
    if libc.sysctlbyname(b'machdep.cpu.brand_string',None,C.byref(size),None,0):raise OSError('CPU model unavailable')
    buf=C.create_string_buffer(size.value)
    if libc.sysctlbyname(b'machdep.cpu.brand_string',buf,C.byref(size),None,0):raise OSError('CPU model unavailable')
    return buf.value.decode()

class SMCTemperatures:
    """One owned SMC connection per read, closed on success, error or cancellation."""
    def __init__(self):
        self.model=None
        self.infos={}
        self.io=C.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')
        self.libc=C.CDLL(None)
        self.libc.mach_task_self.restype=C.c_uint32
        self.io.IOServiceMatching.argtypes=[C.c_char_p];self.io.IOServiceMatching.restype=C.c_void_p
        self.io.IOServiceGetMatchingService.argtypes=[C.c_uint32,C.c_void_p];self.io.IOServiceGetMatchingService.restype=C.c_uint32
        self.io.IOServiceOpen.argtypes=[C.c_uint32,C.c_uint32,C.c_uint32,C.POINTER(C.c_uint32)]
        self.io.IOServiceClose.argtypes=[C.c_uint32];self.io.IOObjectRelease.argtypes=[C.c_uint32]
        self.io.IOConnectCallStructMethod.argtypes=[C.c_uint32,C.c_uint32,C.c_void_p,C.c_size_t,C.c_void_p,C.POINTER(C.c_size_t)]

    def _call(self,connection,request):
        if request.command not in (5,9):raise ValueError('Only read and metadata commands are permitted')
        response=_Data();size=C.c_size_t(C.sizeof(response))
        result=self.io.IOConnectCallStructMethod(connection,2,C.byref(request),C.sizeof(request),C.byref(response),C.byref(size))
        if result or response.result or size.value!=C.sizeof(response):raise OSError('SMC read unavailable')
        return response

    def read(self,cancel=None):
        try:
            if self.model is None:self.model=model_name()
            if not self.model.startswith('Apple M2'):return summarize({},error='No verified temperature-key mapping for '+self.model)
            if cancel and cancel.is_set():raise InterruptedError('Scan stopped')
            service=self.io.IOServiceGetMatchingService(0,self.io.IOServiceMatching(b'AppleSMC'))
            if not service:return summarize({},error='Apple SMC interface not exposed')
            connection=C.c_uint32()
            try:
                result=self.io.IOServiceOpen(service,self.libc.mach_task_self(),0,C.byref(connection))
            finally:self.io.IOObjectRelease(service)
            if result:return summarize({},error='Temperature sensor access denied')
            readings={}
            try:
                for key in CPU_KEYS+GPU_KEYS:
                    if cancel and cancel.is_set():raise InterruptedError('Scan stopped')
                    try:
                        key_id=int.from_bytes(key.encode(),'big')
                        if key not in self.infos:self.infos[key]=self._call(connection,_Data(key=key_id,command=9)).info
                        info=self.infos[key]
                        if info.size!=4 or info.type!=int.from_bytes(b'flt ','big'):continue
                        data=self._call(connection,_Data(key=key_id,command=5,info=info))
                        readings[key]=struct.unpack('<f',bytes(data.data[:4]))[0]
                    except OSError:continue
            finally:self.io.IOServiceClose(connection)
            result=summarize(readings)
            if result['cpu_c'] is None and result['gpu_c'] is None:result['error']='No valid mapped temperature readings returned'
            result['model']=self.model
            return result
        except InterruptedError:raise
        except (OSError,AttributeError) as exc:return summarize({},error=str(exc))
