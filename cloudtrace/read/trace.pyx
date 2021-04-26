from libc.stdlib cimport malloc, free, calloc
from libc.string cimport memcpy

cdef class BaseObj:
    def __cinit__(self):
        self.ptr = NULL
        self.ptr_owner = False

    def __dealloc__(self):
        if self.ptr_owner and self.ptr is not NULL:
            free(self.ptr)

cdef class TraceHop(BaseObj):

    def __cinit__(self):
        self.hop = <trace_hop_t>self.hop

    @staticmethod
    cdef BaseObj loads(char *buf):
        cdef:
            TraceHop hop = TraceHop.new_ptr()
        memcpy(hop.ptr, buf, sizeof(trace_hop_t))
        buf += sizeof(trace_hop_t)

    @staticmethod
    cdef TraceHop new_ptr():
        cdef:
            trace_hop_t *sh = calloc(sizeof(trace_hop_t))
            TraceHop hop = TraceHop.from_ptr(sh)
        hop.ptr_owner = True
        return hop

    @staticmethod
    cdef TraceHop from_ptr(void *ptr):
        cdef:
            TraceHop sh = TraceHop.__new__(TraceHop)
        sh.ptr = <trace_hop_t>ptr
        return sh

cdef class Trace(BaseObj):

    def __cinit__(self):
        self.trace = <trace_t>self.ptr

    def __dealloc__(self):
        if self.ptr_owner and self.ptr is not NULL:
            for i in range(self.trace.hop_count):
                free(self.trace.hops[i])
            free(self.ptr)

    @staticmethod
    cdef BaseObj loads(char *buf):
        cdef:
            Trace trace = Trace.new_ptr()
        memcpy(trace.ptr, buf, sizeof(trace_t))
        buf += sizeof(trace_hop_t)
        trace.trace.hops = <trace_hop_t**>calloc(trace.trace.hop_count * sizeof(trace_hop_t*))
        for i in range(trace.trace.hop_count):
            memcpy(trace.trace.hops[i], buf, sizeof(trace_hop_t))

    @staticmethod
    cdef Trace new_ptr():
        cdef:
            trace_t *sh = calloc(sizeof(trace_t))
            Trace trace = Trace.from_ptr(sh)
        trace.ptr_owner = True
        return trace

    @staticmethod
    cdef Trace from_ptr(void *ptr):
        cdef:
            Trace sh = Trace.__new__(Trace)
        sh.ptr = <trace_t>ptr
        return sh
