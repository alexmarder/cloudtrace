import bz2
import gzip
from subprocess import Popen, PIPE, TimeoutExpired
from libc.stdlib cimport malloc, free, calloc
from libc.string cimport memcpy, strcpy, memset, memcmp

def fopen(filename, mode='rt', *args, **kwargs):
    if filename.endswith('.gz'):
        return gzip.open(filename, mode, *args, **kwargs)
    elif filename.endswith('.bz2'):
        return bz2.open(filename, mode, *args, **kwargs)
    return open(filename, mode, *args, **kwargs)

cdef class Pcap:
    def __cinit__(self, filename, bint fix=True, uint8_t verbose=0):
        cdef:
            bytes buf
        self.global_hdr = <global_hdr_t *>calloc(1, sizeof(global_hdr_t))
        self.packet_hdr = <packet_hdr_t *>calloc(1, sizeof(packet_hdr_t))
        if not fix:
            self.infile = fopen(filename, mode='rb')
            self.proc = None
        else:
            vstr = '-v '.format(verbose) if verbose > 0 else ''
            cmd = 'pcapfix2 {}-o - {}'.format(vstr, filename)
            print(cmd)
            self.proc = Popen(cmd, shell=True, stdout=PIPE)
            self.infile = self.proc.stdout
        buf = self.infile.read(sizeof(global_hdr_t))
        memcpy(self.global_hdr, <char *>buf, sizeof(global_hdr_t))
        self.frame = <char *>calloc(1, 4096)

    def __dealloc__(self):
        if self.frame is not NULL:
            free(self.frame)
        if self.packet_hdr is not NULL:
            free(self.packet_hdr)
        if self.global_hdr is not NULL:
            free(self.global_hdr)

    cpdef void close(self) except *:
        if self.proc is not None:
            try:
                self.proc.wait(timeout=1)
            except TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        else:
            print('closing infile')
            self.infile.close()
            print('infile closed')

    cpdef int next_packet(self):
        cdef:
            bytes buf, buf2
        buf = self.infile.read(sizeof(packet_hdr_t))
        if len(buf) < sizeof(packet_hdr_t):
            return 0
        memcpy(self.packet_hdr, <char *>buf, sizeof(packet_hdr_t))
        if self.packet_hdr.incl_len > 4096:
            print('Too big: {:,d}'.format(self.packet_hdr.incl_len))
        buf2 = self.infile.read(self.packet_hdr.incl_len)
        if len(buf2) < self.packet_hdr.incl_len:
            print('Not enough bytes: Wanted {:,d} Got {:,d}'.format(self.packet_hdr.incl_len, len(buf2)))
        memcpy(self.frame, <char *>buf2, self.packet_hdr.incl_len)
        # memcpy(self.frame, <char *>buf2, len(buf2))
        return 1

    cpdef void read_all(self) except *:
        cdef:
            int code
            uint64_t loop = 0
        while True:
            loop += 1
            if loop % 1000000 == 0:
                print('Loop {:,d}'.format(loop))
            code = self.next_packet()
            if not code:
                break
        print('done')
