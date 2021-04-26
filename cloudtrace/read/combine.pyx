from libc.string cimport memcpy, strcpy, memset, memcmp
from libc.stdlib cimport malloc, free, calloc

cdef class Trace:
    def __cinit__(self):
        self.hops = <hop_t **>calloc(32, sizeof(hop_t))

    def __dealloc__(self):
        cdef:
            hop_t *hop
        for i in range(32):
            hop = self.hops[i]
            if hop is not NULL:
                free(hop)
        if self.hops is not NULL:
            free(self.hops)

    cdef hop_t *new_hop(self, uint8_t probe_ttl) except *:
        cdef:
            hop_t *hop
        probe_ttl -= 1
        if self.hops[probe_ttl] is not NULL:
            # raise Exception('Hop not null!')
            print('Hop not null')
            return self.hops[probe_ttl]
        hop = <hop_t *>calloc(1, sizeof(hop_t))
        self.hops[probe_ttl] = hop
        return hop