from libc.stdint cimport uint8_t, uint16_t, uint32_t
from posix.time cimport timeval
from cloudtrace.read.utils cimport *

cdef struct node_s:
    void *dst
    uint8_t dstlen
    timeval time
    node_s *next
ctypedef node_s node

cdef class LinkedList:
    cdef:
        node *start
        node *end

    cdef void add(self, uint8_t family, void *dst, timeval *time) except *;
    cdef node *pop(self);

cdef void free_node(node *n);

cdef class Node:
    cdef:
        bytes dst
        timeval time
        Node next

cdef class LinkedList2:
    cdef:
        Node start
        Node end

    cdef void add(self, uint8_t family, char *dst, timeval *time) except *;
    cdef Node pop(self);
