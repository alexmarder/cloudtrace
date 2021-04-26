from libc.stdlib cimport free, calloc
from libc.string cimport memcpy, strcpy, memset, memcmp

cdef class LinkedList:
    def __cinit__(self):
        self.start = NULL
        self.end = NULL

    def __dealloc__(self):
        cdef:
            node *curr
            node *next
        curr = self.start
        while curr is not NULL:
            next = curr.next
            if curr.dst is not NULL:
                free(curr.dst)
            if curr is not NULL:
                free(curr)
            curr = next

    cdef void add(self, uint8_t family, void *dst, timeval *time) except *:
        cdef:
            node *addnode = <node *>calloc(1, sizeof(node))
        if addnode is NULL:
            raise MemoryError()
        if family == AF_INET:
            addnode.dstlen = 4
        else:
            addnode.dstlen = 16
        addnode.dst = <void *>calloc(1, addnode.dstlen)
        memcpy(addnode.dst, dst, addnode.dstlen)
        memcpy(&addnode.time, time, sizeof(timeval))
        if self.start is NULL:
            self.start = addnode
            self.end = addnode
        else:
            self.end.next = addnode
            self.end = addnode

    cdef node *pop(self):
        cdef:
            node *tmp
        if self.start is NULL:
            return NULL
        tmp = self.start
        self.start = self.start.next
        if self.start is NULL:
            self.end = NULL
        # free_node(tmp)
        # return 1
        return tmp

cdef void free_node(node *n):
    if n.dst is not NULL:
        free(n.dst)
    if n is not NULL:
        free(n)

cdef class Node:
    def __cinit__(self):
        self.next = None
        self.dst = None

cdef class LinkedList2:
    def __cinit__(self):
        self.start = None
        self.end = None

    def __dealloc__(self):
        cdef:
            Node curr
            Node next
        curr = self.start
        while curr is not None:
            next = curr.next
            del curr
            curr = next

    cdef void add(self, uint8_t family, char *dst, timeval *time) except *:
        cdef:
            Node addnode = Node()
            uint8_t dstlen
        if family == AF_INET:
            dstlen = 4
        else:
            dstlen = 16
        addnode.dst = dst[:dstlen]
        memcpy(&addnode.time, time, sizeof(timeval))
        if self.start is None:
            self.start = addnode
            self.end = addnode
        else:
            self.end.next = addnode
            self.end = addnode

    cdef Node pop(self):
        cdef:
            Node tmp
        if self.start is None:
            return None
        tmp = self.start
        self.start = self.start.next
        if self.start is None:
            self.end = None
        return tmp
