
#include "native_client/src/trusted/service_runtime/lind_syscalls.h"

int32_t NaClSysSelect(struct NaClAppThread *natp,
                           uint32_t nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {

}

int32_t NaClSysPoll(struct NaClAppThread *natp,
                        struct pollfd *fds, nfds_t nfds, int timeout) {

}

int32_t NaClSysEpollCreate(struct NaClAppThread *natp,
                           int size) {

}

int32_t NaClSysEpollCtl(struct NaClAppThread *natp,
                         int epfd, int op, int fd, struct epoll_event *event) {

}

int32_t NaClSysEpollWait(struct NaClAppThread *natp,
                         int epfd, struct epoll_event *events,
                         int maxevents, int timeout) {

}

int32_t NaClSysSocket(struct NaClAppThread *natp,
                      int domain, int type, int protocol) {

}

int32_t NaClSysBind(struct NaClAppThread *natp,
                int sockfd, const struct sockaddr *addr,
                socklen_t addrlen) {

}

int32_t NaClSysListen(struct NaClAppThread *natp,
                      int sockfd, int backlog) {

}

int32_t NaClSysAccept(struct NaClAppThread *natp,
                      int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

}

int32_t NaClSysConnect(struct NaClAppThread *natp,
                       int sockfd, const struct sockaddr *addr,
                       socklen_t addrlen) {

}

int32_t NaClSysSocketPair(struct NaClAppThread *natp,
                         int domain, int type, int protocol, int* sv) {

}

int32_t NaClSysSend(struct NaClAppThread *natp,
                    int sockfd, const void *buf, size_t len, int flags) {

}

int32_t NaClSysSendTo(struct NaClAppThread *natp,
                    int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen) {

}

int32_t NaClSysSendMsg(struct NaClAppThread *natp,
                    int sockfd, const struct msghdr *msg, int flags) {

}

int32_t NaClSysRecv(struct NaClAppThread *natp,
                    int sockfd, void *buf, size_t len, int flags) {

}

int32_t NaClSysRecvFrom(struct NaClAppThread *natp,
                    int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen) {

}

int32_t NaClSysRecvMsg(struct NaClAppThread *natp,
                    int sockfd, struct msghdr *msg, int flags) {

}

int32_t NaClSysGetSockName(struct NaClAppThread *natp,
                           int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

}

int32_t NaClSysGetPeerName(struct NaClAppThread *natp,
                           int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

}

int32_t NaClSysGetSockOpt(struct NaClAppThread *natp,
                          int sockfd, int level, int optname,
                          void *optval, socklen_t *optlen) {

}

int32_t NaClSysSetSockOpt(struct NaClAppThread *natp,
                          int sockfd, int level, int optname,
                          const void *optval, socklen_t optlen) {

}

int32_t NaClSysFcntl(struct NaClAppThread *natp,
                     int fd, int cmd, int opt) {

}
