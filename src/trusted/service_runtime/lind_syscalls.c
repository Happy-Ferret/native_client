
#include <stddef.h>
#include <string.h>

#include "native_client/src/shared/platform/nacl_host_desc.h"

#include "native_client/src/trusted/desc/nacl_desc_base.h"
#include "native_client/src/trusted/desc/nacl_desc_io.h"
#include "native_client/src/trusted/service_runtime/lind_syscalls.h"
#include "native_client/src/trusted/service_runtime/nacl_copy.h"
#include "native_client/src/trusted/service_runtime/include/sys/errno.h"

int32_t NaClSysSelect(struct NaClAppThread *natp,
                           uint32_t nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    struct NaClApp       *nap = natp->nap;
    fd_set sys_readfds, sys_writefds, sys_exceptfds;
    fd_set nhreadfds, nhwritefds, nhexceptfds;
    uint32_t nhfds = 0;
    struct timeval ntimeout;
    int32_t retval = -NACL_ABI_EINVAL;
    struct NaClDesc* ndp;
    int map_hd_to_nd[FD_SETSIZE];

    if(readfds && !NaClCopyInFromUser(nap, &sys_readfds, (uintptr_t)readfds, sizeof(fd_set))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(writefds && !NaClCopyInFromUser(nap, &sys_writefds, (uintptr_t)writefds, sizeof(fd_set))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(exceptfds && !NaClCopyInFromUser(nap, &sys_exceptfds, (uintptr_t)exceptfds, sizeof(fd_set))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(timeout && !NaClCopyInFromUser(nap, &ntimeout, (uintptr_t)timeout, sizeof(struct timeval))) {
        goto cleanup;
    }
    /* convert NaCl FDs to host FDs */
    memset(map_hd_to_nd, 0, sizeof(map_hd_to_nd));
    FD_ZERO(&nhreadfds);
    FD_ZERO(&nhwritefds);
    FD_ZERO(&nhexceptfds);
    for(int i=0; i<(int)nfds; ++i) {
        if(FD_ISSET(i, &sys_readfds) || FD_ISSET(i, &sys_writefds) || FD_ISSET(i, &sys_exceptfds)) {
            ndp = NaClGetDesc(nap, i);
            if (NULL == ndp) {
                retval = -NACL_ABI_EBADF;
                goto cleanup;
            }
            if(readfds && FD_ISSET(i, &sys_readfds)) {
                retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SelectAdd)(ndp, &nhreadfds, i, map_hd_to_nd, FD_SETSIZE, &nhfds);
                if(retval<0) {
                    goto cleanup;
                }
            }
            if(writefds && FD_ISSET(i, &sys_writefds)) {
                retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SelectAdd)(ndp, &nhwritefds, i, map_hd_to_nd, FD_SETSIZE, &nhfds);
                if(retval<0) {
                    goto cleanup;
                }
            }
            if(exceptfds && FD_ISSET(i, &sys_exceptfds)) {
                retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SelectAdd)(ndp, &nhexceptfds, i, map_hd_to_nd, FD_SETSIZE, &nhfds);
                if(retval<0) {
                    goto cleanup;
                }
            }
            NaClDescUnref(ndp);
        }
    }
    retval = NaClHostDescSelect(nhfds+1, readfds?&nhreadfds:NULL, writefds?&nhwritefds:NULL, exceptfds?&nhexceptfds:NULL, timeout?&ntimeout:NULL);
    if(retval<0) {
        goto cleanup;
    }
    /* safe to clear them now */
    FD_ZERO(&sys_readfds);
    FD_ZERO(&sys_writefds);
    FD_ZERO(&sys_exceptfds);
    for(int i=0; i<=(int)nhfds; ++i) {
        if(readfds && FD_ISSET(i, &nhreadfds)) {
            FD_SET(map_hd_to_nd[i], &sys_readfds);
        }
        if(writefds && FD_ISSET(i, &nhwritefds)) {
            FD_SET(map_hd_to_nd[i], &sys_writefds);
        }
        if(exceptfds && FD_ISSET(i, &nhexceptfds)) {
            FD_SET(map_hd_to_nd[i], &sys_exceptfds);
        }
    }
    if(readfds && !NaClCopyOutToUser(nap, (uintptr_t)readfds, &sys_readfds, sizeof(fd_set))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(writefds && !NaClCopyOutToUser(nap, (uintptr_t)writefds, &sys_writefds, sizeof(fd_set))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(exceptfds && !NaClCopyOutToUser(nap, (uintptr_t)exceptfds, &sys_exceptfds, sizeof(fd_set))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(timeout && !NaClCopyOutToUser(nap, (uintptr_t)timeout, &ntimeout, sizeof(fd_set))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
cleanup:
    return retval;
}

int32_t NaClSysPoll(struct NaClAppThread *natp,
                        struct pollfd *fds, nfds_t nfds, int timeout) {
    struct NaClApp       *nap = natp->nap;
    int32_t retval = -NACL_ABI_EINVAL;
    struct NaClDesc* ndp;
    int map_hd_to_nd[FD_SETSIZE];
    struct pollfd* sys_fds;
    size_t pollfd_size = sizeof(struct pollfd)*nfds;

    memset(map_hd_to_nd, 0, sizeof(map_hd_to_nd));
    sys_fds = malloc(pollfd_size);
    if(!sys_fds) {
        retval = -NACL_ABI_ENOMEM;
        goto cleanup;
    }

    if(!fds || !NaClCopyInFromUser(nap, &sys_fds, (uintptr_t)fds, pollfd_size)) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    for(int i=0;i<(int)nfds;++i) {
        ndp = NaClGetDesc(nap, sys_fds[i].fd);
        if (NULL == ndp) {
            retval = -NACL_ABI_EBADF;
            goto cleanup;
        }
        retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     PollWatch)(ndp, &sys_fds[i], map_hd_to_nd, FD_SETSIZE);
        if(retval<0) {
            goto cleanup;
        }
        NaClDescUnref(ndp);
    }

    retval = NaClHostDescPoll((host_pollfd*)sys_fds, nfds, timeout);
    if(retval<0) {
        goto cleanup;
    }

    for(int i=0;i<(int)nfds;++i) {
        sys_fds[i].fd = map_hd_to_nd[sys_fds[i].fd];
    }

    if(!NaClCopyOutToUser(nap, (uintptr_t)fds, sys_fds, pollfd_size)) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

cleanup:
    free(sys_fds);
    return retval;
}

int32_t NaClSysEpollCreate(struct NaClAppThread *natp,
                           int size) {
    struct NaClApp       *nap = natp->nap;
    int32_t retval = -NACL_ABI_EINVAL;
    struct NaClHostDesc* hepd = NULL;

    hepd = malloc(sizeof(*hepd));
    if(!hepd) {
        retval = -NACL_ABI_ENOMEM;
        goto cleanup;
    }

    retval = NaClHostDescEpollCreate(hepd, size);
    if(retval<0) {
        goto cleanup;
    }
    retval = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(hepd)));

cleanup:
    if(retval<0) {
        free(hepd);
    }
    return retval;

}

int32_t NaClSysEpollCtl(struct NaClAppThread *natp,
                         int epfd, int op, int fd, struct epoll_event *event) {
    struct NaClApp       *nap = natp->nap;
    int32_t retval = -NACL_ABI_EINVAL;
    struct NaClDesc* nepdp = NULL;
    struct NaClDesc* ndp = NULL;
    struct epoll_event sys_event;

    if( (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) &&
            (!event || !NaClCopyInFromUser(nap, &sys_event, (uintptr_t)event, sizeof(*event)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    nepdp = NaClGetDesc(nap, epfd);
    if(NULL == nepdp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    ndp = NaClGetDesc(nap, fd);
    if(NULL == ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) nepdp->base.vtbl)->
                     EpollCtl)(nepdp, op, ndp, event?&sys_event:NULL);

cleanup:
    NaClDescSafeUnref(nepdp);
    NaClDescUnref(ndp);
    return retval;
}

int32_t NaClSysEpollWait(struct NaClAppThread *natp,
                         int epfd, struct epoll_event *events,
                         int maxevents, int timeout) {
    struct NaClApp       *nap = natp->nap;
    int32_t retval = -NACL_ABI_EINVAL;
    struct NaClDesc* nepdp = NULL;
    uintptr_t sys_events;
    size_t epoll_event_size = sizeof(struct epoll_event)*maxevents;

    if(!events || kNaClBadAddress == (sys_events = NaClUserToSysAddrRange(nap, (uintptr_t)events, epoll_event_size))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    nepdp = NaClGetDesc(nap, epfd);
    if(NULL == nepdp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) nepdp->base.vtbl)->
                     EpollWait)(nepdp, (struct epoll_event *)sys_events, maxevents, timeout);

cleanup:
    NaClDescSafeUnref(nepdp);
    return retval;
}

int32_t NaClSysSocket(struct NaClAppThread *natp,
                      int domain, int type, int protocol) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClHostDesc  *hd;
    hd = malloc(sizeof *hd);
    if (NULL == hd) {
      retval = -NACL_ABI_ENOMEM;
      goto cleanup;
    }
    retval = NaClHostDescSocket(hd, domain, type, protocol);
    if (0 == retval) {
      retval = NaClSetAvail(nap,
                            ((struct NaClDesc *) NaClDescIoDescMake(hd)));
    }
cleanup:
    return retval;
}

int32_t NaClSysBind(struct NaClAppThread *natp,
                int sockfd, const struct sockaddr *addr,
                socklen_t addrlen) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    char* sys_sockaddr = NULL;

    sys_sockaddr = malloc(addrlen);
    if(!sys_sockaddr) {
        retval = -NACL_ABI_ENOMEM;
        goto cleanup;
    }
    if(!addr || !NaClCopyInFromUser(nap, sys_sockaddr, (uintptr_t)addr, addrlen)) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockBind)(ndp, (const struct sockaddr *)sys_sockaddr, addrlen);
cleanup:
    free(sys_sockaddr);
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysListen(struct NaClAppThread *natp,
                      int sockfd, int backlog) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockListen)(ndp, backlog);
cleanup:
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysAccept(struct NaClAppThread *natp,
                      int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    char* sys_sockaddr = NULL;
    socklen_t sys_addrlen;
    struct NaClDesc* result;

    if(addr) {
        if(!addrlen || !NaClCopyInFromUser(nap, &sys_addrlen, (uintptr_t)addrlen, sizeof(socklen_t))) {
            retval = -NACL_ABI_EINVAL;
            goto cleanup;
        }
        sys_sockaddr = malloc(sys_addrlen);
        if(!sys_sockaddr) {
            retval = -NACL_ABI_ENOMEM;
            goto cleanup;
        }
        if(!NaClCopyInFromUser(nap, sys_sockaddr, (uintptr_t)addr, sys_addrlen)) {
            retval = -NACL_ABI_EINVAL;
            goto cleanup;
        }
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockAccept)(ndp, addr?(const struct sockaddr *)sys_sockaddr:NULL, addr?&sys_addrlen:NULL, &result);

    if(retval<0) {
        goto cleanup;
    }

    if(!NaClCopyOutToUser(nap, (uintptr_t)addrlen, &sys_addrlen, sizeof(socklen_t))) {
        retval = -NACL_ABI_EINVAL;
    }

    retval = NaClSetAvail(nap, result);

cleanup:
    free(sys_sockaddr);
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysConnect(struct NaClAppThread *natp,
                       int sockfd, const struct sockaddr *addr,
                       socklen_t addrlen) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    char* sys_sockaddr = NULL;

    sys_sockaddr = malloc(addrlen);
    if(!sys_sockaddr) {
        retval = -NACL_ABI_ENOMEM;
        goto cleanup;
    }
    if(!addr || !NaClCopyInFromUser(nap, sys_sockaddr, (uintptr_t)addr, addrlen)) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockConnect)(ndp, (const struct sockaddr *)sys_sockaddr, addrlen);
cleanup:
    free(sys_sockaddr);
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysSocketPair(struct NaClAppThread *natp,
                         int domain, int type, int protocol, int* sv) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClHostDesc  *hd[2] = {NULL, NULL};
    uintptr_t sys_sv;

    if(!sv || kNaClBadAddress == (sys_sv = NaClUserToSysAddrRange(nap, (uintptr_t)sv, sizeof(int)*2))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    for (int i=0; i<2; ++i) {
        hd[i] = malloc(sizeof (struct NaClHostDesc));
        if(!hd[i]) {
            retval = -NACL_ABI_ENOMEM;
            goto cleanup;
        }
    }
    retval = NaClHostDescSocketPair(domain, type, protocol, hd);
    if(retval<0) {
        goto cleanup;
    }

    ((int*)sys_sv)[0] = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(hd[0])));
    ((int*)sys_sv)[1] = NaClSetAvail(nap, ((struct NaClDesc *) NaClDescIoDescMake(hd[1])));
cleanup:
    if(retval<0) {
        free(hd[0]);
        free(hd[1]);
    }
    return retval;
}

int32_t NaClSysSend(struct NaClAppThread *natp,
                    int sockfd, const void *buf, size_t len, int flags) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    uintptr_t sys_buf = 0;

    if(!buf || kNaClBadAddress == (sys_buf = NaClUserToSysAddrRange(nap, (uintptr_t)buf, len))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }


    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockSend)(ndp, (const void *)sys_buf, len, flags);

cleanup:
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysSendTo(struct NaClAppThread *natp,
                    int sockfd, const void *buf, size_t len, int flags,
                      const struct sockaddr *dest_addr, socklen_t addrlen) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    uintptr_t sys_buf = 0;
    uintptr_t sys_dest_addr = 0;

    if(!buf) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(!buf || kNaClBadAddress == (sys_buf = NaClUserToSysAddrRange(nap, (uintptr_t)buf, len))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    if(dest_addr) {
        if(kNaClBadAddress == (sys_dest_addr = NaClUserToSysAddrRange(nap, (uintptr_t)dest_addr, addrlen))) {
            retval = -NACL_ABI_EINVAL;
            goto cleanup;
        }
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockSendTo)(ndp, (const void *)sys_buf, len, flags, (const struct sockaddr *)sys_dest_addr, addrlen);

cleanup:
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysSendMsg(struct NaClAppThread *natp,
                    int sockfd, const struct msghdr *msg, int flags) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    struct msghdr sys_msg;
    struct iovec *sys_iovec = NULL;

    if(!msg || !NaClCopyInFromUser(nap, &sys_msg, (uintptr_t)msg, sizeof(*msg))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    if(!sys_msg.msg_iov) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    sys_iovec = malloc(sizeof(struct iovec)*sys_msg.msg_iovlen);
    if(!sys_iovec) {
        retval = -NACL_ABI_ENOMEM;
        goto cleanup;
    }
    if(!NaClCopyInFromUser(nap, sys_iovec, (uintptr_t)sys_msg.msg_iov, sizeof(struct iovec)*sys_msg.msg_iovlen)) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    sys_msg.msg_iov = sys_iovec;

    for(size_t i=0; i<sys_msg.msg_iovlen; ++i) {
        if(!sys_iovec[i].iov_base || kNaClBadAddress == (uintptr_t)(sys_iovec[i].iov_base = (void*)NaClUserToSysAddrRange(nap, (uintptr_t)sys_iovec[i].iov_base, sys_iovec[i].iov_len))) {
            retval = -NACL_ABI_EINVAL;
            goto cleanup;
        }
    }

    if(sys_msg.msg_name && (kNaClBadAddress == (uintptr_t)(sys_msg.msg_name = (void*)NaClUserToSysAddrRange(nap, (uintptr_t)sys_msg.msg_name, sys_msg.msg_namelen)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    if(sys_msg.msg_control && (kNaClBadAddress == (uintptr_t)(sys_msg.msg_control = (void*)NaClUserToSysAddrRange(nap, (uintptr_t)sys_msg.msg_control, sys_msg.msg_controllen)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockSendMsg)(ndp, &sys_msg, flags);

cleanup:
    free(sys_iovec);
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysRecv(struct NaClAppThread *natp,
                    int sockfd, void *buf, size_t len, int flags) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    uintptr_t            sys_buf;

    if(!buf || (kNaClBadAddress == (sys_buf = NaClUserToSysAddrRange(nap, (uintptr_t)buf, len)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockRecv)(ndp, (void *)sys_buf, len, flags);

cleanup:
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysRecvFrom(struct NaClAppThread *natp,
                    int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    uintptr_t            sys_buf;
    uintptr_t            sys_src_addr;
    socklen_t            sys_addrlen;

    if(!buf || (kNaClBadAddress == (sys_buf = NaClUserToSysAddrRange(nap, (uintptr_t)buf, len)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    if(src_addr) {
        if(!addrlen || !NaClCopyInFromUser(nap, &sys_addrlen, (uintptr_t)addrlen, sizeof(socklen_t))) {
            retval = -NACL_ABI_EINVAL;
            goto cleanup;
        }
        if((kNaClBadAddress == (sys_src_addr = NaClUserToSysAddrRange(nap, (uintptr_t)src_addr, sys_addrlen)))) {
            retval = -NACL_ABI_EINVAL;
            goto cleanup;
        }
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockRecvFrom)(ndp, (void *)sys_buf, len, flags, (struct sockaddr *)sys_src_addr, &sys_addrlen);
    if(retval<0) {
        goto cleanup;
    }

    if(!NaClCopyOutToUser(nap, (uintptr_t)addrlen, &sys_addrlen, sizeof(socklen_t))) {
        retval = -NACL_ABI_EINVAL;
    }
cleanup:
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysRecvMsg(struct NaClAppThread *natp,
                    int sockfd, struct msghdr *msg, int flags) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    struct msghdr sys_msg;
    struct iovec *sys_iovec = NULL;

    if(!msg || !NaClCopyInFromUser(nap, &sys_msg, (uintptr_t)msg, sizeof(*msg))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    if(!sys_msg.msg_iov) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    sys_iovec = malloc(sizeof(struct iovec)*sys_msg.msg_iovlen);
    if(!sys_iovec) {
        retval = -NACL_ABI_ENOMEM;
        goto cleanup;
    }
    if(!NaClCopyInFromUser(nap, sys_iovec, (uintptr_t)sys_msg.msg_iov, sizeof(struct iovec)*sys_msg.msg_iovlen)) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    sys_msg.msg_iov = sys_iovec;

    for(size_t i=0; i<sys_msg.msg_iovlen; ++i) {
        if(!sys_iovec[i].iov_base || kNaClBadAddress == (uintptr_t)(sys_iovec[i].iov_base = (void*)NaClUserToSysAddrRange(nap, (uintptr_t)sys_iovec[i].iov_base, sys_iovec[i].iov_len))) {
            retval = -NACL_ABI_EINVAL;
            goto cleanup;
        }
    }

    if(sys_msg.msg_name && (kNaClBadAddress == (uintptr_t)(sys_msg.msg_name = (void*)NaClUserToSysAddrRange(nap, (uintptr_t)sys_msg.msg_name, sys_msg.msg_namelen)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    if(sys_msg.msg_control && (kNaClBadAddress == (uintptr_t)(sys_msg.msg_control = (void*)NaClUserToSysAddrRange(nap, (uintptr_t)sys_msg.msg_control, sys_msg.msg_controllen)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockRecvMsg)(ndp, &sys_msg, flags);

    if(!NaClCopyOutToUser(nap, (uintptr_t)((char*)msg+offsetof(struct msghdr, msg_flags)), &sys_msg.msg_flags, sizeof(sys_msg.msg_flags))) {
        retval = -NACL_ABI_EINVAL;
    }

cleanup:
    free(sys_iovec);
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysGetSockName(struct NaClAppThread *natp,
                           int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    uintptr_t sys_sockaddr = kNaClBadAddress;
    uintptr_t sys_addrlen = kNaClBadAddress;

    if(!addr || ! addrlen) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(kNaClBadAddress == (sys_addrlen = NaClUserToSysAddrRange(nap, (uintptr_t)addrlen, sizeof(socklen_t)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(kNaClBadAddress == (sys_sockaddr = NaClUserToSysAddrRange(nap, (uintptr_t)addr, *((socklen_t*)sys_addrlen)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockGetSockName)(ndp, (struct sockaddr *)sys_sockaddr, (socklen_t *)sys_addrlen);


cleanup:
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysGetPeerName(struct NaClAppThread *natp,
                           int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    uintptr_t sys_sockaddr = kNaClBadAddress;
    uintptr_t sys_addrlen = kNaClBadAddress;

    if(!addr || ! addrlen) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(kNaClBadAddress == (sys_addrlen = NaClUserToSysAddrRange(nap, (uintptr_t)addrlen, sizeof(socklen_t)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(kNaClBadAddress == (sys_sockaddr = NaClUserToSysAddrRange(nap, (uintptr_t)addr, *((socklen_t*)sys_addrlen)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockGetPeerName)(ndp, (struct sockaddr *)sys_sockaddr, (socklen_t *)sys_addrlen);

cleanup:
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysGetSockOpt(struct NaClAppThread *natp,
                          int sockfd, int level, int optname,
                          void *optval, socklen_t *optlen) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    uintptr_t sys_optval = kNaClBadAddress;
    uintptr_t sys_optlen = kNaClBadAddress;

    if(!optval || ! optlen) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(kNaClBadAddress == (sys_optlen = NaClUserToSysAddrRange(nap, (uintptr_t)optlen, sizeof(socklen_t)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(kNaClBadAddress == (sys_optval = NaClUserToSysAddrRange(nap, (uintptr_t)optval, *((socklen_t *)sys_optlen)))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockGetSockOpt)(ndp, level, optname, (void*)sys_optval, (socklen_t*)sys_optlen);

cleanup:
    NaClDescSafeUnref(ndp);
    return retval;

}

int32_t NaClSysSetSockOpt(struct NaClAppThread *natp,
                          int sockfd, int level, int optname,
                          const void *optval, socklen_t optlen) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp = NULL;
    uintptr_t sys_optval = kNaClBadAddress;

    if(!optval) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }
    if(kNaClBadAddress == (sys_optval = NaClUserToSysAddrRange(nap, (uintptr_t)optval, optlen))) {
        retval = -NACL_ABI_EINVAL;
        goto cleanup;
    }

    ndp = NaClGetDesc(nap, sockfd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     SockSetSockOpt)(ndp, level, optname, (const void *)sys_optval, optlen);

cleanup:
    NaClDescSafeUnref(ndp);
    return retval;
}

int32_t NaClSysFcntl(struct NaClAppThread *natp,
                     int fd, int cmd, int opt) {
    struct NaClApp       *nap = natp->nap;
    int32_t             retval = -NACL_ABI_EINVAL;
    struct NaClDesc*     ndp;
    struct NaClDesc*     new_ndp;

    ndp = NaClGetDesc(nap, fd);
    if(!ndp) {
        retval = -NACL_ABI_EBADF;
        goto cleanup;
    }

    retval = (*((struct NaClDescVtbl const *) ndp->base.vtbl)->
                     Fcntl)(ndp, cmd, opt, &new_ndp);
    if(retval<0) {
        goto cleanup;
    }

    if(cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
        NaClFastMutexLock(&nap->desc_mu);
        while(DynArrayGet(&nap->desc_tbl, opt)) {
            ++opt;
        }
        NaClLog(3, "Found a valid FD: %d\n", opt);
        if (!DynArraySet(&nap->desc_tbl, opt, new_ndp)) {
        NaClLog(LOG_FATAL,
                "NaClSetDesc: could not set descriptor %d to 0x%08"
                NACL_PRIxPTR"\n",
                opt,
                (uintptr_t) new_ndp);
        }
        NaClFastMutexUnlock(&nap->desc_mu);
        retval = opt;
    }

cleanup:
    NaClDescSafeUnref(ndp);
    return retval;
}
