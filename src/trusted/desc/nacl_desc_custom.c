/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "native_client/src/trusted/desc/nacl_desc_custom.h"

#include "native_client/src/shared/platform/nacl_check.h"


struct NaClDescCustom {
  struct NaClDesc base NACL_IS_REFCOUNT_SUBCLASS;
  void *handle;
  struct NaClDescCustomFuncs funcs;
};

static const struct NaClDescVtbl kNaClDescCustomVtbl;


struct NaClDesc *NaClDescMakeCustomDesc(
    void *handle, const struct NaClDescCustomFuncs *funcs) {
  struct NaClDescCustom *desc = malloc(sizeof *desc);
  if (NULL == desc) {
    return NULL;
  }
  if (!NaClDescCtor(&desc->base)) {
    free(desc);
    return NULL;
  }
  /* For simplicity, all the callbacks are currently required. */
  DCHECK(funcs->Destroy != NULL);
  DCHECK(funcs->SendMsg != NULL);
  DCHECK(funcs->RecvMsg != NULL);
  desc->handle = handle;
  desc->funcs = *funcs;
  desc->base.base.vtbl = (const struct NaClRefCountVtbl *) &kNaClDescCustomVtbl;
  return &desc->base;
}

static void NaClDescCustomDtor(struct NaClRefCount *vself) {
  struct NaClDescCustom *self = (struct NaClDescCustom *) vself;

  (*self->funcs.Destroy)(self->handle);
  vself->vtbl = (const struct NaClRefCountVtbl *) &kNaClDescVtbl;
  (*vself->vtbl->Dtor)(vself);
}

static ssize_t NaClDescCustomSendMsg(struct NaClDesc                 *vself,
                                     const struct NaClImcTypedMsgHdr *msg,
                                     int                             flags) {
  struct NaClDescCustom *self = (struct NaClDescCustom *) vself;

  return (*self->funcs.SendMsg)(self->handle, msg, flags);
}

static ssize_t NaClDescCustomRecvMsg(
    struct NaClDesc               *vself,
    struct NaClImcTypedMsgHdr     *msg,
    int                           flags,
    struct NaClDescQuotaInterface *quota_interface) {
  struct NaClDescCustom *self = (struct NaClDescCustom *) vself;
  UNREFERENCED_PARAMETER(quota_interface);

  return (*self->funcs.RecvMsg)(self->handle, msg, flags);
}

static const struct NaClDescVtbl kNaClDescCustomVtbl = {
  {
    NaClDescCustomDtor,  /* diff */
  },
  NaClDescMapNotImplemented,
  NACL_DESC_UNMAP_NOT_IMPLEMENTED
  NaClDescReadNotImplemented,
  NaClDescWriteNotImplemented,
  NaClDescSeekNotImplemented,
  NaClDescPReadNotImplemented,
  NaClDescPWriteNotImplemented,
  NaClDescIoctlNotImplemented,
  NaClDescFstatNotImplemented,
  NaClDescGetdentsNotImplemented,
  NaClDescExternalizeSizeNotImplemented,
  NaClDescExternalizeNotImplemented,
  NaClDescLockNotImplemented,
  NaClDescTryLockNotImplemented,
  NaClDescUnlockNotImplemented,
  NaClDescWaitNotImplemented,
  NaClDescTimedWaitAbsNotImplemented,
  NaClDescSignalNotImplemented,
  NaClDescBroadcastNotImplemented,
  NaClDescCustomSendMsg,  /* diff */
  NaClDescCustomRecvMsg,  /* diff */
  NaClDescLowLevelSendMsgNotImplemented,
  NaClDescLowLevelRecvMsgNotImplemented,
  NaClDescConnectAddrNotImplemented,
  NaClDescAcceptConnNotImplemented,
  NaClDescPostNotImplemented,
  NaClDescSemWaitNotImplemented,
  NaClDescGetValueNotImplemented,
  NaClDescSetMetadata,
  NaClDescGetMetadata,
  NaClDescSetFlags,
  NaClDescGetFlags,
  NaClDescSelectAddNotImplemented,
  NaClDescPollWatchNotImplemented,
  NaClDescBindNotImplemented,
  NaClDescListenNotImplemented,
  NaClDescAcceptNotImplemented,
  NaClDescConnectNotImplemented,
  NaClDescGetPeerNameNotImplemented,
  NaClDescGetSockNameNotImplemented,
  NaClDescSendNotImplemented,
  NaClDescSendToNotImplemented,
  NaClDescSockSendMsgNotImplemented,
  NaClDescRecvNotImplemented,
  NaClDescRecvFromNotImplemented,
  NaClDescSockRecvMsgNotImplemented,
  NaClDescGetSockOptNotImplemented,
  NaClDescSetSockOptNotImplemented,
  NaClDescEpollCtrlNotImplemented,
  NaClDescEpollWaitNotImplemented,
  NaClDescFcntlNotImplemented,
  NACL_DESC_CUSTOM,  /* diff */
};
