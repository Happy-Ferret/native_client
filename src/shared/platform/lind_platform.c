/*
 * lind_platform.c
 *
 *  Created on: Jul 23, 2013
 *      Author: sji
 */

#include <Python.h>
#include <errno.h>
#include <stdarg.h>

#include "native_client/src/shared/platform/nacl_log.h"
#include "native_client/src/shared/platform/lind_platform.h"

PyObject* repylib = NULL;
PyObject* code = NULL;
PyObject* context = NULL;

static int initialized = 0;

#define REPY_RELPATH "../repy/"

#define GOTO_ERROR_IF_NULL(x) if(!(x)) {goto error;}

PyObject* CallPythonFunc(PyObject* context, const char* func, PyObject* args)
{
    PyObject* func_obj = NULL;
    PyObject* result = NULL;
    func_obj = PyDict_GetItemString(context, func);
    GOTO_ERROR_IF_NULL(func_obj);
    GOTO_ERROR_IF_NULL(args);
    result = PyObject_CallObject(func_obj, args);
    GOTO_ERROR_IF_NULL(result);
    return result;
error:
    PyErr_Print();
    Py_XDECREF(func_obj);
    return 0;
}

static PyObject* CallPythonFunc0(PyObject* context, const char* func)
{
    PyObject* args = Py_BuildValue("()");
    return CallPythonFunc(context, func, args);
}

static PyObject* CallPythonFunc1(PyObject* context, const char* func, PyObject* arg)
{
    PyObject* args = Py_BuildValue("(O)", arg);
    return CallPythonFunc(context, func, args);
}

int LindPythonInit(void)
{
    PyObject* path = NULL;
    PyObject* repylib_name = NULL;
    PyObject* result = NULL;
    PyObject* repy_main_func = NULL;
    PyObject* repy_main_args = NULL;
    char* argv[] = {"dummy"};

    if(initialized++) {
        return 1;
    }
    Py_SetProgramName("dummy");
    PyEval_InitThreads();
    Py_InitializeEx(0);
    PySys_SetArgvEx(1, argv, 0);

    path = PySys_GetObject("path");
    GOTO_ERROR_IF_NULL(path);
    PyList_Append(path, PyString_FromString(REPY_RELPATH));

    repylib_name = PyString_FromString("repylib");
    repylib = PyImport_Import(repylib_name);
    GOTO_ERROR_IF_NULL(repylib);
    repy_main_func = PyObject_GetAttrString(repylib, "repy_main");
    GOTO_ERROR_IF_NULL(repy_main_func);
    repy_main_args = Py_BuildValue("([sssss])", "lind", "--safebinary", REPY_RELPATH"restrictions.lind",
            REPY_RELPATH"lind_server.py", "./dummy.nexe");
    result = PyObject_CallObject(repy_main_func, repy_main_args);
    GOTO_ERROR_IF_NULL(result);
    PyOS_AfterFork();
    PyArg_ParseTuple(result, "OO", &code, &context);
    GOTO_ERROR_IF_NULL(code && context);
    result = PyEval_EvalCode((PyCodeObject*)code, context, context);
    GOTO_ERROR_IF_NULL(result);
    PyEval_ReleaseLock();
    return 1;
error:
    initialized = 0;
    PyErr_Print();
    PyEval_ReleaseLock();
    return 0;
}

int LindPythonFinalize(void)
{
    int retval = 0;
    PyObject* repy_finalize_func = NULL;
    PyObject* repy_finalize_args = NULL;
    PyObject* result = NULL;
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();
    if(!initialized) {
        return 0;
    }
    result = CallPythonFunc0(context, "finalize");
    GOTO_ERROR_IF_NULL(result);
    repy_finalize_func = PyObject_GetAttrString(repylib, "finalize");
    GOTO_ERROR_IF_NULL(repy_finalize_func);
    repy_finalize_args = Py_BuildValue("()");
    result = PyObject_CallObject(repy_finalize_func, repy_finalize_args);
    GOTO_ERROR_IF_NULL(result);
    Py_Finalize();
    initialized = 0;
    retval = 1;
    goto cleanup;
error:
    PyErr_Print();
cleanup:
    Py_XDECREF(repy_finalize_func);
    Py_XDECREF(result);
    Py_XDECREF(code);
    Py_XDECREF(context);
    Py_XDECREF(repylib);
    PyGILState_Release(gstate);
    return retval;
}

int GetHostFdFromLindFd(int lindFd)
{
    int retval = -1;
    PyObject* pyLindFd = NULL;
    PyObject* pyHostFd = NULL;
    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();
    if(lindFd < 0) {
        goto cleanup;
    }
    pyLindFd = PyInt_FromLong(lindFd);
    pyHostFd = CallPythonFunc1(context, "GetHostFdFromLindFd", pyLindFd);
    GOTO_ERROR_IF_NULL(pyHostFd);
    if(!PyInt_CheckExact(pyHostFd)) {
        goto error;
    }
    retval = (int)PyInt_AsLong(pyHostFd);
    goto cleanup;
error:
    PyErr_Print();
cleanup:
    Py_XDECREF(pyLindFd);
    Py_XDECREF(pyHostFd);
    NaClLog(3, "host_fd:%d for lind_fd:%d\n", retval, lindFd);
    PyGILState_Release(gstate);
    return retval;
}

int ParseResponse(PyObject* response, int num, ...)
{
    int retval = 0;
    PyObject* attrIsError = NULL;
    PyObject* attrCode = NULL;
    PyObject* attrDataOrMessage = NULL;
    int isError;
    int code;
    char* dataOrMessage;
    int len;
    va_list varg;
    PyGILState_STATE gstate;
    char* dst;
    int maxlen;

    NaClLog(3, "Entered ParseResponse\n");

    gstate = PyGILState_Ensure();

    attrIsError = PyObject_GetAttrString(response, "is_error");
    GOTO_ERROR_IF_NULL(attrIsError);

    attrCode = PyObject_GetAttrString(response, "return_code");
    GOTO_ERROR_IF_NULL(attrCode);

    dataOrMessage = NULL;
    len = 0;

    if(attrIsError == Py_True) {
        isError = 1;
        attrDataOrMessage = PyObject_GetAttrString(response, "message");
        GOTO_ERROR_IF_NULL(attrDataOrMessage);
    } else {
        isError = 0;
        attrDataOrMessage = PyObject_GetAttrString(response, "data");
    }

    code = PyInt_AsLong(attrCode);
    if(PyErr_Occurred()) {
        goto error;
    }

    if(attrDataOrMessage) {
        len = (int)PyString_Size(attrDataOrMessage);
        if(PyErr_Occurred()) {
            goto error;
        }
        dataOrMessage = PyString_AsString(attrDataOrMessage);
        if(PyErr_Occurred()) {
            goto error;
        }
    }
    NaClLog(3, "ParseResponse isError=%d, code=%d, len=%d\n", isError, code, len);
    if(isError) {
        NaClLog(3, "Error message: %s\n", dataOrMessage);
    }
    errno = isError?code:0;
    retval = isError?-1:code;
    if(isError) {
        goto cleanup;
    }
    va_start(varg, num);

    if(num == 1) {
        dst = va_arg(varg, char*);
        maxlen = va_arg(varg, int);
        CopyData(dst, dataOrMessage, maxlen, len);
    } else if(num>1) {
        CopyMultiDataVa(dataOrMessage, len, varg);
    }

    va_end(varg);
    goto cleanup;
error:
    NaClLog(LOG_ERROR, "ParseResponse Python error\n");
    PyErr_Print();
cleanup:
    Py_XDECREF(attrIsError);
    Py_XDECREF(attrCode);
    Py_XDECREF(attrDataOrMessage);
    Py_XDECREF(response);
    PyGILState_Release(gstate);
    return retval;
}

PyObject* MakeLindSysCall(int syscall, char* format, ...) {
    PyObject* callandarg = NULL;
    PyObject* response = NULL;
    PyObject* args = NULL;
    PyGILState_STATE gstate;
    int isError;
    int retcode;
    va_list varg;

    gstate = PyGILState_Ensure();
    va_start(varg, format);
    args = Py_VaBuildValue(format, varg);
    va_end(varg);
    callandarg = Py_BuildValue("(iO)", syscall, args);
    response = CallPythonFunc(context, "LindSyscall", callandarg);
cleanup:
    Py_XDECREF(callandarg);
    Py_XDECREF(args);
    PyGILState_Release(gstate);
    return response;
}

void CopyData(char* dst, char* src, int maxlen, int srclen) {
    assert(maxlen>=srclen);
    memcpy(dst, src, srclen);
}

void CopyMultiDataVa(char* src, int num, va_list varg) {
    int offset;
    char* dst;
    int maxlen;
    int srclen;

    offset = sizeof(uint32_t)*num;
    for(int i=0; i<num; ++i) {
        dst = va_arg(varg, char*);
        maxlen = va_arg(varg, int);
        srclen = ((uint32_t*)src)[i];
        CopyData(dst, src+offset, maxlen, srclen);
        offset += srclen;
    }
}

void CopyMultiData(char* src, int num, ...) {
    va_list varg;

    va_start(varg, num);
    CopyMultiDataVa(src, num, varg);
    va_end(varg);
}

#define DUMP_DATA(x) printf(#x" = 0x%"NACL_PRIX64"\n", (uint64_t)(x));

#if 0
#define DUMP_STAT(x) \
        DUMP_DATA((x)->st_dev); \
        DUMP_DATA((x)->st_ino); \
        DUMP_DATA((x)->st_nlink); \
        DUMP_DATA((x)->st_mode); \
        DUMP_DATA(S_ISREG((x)->st_mode)); \
        DUMP_DATA(S_ISDIR((x)->st_mode)); \
        DUMP_DATA(S_ISCHR((x)->st_mode)); \
        DUMP_DATA(S_ISBLK((x)->st_mode)); \
        DUMP_DATA(S_ISFIFO((x)->st_mode)); \
        DUMP_DATA(S_ISLNK((x)->st_mode)); \
        DUMP_DATA(S_ISSOCK((x)->st_mode)); \
        DUMP_DATA((x)->st_uid); \
        DUMP_DATA((x)->st_gid); \
        DUMP_DATA((x)->st_rdev); \
        DUMP_DATA((x)->st_size); \
        DUMP_DATA((x)->st_blksize); \
        DUMP_DATA((x)->st_blocks)
#else
#define DUMP_STAT(x)
#endif

ssize_t lind_pread(int fd, void* buf, int count, off_t offset)
{
    off_t cur_pos=0;
    int ret = 0;
    cur_pos = lind_lseek (0, fd, SEEK_CUR);
    lind_lseek(offset, fd, SEEK_SET);
    ret = lind_read(fd, count, buf);
    lind_lseek(cur_pos, fd, SEEK_SET);
    return ret;
}

ssize_t lind_pwrite(int fd, const void *buf, int count, off_t offset)
{
    off_t cur_pos=0;
    int ret = 0;
    cur_pos = lind_lseek (0, fd, SEEK_CUR);
    lind_lseek(offset, fd, SEEK_SET);
    ret = lind_write(fd, count, buf);
    lind_lseek(cur_pos, fd, SEEK_SET);
    return ret;
}

int lind_access (const char *pathname, int mode)
{
    return ParseResponse(MakeLindSysCall(LIND_safe_fs_access, "[is]", 1, pathname), 0);
}

int lind_unlink (const char *name)
{
    return ParseResponse(MakeLindSysCall(LIND_safe_fs_unlink, "[s]", name), 0);
}

int lind_link (const char *from, const char *to)
{
    return ParseResponse(MakeLindSysCall(LIND_safe_fs_unlink, "[ss]", from, to), 0);
}

int lind_chdir (const char *name)
{
    return ParseResponse(MakeLindSysCall(LIND_safe_fs_chdir, "[s]", name), 0);
}

int lind_mkdir (const char *path, int mode)
{
    return ParseResponse(MakeLindSysCall(LIND_safe_fs_chdir, "[is]", mode, path), 0);
}

int lind_rmdir (const char *path)
{
    char* data;
    int len;
    int retval;
    retval = MakeLindSysCall(LIND_safe_fs_rmdir, &data, &len, "[s]", path);
    free(data);
    return retval;
}

int lind_stat (const char *path, struct lind_stat *buf)
{
    char* data;
    int len;
    int retval;
    int version = 0;
    retval = MakeLindSysCall(LIND_safe_fs_xstat, &data, &len, "[is]", version, path);
    if(retval<0) {
        return retval;
    }
    CopyData(buf, data, sizeof(*buf), len);
    free(data);
    return retval;
}

int lind_open (const char *path, int flags, int mode)
{
    char* data;
    int len;
    int retval;
    retval = MakeLindSysCall(LIND_safe_fs_open, &data, &len, "[iis]", flags, mode, path);
    free(data);
    return retval;
}

int lind_close (int fd)
{
    char* data;
    int len;
    int retval;
    retval = MakeLindSysCall(LIND_safe_fs_close, &data, &len, "[i]", fd);
    free(data);
    return retval;
}

ssize_t lind_read (int fd, void *buf, int size)
{
    char* data;
    int len;
    ssize_t retval;
    if(!buf) {
        errno = EINVAL;
        return retval;
    }
    retval = MakeLindSysCall(LIND_safe_fs_read, &data, &len, "[ii]", fd, size);
    if(retval<0) {
        return retval;
    }
    CopyData(buf, data, size, len);
    free(data);
    return retval;
}

ssize_t lind_write (int fd, const void *buf, size_t count)
{
    char* data;
    int len;
    ssize_t retval;
    if(!buf) {
        errno = EINVAL;
        return retval;
    }
    retval = MakeLindSysCall(LIND_safe_fs_read, &data, &len, "[iis#]", fd, count, buf, count);
    free(data);
    return retval;
}

off_t lind_lseek (int fd, off_t offset, int whence)
{
    char* data;
    int len;
    int retval;
    off_t ret_off;
    retval = MakeLindSysCall(LIND_safe_fs_lseek, &data, &len, "[iii]", offset, fd, whence);
    if(retval<0) {
        return retval;
    }
    CopyData(&ret_off, data, sizeof(ret_off), len);
    free(data);
    return ret_off;
}

int lind_fstat (int fd, struct lind_stat *buf)
{
    char* data;
    int len;
    int retval;
    int version = 0;
    retval = MakeLindSysCall(LIND_safe_fs_fxstat, &data, &len, "[ii]", fd, version);
    if(retval<0) {
        return retval;
    }
    CopyData(buf, data, sizeof(*buf), len);
    free(data);
    DUMP_STAT(buf);
    return retval;
}

int lind_fstatfs (int fd, struct lind_statfs *buf)
{
    char* data;
    int len;
    int retval;
    int version = 0;
    retval = MakeLindSysCall(LIND_safe_fs_fstatfs, &data, &len, "[i]", fd);
    if(retval<0) {
        return retval;
    }
    CopyData(buf, data, sizeof(*buf), len);
    free(data);
    return retval;
}

int lind_statfs (const char *path, struct lind_statfs *buf)
{
    char* data;
    int len;
    int retval;
    int version = 0;
    retval = MakeLindSysCall(LIND_safe_fs_statfs, &data, &len, "[s]", path);
    if(retval<0) {
        return retval;
    }
    CopyData(buf, data, sizeof(*buf), len);
    free(data);
    return retval;
}

int lind_noop (void)
{
    char* data;
    int len;
    int retval;
    int version = 0;
    retval = MakeLindSysCall(LIND_debug_noop, &data, &len, "[]");
    free(data);
    return retval;
}

int lind_getpid (pid_t * buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[])", LIND_sys_getpid);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_dup (int oldfd)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[i])", LIND_safe_fs_dup, oldfd);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_dup2 (int oldfd, int newfd)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_fs_dup, oldfd, newfd);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_getdents (int fd, size_t nbytes, char *buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_fs_getdents, fd, nbytes);
    LIND_API_PART2
    COPY_DATA(buf, nbytes)
    LIND_API_PART3
}

int lind_fcntl_get (int fd, int cmd)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_fs_fcntl, fd, cmd);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_fcntl_set (int fd, int cmd, long set_op)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iil])", LIND_safe_fs_fcntl, fd, cmd, set_op);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_socket (int domain, int type, int protocol)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iii])", LIND_safe_net_socket, domain, type, protocol);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_bind (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    LIND_API_PART1
    CHECK_NOT_NULL(addr)
    callArgs = Py_BuildValue("(i[iis#])", LIND_safe_net_bind, sockfd, addrlen, addr, addrlen);
    LIND_API_PART2
    LIND_API_PART3
}

ssize_t lind_send (int sockfd, const void *buf, size_t len, int flags)
{
    LIND_API_PART1
    CHECK_NOT_NULL(buf)
    callArgs = Py_BuildValue("(i[iiis#])", LIND_safe_net_send, sockfd, len, flags, buf, len);
    LIND_API_PART2
    LIND_API_PART3
}

ssize_t lind_recv (int sockfd, void *buf, size_t len, int flags)
{
    LIND_API_PART1
    CHECK_NOT_NULL(buf)
    callArgs = Py_BuildValue("(i[iii])", LIND_safe_net_recv, sockfd, len, flags);
    LIND_API_PART2
    COPY_DATA(buf, len)
    LIND_API_PART3
}

int lind_connect (int sockfd, const struct sockaddr *src_addr, socklen_t addrlen)
{
    LIND_API_PART1
    CHECK_NOT_NULL(src_addr)
    callArgs = Py_BuildValue("(i[iis#])", LIND_safe_net_connect, sockfd, addrlen, src_addr, addrlen);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_listen (int sockfd, int backlog)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_net_listen, sockfd, backlog);
    LIND_API_PART2
    LIND_API_PART3
}

ssize_t lind_sendto (int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{
    UNREFERENCED_PARAMETER(sockfd);
    UNREFERENCED_PARAMETER(len);
    UNREFERENCED_PARAMETER(flags);
    UNREFERENCED_PARAMETER(addrlen);
    UNREFERENCED_PARAMETER(dest_addr);
    UNREFERENCED_PARAMETER(buf);
    /*CHECK_NOT_NULL(dest_addr);
    CHECK_NOT_NULL(buf);
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iiiis#s#])", LIND_safe_net_sendto, sockfd, len, addrlen, dest_addr, addrlen, buf, len);
    LIND_API_PART2
    LIND_API_PART3*/

    // unimplemented
    return 0;
}

int lind_accept (int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_net_accept, sockfd, addrlen);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_getpeername (int sockfd, struct sockaddr *addr, socklen_t* addrlen)
{
    UNREFERENCED_PARAMETER(sockfd);
    UNREFERENCED_PARAMETER(addrlen_in);
    UNREFERENCED_PARAMETER(addr);
    UNREFERENCED_PARAMETER(addrlen_out);
    /*LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_net_getpeername, sockfd, addrlen);
    LIND_API_PART2
    LIND_API_PART3*/

    // unimplemented
    return 0;
}

int lind_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
    return 0;
}

int lind_setsockopt (int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
    LIND_API_PART1
    CHECK_NOT_NULL(optval)
    callArgs = Py_BuildValue("(i[iiiis#])", LIND_safe_net_setsockopt, sockfd, level, optname, optlen, optval, optlen);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_getsockopt (int sockfd, int level, int optname, void *optval, socklen_t* optlen)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iiii])", LIND_safe_net_getsockopt, sockfd, level, optname, *optlen);
    LIND_API_PART2
    COPY_DATA(optval, optlen)
    LIND_API_PART3
}

int lind_shutdown (int sockfd, int how)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_net_shutdown, sockfd, how);
    LIND_API_PART2
    LIND_API_PART3
}

int lind_select (int nfds, fd_set * readfds, fd_set * writefds, fd_set * exceptfds,
        struct timeval *timeout)
{
    PyObject* readFdObj = NULL;
    PyObject* writeFdObj = NULL;
    PyObject* exceptFdObj = NULL;
    PyObject* timeValObj = NULL;
    struct select_results *result;
    LIND_API_PART1
    if(readfds) {
        readFdObj = PyString_FromStringAndSize((char*)readfds, sizeof(fd_set));
    } else {
        readFdObj = Py_None;
        Py_INCREF(readFdObj);
    }
    if(writefds) {
        writeFdObj = PyString_FromStringAndSize((char*)writefds, sizeof(fd_set));
    } else {
        writeFdObj = Py_None;
        Py_INCREF(writeFdObj);
    }
    if(exceptfds) {
        exceptFdObj = PyString_FromStringAndSize((char*)exceptfds, sizeof(fd_set));
    } else {
        exceptFdObj = Py_None;
        Py_INCREF(exceptFdObj);
    }
    if(timeout) {
        timeValObj = PyString_FromStringAndSize((char*)timeout, sizeof(struct timeval));
    } else {
        timeValObj = Py_None;
        Py_INCREF(timeValObj);
    }
    callArgs = Py_BuildValue("(i[iOOOO])", LIND_safe_net_select, nfds, readFdObj,
            writeFdObj, exceptFdObj, timeValObj);
    Py_XDECREF(readFdObj);
    Py_XDECREF(writeFdObj);
    Py_XDECREF(exceptFdObj);
    Py_XDECREF(timeValObj);
    LIND_API_PART2
    COPY_DATA(result, sizeof(*result))
    LIND_API_PART3
}

int lind_getifaddrs (int ifaddrs_buf_siz, void *ifaddrs)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[i])", LIND_safe_net_getifaddrs, ifaddrs_buf_siz);
    LIND_API_PART2
    COPY_DATA(ifaddrs, ifaddrs_buf_siz)
    LIND_API_PART3
}

ssize_t lind_recvfrom (int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t * addrlen)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iiii])", LIND_safe_net_recvfrom, sockfd, len, flags, addrlen);
    LIND_API_PART2
    COPY_DATA_OFFSET(addrlen, sizeof(*addrlen), 3, 0)
    COPY_DATA_OFFSET(buf, len, 3, 1)
    COPY_DATA_OFFSET(src_addr, sizeof(*src_addr), 3, 2)
    LIND_API_PART3
}

int lind_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iis#])", LIND_safe_net_poll, nfds, timeout, fds, sizeof(struct pollfd)*nfds);
    LIND_API_PART2
    COPY_DATA(fds, sizeof(struct pollfd)*nfds)
    LIND_API_PART3
}

int lind_socketpair (int domain, int type, int protocol, int *fds)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[iii])", LIND_safe_net_socketpair, domain, type, protocol);
    LIND_API_PART2
    COPY_DATA(fds, sizeof(int)*2)
    LIND_API_PART3
}

int lind_getuid (uid_t * buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[])", LIND_safe_sys_getuid);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_geteuid (uid_t * buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[])", LIND_safe_sys_geteuid);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_getgid (gid_t * buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[])", LIND_safe_sys_getgid);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_getegid (gid_t * buf)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[])", LIND_safe_sys_getegid);
    LIND_API_PART2
    COPY_DATA(buf, sizeof(*buf))
    LIND_API_PART3
}

int lind_flock (int fd, int operation)
{
    LIND_API_PART1
    callArgs = Py_BuildValue("(i[ii])", LIND_safe_fs_flock, fd, operation);
    LIND_API_PART2
    LIND_API_PART3
}

char* lind_getcwd(char* buf, size_t size) {
    return NULL;
}


ssize_t lind_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
    return 0;
}
ssize_t lind_recvmsg(int sockfd, struct msghdr *msg, int flags) {
    return 0;
}


int lind_epoll_create(int size) {
    return 0;
}
int lind_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    return 0;
}
int lind_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    return 0;
}

int lind_fcntl(int fd, int cmd, ...) {
    return 0;
}

int lind_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    return 0;
}
