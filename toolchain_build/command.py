#!/usr/bin/python
# Copyright (c) 2012 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Class capturing a command invocation as data."""


# Done first to setup python module path.
import toolchain_env

import inspect

import os
import shutil
import sys

import file_tools
import log_tools


# MSYS tools do not always work with combinations of Windows and MSYS
# path conventions, e.g. '../foo\\bar' doesn't find '../foo/bar'.
# Since we convert all the directory names to MSYS conventions, we
# should not be using Windows separators with those directory names.
# As this is really an implementation detail of this module, we export
# 'command.path' to use in place of 'os.path', rather than having
# users of the module know which flavor to use.
import posixpath
path = posixpath


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NACL_DIR = os.path.dirname(SCRIPT_DIR)

# Read this module's source file just once, to use in hashes for Callbacks.
# Don't directly use __file__ because it could be e.g. command.pyc
with open(os.path.join(SCRIPT_DIR, 'command.py')) as f:
  FILE_CONTENT = f.read()


def PlatformEnvironment(extra_paths):
  """Select the environment variables to run commands with.

  Args:
    extra_paths: Extra paths to add to the PATH variable.
  Returns:
    A dict to be passed as env to subprocess.
  """
  env = os.environ.copy()
  paths = []
  if sys.platform == 'win32':
    if Runnable.use_cygwin:
      # Use the hermetic cygwin.
      paths = [os.path.join(NACL_DIR, 'cygwin', 'bin')]
    else:
      # TODO(bradnelson): switch to something hermetic.
      mingw = os.environ.get('MINGW', r'c:\mingw')
      msys = os.path.join(mingw, 'msys', '1.0')
      if not os.path.exists(msys):
        msys = os.path.join(mingw, 'msys')
      # We need both msys (posix like build environment) and MinGW (windows
      # build of tools like gcc). We add <MINGW>/msys/[1.0/]bin to the path to
      # get sh.exe. We add <MINGW>/bin to allow direct invocation on MinGW
      # tools. We also add an msys style path (/mingw/bin) to get things like
      # gcc from inside msys.
      paths = [
          '/mingw/bin',
          os.path.join(mingw, 'bin'),
          os.path.join(msys, 'bin'),
      ]
  env['PATH'] = os.pathsep.join(
      paths + extra_paths + env.get('PATH', '').split(os.pathsep))
  return env


class Runnable(object):
  """An object representing a single command."""
  use_cygwin = False

  def __init__(self, func, *args, **kwargs):
    """Construct a runnable which will call 'func' with 'args' and 'kwargs'.

    Args:
      func: Function which will be called by Invoke
      args: Positional arguments to be passed to func
      kwargs: Keyword arguments to be passed to func

      RUNNABLES SHOULD ONLY BE IMPLEMENTED IN THIS FILE, because their
      string representation (which is used to calculate whether targets should
      be rebuilt) is based on this file's hash and does not attempt to capture
      the code or bound variables of the function itself (the one exception is
      once_test.py which injects its own callbacks to verify its expectations).

      When 'func' is called, its first argument will be a substitution object
      which it can use to substitute %-templates in its arguments.
    """
    self._func = func
    self._args = args or []
    self._kwargs = kwargs or {}

  def __str__(self):
    values = []

    sourcefile = inspect.getsourcefile(self._func)
    if ('command.py' not in sourcefile and
        'once_test.py' not in sourcefile):
      print 'Function', self._func.func_name, 'in', sourcefile
      raise Exception('Python Runnable objects must be implemented in ' +
                        'command.py!')

    for v in self._args:
      values += [repr(v)]
    for k, v in self._kwargs.iteritems():
      values += [repr(k), repr(v)]
    values += [FILE_CONTENT]

    return '\n'.join(values)

  def Invoke(self, subst):
    return self._func(subst, *self._args, **self._kwargs)


def Command(command, **kwargs):
  """Return a Runnable which invokes 'command' with check_call.

  Args:
    command: List or string with a command suitable for check_call
    kwargs: Keyword arguments suitable for check_call (or 'cwd' or 'path_dirs')

  The command will be %-substituted and paths will be assumed to be relative to
  the cwd given by Invoke. If kwargs contains 'cwd' it will be appended to the
  cwd given by Invoke and used as the cwd for the call. If kwargs contains
  'path_dirs', the directories therein will be added to the paths searched for
  the command. Any other kwargs will be passed to check_call.
  """
  def runcmd(subst, command, **kwargs):
    check_call_kwargs = kwargs.copy()
    command = command[:]

    cwd = subst.SubstituteAbsPaths(check_call_kwargs.get('cwd', '.'))
    subst.SetCwd(cwd)
    check_call_kwargs['cwd'] = cwd

    # Extract paths from kwargs and add to the command environment.
    path_dirs = []
    if 'path_dirs' in check_call_kwargs:
      path_dirs = [subst.Substitute(dirname) for dirname
                   in check_call_kwargs['path_dirs']]
      del check_call_kwargs['path_dirs']
    check_call_kwargs['env'] = PlatformEnvironment(path_dirs)

    if isinstance(command, str):
      command = subst.Substitute(command)
    else:
      command = [subst.Substitute(arg) for arg in command]
      paths = check_call_kwargs['env']['PATH'].split(os.pathsep)
      command[0] = file_tools.Which(command[0], paths=paths)

    log_tools.CheckCall(command, **check_call_kwargs)

  return Runnable(runcmd, command, **kwargs)


def Mkdir(path, parents=False):
  """Convenience method for generating mkdir commands."""
  def mkdir(subst, path):
    path = subst.SubstituteAbsPaths(path)
    if parents:
      os.makedirs(path)
    else:
      os.mkdir(path)
  return Runnable(mkdir, path)


def Copy(src, dst):
  """Convenience method for generating cp commands."""
  def copy(subst, src, dst):
    shutil.copyfile(subst.SubstituteAbsPaths(src),
                    subst.SubstituteAbsPaths(dst))
  return Runnable(copy, src, dst)


def RemoveDirectory(path):
  """Convenience method for generating a command to remove a directory tree."""
  def remove(subst, path):
    file_tools.RemoveDirectoryIfPresent(subst.SubstituteAbsPaths(path))
  return Runnable(remove, path)


def Remove(path):
  """Convenience method for generating a command to remove a file."""
  def remove(subst, path):
    path = subst.SubstituteAbsPaths(path)
    if os.path.exists(path):
      os.remove(path)
  return Runnable(remove, path)


def Rename(src, dst):
  """Convenience method for generating a command to rename a file."""
  def rename(subst, src, dst):
    os.rename(subst.SubstituteAbsPaths(src), subst.SubstituteAbsPaths(dst))
  return Runnable(rename, src, dst)


def WriteData(data, dst):
  """Convenience method to write a file with fixed contents."""
  def writedata(subst, dst, data):
    with open(subst.SubstituteAbsPaths(dst), 'wb') as f:
      f.write(data)
  return Runnable(writedata, dst, data)
