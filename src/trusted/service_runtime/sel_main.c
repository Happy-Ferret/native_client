/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * NaCl Simple/secure ELF loader (NaCl SEL).
 */
#include "native_client/src/include/portability.h"
#include "native_client/src/include/portability_io.h"

#if NACL_OSX
#include <crt_externs.h>
#endif

#if NACL_LINUX
#include <getopt.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "native_client/src/shared/gio/gio.h"
#include "native_client/src/shared/imc/nacl_imc_c.h"
#include "native_client/src/shared/platform/nacl_check.h"
#include "native_client/src/shared/platform/nacl_exit.h"
#include "native_client/src/shared/platform/nacl_log.h"
#include "native_client/src/shared/platform/nacl_sync.h"
#include "native_client/src/shared/platform/nacl_sync_checked.h"
#include "native_client/src/shared/srpc/nacl_srpc.h"

#include "native_client/src/trusted/desc/nacl_desc_base.h"
#include "native_client/src/trusted/desc/nacl_desc_io.h"
#include "native_client/src/trusted/fault_injection/fault_injection.h"
#include "native_client/src/trusted/fault_injection/test_injection.h"
#include "native_client/src/trusted/perf_counter/nacl_perf_counter.h"
#include "native_client/src/trusted/service_runtime/env_cleanser.h"
#include "native_client/src/trusted/service_runtime/include/sys/fcntl.h"
#include "native_client/src/trusted/service_runtime/load_file.h"
#include "native_client/src/trusted/service_runtime/nacl_app.h"
#include "native_client/src/trusted/service_runtime/nacl_all_modules.h"
#include "native_client/src/trusted/service_runtime/nacl_bootstrap_channel_error_reporter.h"
#include "native_client/src/trusted/service_runtime/nacl_debug_init.h"
#include "native_client/src/trusted/service_runtime/nacl_error_log_hook.h"
#include "native_client/src/trusted/service_runtime/nacl_globals.h"
#include "native_client/src/trusted/service_runtime/nacl_signal.h"
#include "native_client/src/trusted/service_runtime/nacl_syscall_common.h"
#include "native_client/src/trusted/service_runtime/nacl_valgrind_hooks.h"
#include "native_client/src/trusted/service_runtime/osx/mach_exception_handler.h"
#include "native_client/src/trusted/service_runtime/outer_sandbox.h"
#include "native_client/src/trusted/service_runtime/sel_ldr.h"
#include "native_client/src/trusted/service_runtime/sel_qualify.h"
#include "native_client/src/trusted/service_runtime/win/exception_patch/ntdll_patch.h"
#include "native_client/src/trusted/service_runtime/win/debug_exception_handler.h"
#include "native_client/src/trusted/service_runtime/lind_syscalls.h"

// yiwen
#include "native_client/src/trusted/service_runtime/sel_ldr.h"
#include "native_client/src/trusted/service_runtime/include/bits/nacl_syscalls.h"
#include <time.h>
#include <sys/shm.h>
#include <sys/mman.h>

#define SHM_SIZE 4096*2

extern int nacl_syscall_counter;
extern int nacl_syscall_invoked_times[NACL_MAX_SYSCALLS];
extern double nacl_syscall_execution_time[NACL_MAX_SYSCALLS];
extern int lind_syscall_counter;
extern int lind_syscall_invoked_times[LIND_MAX_SYSCALLS];
extern double lind_syscall_execution_time[LIND_MAX_SYSCALLS];
extern int nacl_syscall_trace_level_counter;

// yiwen 
// set up the cage id
// set up the fd table for the cage
static void InitializeCage(struct NaClApp *nap, int cage_id) {
  nap->cage_id = cage_id;  
  nap->num_children = 0;  
  nap->num_lib = 3;
  fd_cage_table[cage_id][0] = 0;
  fd_cage_table[cage_id][1] = 1;
  fd_cage_table[cage_id][2] = 2;
  nap->fd = 3; // fd will start with 3, since 0, 1, 2 are reserved  
}

static void (*g_enable_outer_sandbox_func)(void) =
#if NACL_OSX
    NaClEnableOuterSandbox;
#else
    NULL;
#endif

void NaClSetEnableOuterSandboxFunc(void (*func)(void)) {
  g_enable_outer_sandbox_func = func;
}

static void VmentryPrinter(void           *state,
                    struct NaClVmmapEntry *vmep) {
  UNREFERENCED_PARAMETER(state);
  printf("page num 0x%06x\n", (uint32_t)vmep->page_num);
  printf("num pages %d\n", (uint32_t)vmep->npages);
  printf("prot bits %x\n", vmep->prot);
  fflush(stdout);
}

static void PrintVmmap(struct NaClApp  *nap) {
  printf("In PrintVmmap\n");
  fflush(stdout);
  NaClXMutexLock(&nap->mu);
  NaClVmmapVisit(&nap->mem_map, VmentryPrinter, (void *) 0);

  NaClXMutexUnlock(&nap->mu);
}


struct redir {
  struct redir  *next;
  int           nacl_desc;
  enum {
    HOST_DESC,
    IMC_DESC
  }             tag;
  union {
    struct {
      int d;
      int mode;
    }                         host;
    NaClHandle                handle;
    struct NaClSocketAddress  addr;
  } u;
};

int ImportModeMap(char opt) {
  switch (opt) {
    case 'h':
      return O_RDWR;
    case 'r':
      return O_RDONLY;
    case 'w':
      return O_WRONLY;
  }
  fprintf(stderr, ("option %c not understood as a host descriptor"
                   " import mode\n"),
          opt);
  exit(1);
  /* NOTREACHED */
}

static void PrintUsage(void) {
  /* NOTE: this is broken up into multiple statements to work around
           the constant string size limit */
  fprintf(stderr,
          "Usage: sel_ldr [-h d:D] [-r d:D] [-w d:D] [-i d:D]\n"
          "               [-f nacl_file]\n"
          "               [-l log_file]\n"
          "               [-X d] [-acFglQRsSQv]\n"
          "               -- [nacl_file] [args]\n"
          "\n");
  fprintf(stderr,
          " -h\n"
          " -r\n"
          " -w associate a host POSIX descriptor D with app desc d\n"
          "    that was opened in O_RDWR, O_RDONLY, and O_WRONLY modes\n"
          "    respectively\n"
          " -i associates an IMC handle D with app desc d\n"
          " -f file to load; if omitted, 1st arg after \"--\" is loaded\n"
          " -B additional ELF file to load as a blob library\n"
          " -v increases verbosity\n"
          " -X create a bound socket and export the address via an\n"
          "    IMC message to a corresponding inherited IMC app descriptor\n"
          "    (use -1 to create the bound socket / address descriptor\n"
          "    pair, but that no export via IMC should occur)\n");
  fprintf(stderr,
          " -R an RPC supplies the NaCl module.\n"
          "    No nacl_file argument is expected, and the -f flag cannot be\n"
          "    used with this flag.\n"
          "\n"
          " (testing flags)\n"
          " -a allow file access plus some other syscalls! dangerous!\n"
          " -c ignore validator! dangerous! Repeating this option twice skips\n"
          "    validation completely.\n"
          " -F fuzz testing; quit after loading NaCl app\n"
          " -g enable gdb debug stub.  Not secure on x86-64 Windows.\n"
          " -l <file>  write log output to the given file\n"
          " -Q disable platform qualification (dangerous!)\n"
          " -s safely stub out non-validating instructions\n"
          " -S enable signal handling.  Not supported on Windows.\n"
          " -E <name=value>|<name> set an environment variable\n"
          " -Z use fixed feature x86 CPU mode\n"
          );  /* easier to add new flags/lines */
}

#if NACL_LINUX
static const struct option longopts[] = {
  { "r_debug", required_argument, NULL, 'D' },
  { "reserved_at_zero", required_argument, NULL, 'z' },
  { NULL, 0, NULL, 0 }
};

static int my_getopt(int argc, char *const *argv, const char *shortopts) {
  return getopt_long(argc, argv, shortopts, longopts, NULL);
}
#else
#define my_getopt getopt
#endif

int NaClSelLdrMain(int argc, char **argv) {
  int                           opt;
  char                          *rest;
  struct redir                  *entry;
  struct redir                  *redir_queue;
  struct redir                  **redir_qend;


  struct NaClApp                state;
  char                          *nacl_file = NULL;
  char                          *blob_library_file = NULL;
  int                           rpc_supplies_nexe = 0;
  int                           export_addr_to = -1;

  struct NaClApp                *nap = &state;

  // yiwen: added a second nap(cage), call it nap2.
  // we need to set up both state2 and nap2 properly, before loading file into nap2.
  struct NaClApp                state2;
  struct NaClApp                *nap2 = &state2;

  // yiwen: added a third cage, nap3. 
  struct NaClApp                state3;
  struct NaClApp                *nap3 = &state3;
  
  // argc2 and argv2 defines the NaCl file we want to run for nap2.
  // they will be used when we try to create the thread.
  int argc2;
  char **argv2;

  struct GioFile                gout;
  NaClErrorCode                 errcode = LOAD_INTERNAL;
  struct NaClDesc               *blob_file = NULL;

  int                           ret_code;
  struct DynArray               env_vars;

  char                          *log_file = NULL;
  int                           verbosity = 0;
  int                           fuzzing_quit_after_load = 0;
  int                           debug_mode_bypass_acl_checks = 0;
  int                           debug_mode_ignore_validator = 0;
  int                           skip_qualification = 0;
  int                           handle_signals = 0;
  int                           enable_debug_stub = 0;
  struct NaClPerfCounter        time_all_main;
  const char                    **envp;
  struct NaClEnvCleanser        env_cleanser;
 
  // yiwen
  char                          *nacl_file2 = NULL;

  // yiwen: define variables for doing evaluation measurement
  clock_t 			nacl_main_begin;
  clock_t			nacl_main_finish;
  clock_t			nacl_initialization_finish;
  double			nacl_main_spent;
  double			nacl_initialization_spent;

  clock_t 			nacl_user_program_begin;
  clock_t 			nacl_user_program_finish;
  double			nacl_user_program_spent;
  #ifdef SYSCALL_TIMING
  int				i;
  double			nacl_syscall_total_time;
  double			lind_syscall_total_time;
  #endif

  // yiwen: testing mmap
  /*
  int shmid; 
  char *reg1;
  char *reg2;
  char *reg3;
  int data_size;
  void *reg1_ptr;
  void *reg2_ptr;
  void *reg3_ptr; */

  // yiwen: testing cow mapping
  /*
  int shm_fd;
  char *shm_buf1;
  char *shm_buf2;
  void *cage1_ptr; */

  // yiwen: variables used to create our named pipe
  char * myfifo;
  int myfifo_fd;
  char user_input[256];  

  // yiwen: variables used when processing the user input command from the client program
  int j;
  int k;
  int is_new_argument;

#if NACL_OSX
  /* Mac dynamic libraries cannot access the environ variable directly. */
  envp = (const char **) *_NSGetEnviron();
#else
  /* Overzealous code style check is overzealous. */
  /* @IGNORE_LINES_FOR_CODE_HYGIENE[1] */
  extern char **environ;
  envp = (const char **) environ;
#endif

  // yiwen: initialize the syscall_counter
  // NaClLog(LOG_WARNING, "[NaCl Main Loader] NaCl Loader started! \n\n");
  nacl_syscall_counter = 0;
  lind_syscall_counter = 0;
  nacl_syscall_trace_level_counter = 0;

  // yiwen: time measurement, record the start time of the NaCl main program
  nacl_main_begin = clock();

  ret_code = 1;
  redir_queue = NULL;
  redir_qend = &redir_queue;

  memset(&state, 0, sizeof state);
  // yiwen: my code, setting up nap2(cage2)
  memset(&state2, 0, sizeof state2);
  // yiwen: nap0 is shared with nacl_syscall_common.c
  // we use it to store the snapshot of an initial cage, which is ready to run a program(create a thread)
  // this snapshot is used by execv()
  nap0 = &state0;
  nap0_2 = &state0_2;
  nap_ready = &state_ready;
  nap_ready_2 = &state_ready_2;
  memset(&state0, 0, sizeof state0);
  memset(&state0_2, 0, sizeof state0_2);
  // yiwen: my code, setting up nap3(cage3)
  memset(&state_ready, 0, sizeof state_ready);
  memset(&state_ready_2, 0, sizeof state_ready_2);
  memset(&state3, 0, sizeof state3);

  NaClAllModulesInit();
  NaClBootstrapChannelErrorReporterInit();
  NaClErrorLogHookInit(NaClBootstrapChannelErrorReporter, &state);

  verbosity = NaClLogGetVerbosity();

  NaClPerfCounterCtor(&time_all_main, "SelMain");

  fflush((FILE *) NULL);

  NaClDebugExceptionHandlerStandaloneHandleArgs(argc, argv);

  if (!GioFileRefCtor(&gout, stdout)) {
    fprintf(stderr, "Could not create general standard output channel\n");
    exit(1);
  }
  if (!NaClAppCtor(&state)) {
    NaClLog(LOG_FATAL, "NaClAppCtor() failed\n");
  }
  // yiwen: my code
  if (!NaClAppCtor(&state2)) {
    NaClLog(LOG_FATAL, "NaClAppCtor() failed\n");
  }
  if (!NaClAppCtor(&state3)) {
    NaClLog(LOG_FATAL, "NaClAppCtor() failed\n");
  }
  // yiwen
  if (!NaClAppCtor(&state0)) {
    NaClLog(LOG_FATAL, "NaClAppCtor() failed\n");
  }
  if (!NaClAppCtor(&state0_2)) {
    NaClLog(LOG_FATAL, "NaClAppCtor() failed\n");
  }
  // yiwen
  if (!NaClAppCtor(&state_ready)) {
    NaClLog(LOG_FATAL, "NaClAppCtor() failed\n");
  }
  if (!NaClAppCtor(&state_ready_2)) {
    NaClLog(LOG_FATAL, "NaClAppCtor() failed\n");
  }
  if (!DynArrayCtor(&env_vars, 0)) {
    NaClLog(LOG_FATAL, "Failed to allocate env var array\n");
  }
  /*
   * On platforms with glibc getopt, require POSIXLY_CORRECT behavior,
   * viz, no reordering of the arglist -- stop argument processing as
   * soon as an unrecognized argument is encountered, so that, for
   * example, in the invocation
   *
   *   sel_ldr foo.nexe -vvv
   *
   * the -vvv flags are made available to the nexe, rather than being
   * consumed by getopt.  This makes the behavior of the Linux build
   * of sel_ldr consistent with the Windows and OSX builds.
   */
  while ((opt = my_getopt(argc, argv,
#if NACL_LINUX
                       "+D:z:"
#endif
                       "aB:ceE:f:Fgh:i:l:Qr:RsSvw:X:Z")) != -1) {
    switch (opt) {
      case 'a':
        fprintf(stderr, "DEBUG MODE ENABLED (bypass acl)\n");
        debug_mode_bypass_acl_checks = 1;
        break;
      case 'B':
        blob_library_file = optarg;
        break;
      case 'c':
        ++debug_mode_ignore_validator;
        break;
#if NACL_LINUX
      case 'D':
        NaClHandleRDebug(optarg, argv[0]);
        break;
#endif
      case 'e':
        nap->enable_exception_handling = 1;
        break;
      case 'E':
        /*
         * For simplicity, we treat the environment variables as a
         * list of strings rather than a key/value mapping.  We do not
         * try to prevent duplicate keys or require the strings to be
         * of the form "KEY=VALUE".  This is in line with how execve()
         * works in Unix.
         *
         * We expect that most callers passing "-E" will either pass
         * in a fixed list or will construct the list using a
         * high-level language, in which case de-duplicating keys
         * outside of sel_ldr is easier.  However, we could do
         * de-duplication here if it proves to be worthwhile.
         */
        if (!DynArraySet(&env_vars, env_vars.num_entries, optarg)) {
          NaClLog(LOG_FATAL, "Adding item to env_vars failed\n");
        }
        break;
      case 'f':
        nacl_file = optarg;
        break;
      case 'F':
        fuzzing_quit_after_load = 1;
        break;

      case 'g':
        enable_debug_stub = 1;
        break;

      case 'h':
      case 'r':
      case 'w':
        /* import host descriptor */
        entry = malloc(sizeof *entry);
        if (NULL == entry) {
          fprintf(stderr, "No memory for redirection queue\n");
          exit(1);
        }
        entry->next = NULL;
        entry->nacl_desc = strtol(optarg, &rest, 0);
        entry->tag = HOST_DESC;
        entry->u.host.d = strtol(rest+1, (char **) 0, 0);
        entry->u.host.mode = ImportModeMap(opt);
        *redir_qend = entry;
        redir_qend = &entry->next;
        break;
      case 'i':
        /* import IMC handle */
        entry = malloc(sizeof *entry);
        if (NULL == entry) {
          fprintf(stderr, "No memory for redirection queue\n");
          exit(1);
        }
        entry->next = NULL;
        entry->nacl_desc = strtol(optarg, &rest, 0);
        entry->tag = IMC_DESC;
        entry->u.handle = (NaClHandle) strtol(rest+1, (char **) 0, 0);
        *redir_qend = entry;
        redir_qend = &entry->next;
        break;
      case 'l':
        log_file = optarg;
        break;
      case 'Q':
        fprintf(stderr, "PLATFORM QUALIFICATION DISABLED BY -Q - "
                "Native Client's sandbox will be unreliable!\n");
        skip_qualification = 1;
        break;
      case 'R':
        rpc_supplies_nexe = 1;
        break;
      /* case 'r':  with 'h' and 'w' above */
      case 's':
        if (nap->validator->stubout_mode_implemented) {
          nap->validator_stub_out_mode = 1;
        } else {
           NaClLog(LOG_WARNING,
                   "stub_out_mode is not supported, disabled\n");
        }
        break;
      case 'S':
        handle_signals = 1;
        break;
      case 'v':
        ++verbosity;
        NaClLogIncrVerbosity();
        break;
      /* case 'w':  with 'h' and 'r' above */
      case 'X':
        export_addr_to = strtol(optarg, (char **) 0, 0);
        break;
#if NACL_LINUX
      case 'z':
        NaClHandleReservedAtZero(optarg);
        break;
#endif
      case 'Z':
        if (nap->validator->readonly_text_implemented) {
          NaClLog(LOG_WARNING, "Enabling Fixed-Feature CPU Mode\n");
          nap->fixed_feature_cpu_mode = 1;
          if (!nap->validator->FixCPUFeatures(nap->cpu_features)) {
            NaClLog(LOG_ERROR,
                    "This CPU lacks features required by "
                    "fixed-function CPU mode.\n");
            exit(1);
          }
        } else {
           NaClLog(LOG_ERROR,
                   "fixed_feature_cpu_mode is not supported\n");
           exit(1);
        }
        break;
      default:
        fprintf(stderr, "ERROR: unknown option: [%c]\n\n", opt);
        PrintUsage();
        exit(-1);
    }
  }

  // time_start = clock();
  if(!LindPythonInit()) {
      fflush(NULL);
      exit(1);
  }
  // time_end = clock();
  // time_counter = (double)(time_end - time_start) / CLOCKS_PER_SEC;

  if (debug_mode_ignore_validator == 1)
    fprintf(stderr, "DEBUG MODE ENABLED (ignore validator)\n");
  else if (debug_mode_ignore_validator > 1)
    fprintf(stderr, "DEBUG MODE ENABLED (skip validator)\n");

  if (verbosity) {
    int         ix;
    char const  *separator = "";

    fprintf(stderr, "sel_ldr argument list:\n");
    for (ix = 0; ix < argc; ++ix) {
      fprintf(stderr, "%s%s", separator, argv[ix]);
      separator = " ";
    }
    putc('\n', stderr);
  }

  if (debug_mode_bypass_acl_checks) {
    NaClInsecurelyBypassAllAclChecks();
  }

  /*
   * change stdout/stderr to log file now, so that subsequent error
   * messages will go there.  unfortunately, error messages that
   * result from getopt processing -- usually out-of-memory, which
   * shouldn't happen -- won't show up.
   */
  if (NULL != log_file) {
    NaClLogSetFile(log_file);
  }

  if (rpc_supplies_nexe) {
    if (NULL != nacl_file) {
      fprintf(stderr,
              "sel_ldr: mutually exclusive flags -f and -R both used\n");
      exit(1);
    }
    /* post: NULL == nacl_file */
    if (export_addr_to < 0) {
      fprintf(stderr,
              "sel_ldr: -R requires -X to set up secure command channel\n");
      exit(1);
    }
  } else {
    if (NULL == nacl_file && optind < argc) {
      nacl_file = argv[optind];
      ++optind;
    }
    if (NULL == nacl_file) {
      fprintf(stderr, "No nacl file specified\n");
      exit(1);
    }
    /* post: NULL != nacl_file */
  }
  /*
   * post condition established by the above code (in Hoare logic
   * terminology):
   *
   * NULL == nacl_file iff rpc_supplies_nexe
   *
   * so hence forth, testing !rpc_supplies_nexe suffices for
   * establishing NULL != nacl_file.
   */
  CHECK((NULL == nacl_file) == rpc_supplies_nexe);

  /* to be passed to NaClMain, eventually... */
  argv[--optind] = (char *) "NaClMain";

  state.ignore_validator_result = (debug_mode_ignore_validator > 0);
  state.skip_validator = (debug_mode_ignore_validator > 1);

  if (getenv("NACL_UNTRUSTED_EXCEPTION_HANDLING") != NULL) {
    state.enable_exception_handling = 1;
  }
  /*
   * TODO(mseaborn): Always enable the Mach exception handler on Mac
   * OS X, and remove handle_signals and sel_ldr's "-S" option.
   */
  if (state.enable_exception_handling || enable_debug_stub ||
      (handle_signals && NACL_OSX)) {
#if NACL_WINDOWS
    state.attach_debug_exception_handler_func =
        NaClDebugExceptionHandlerStandaloneAttach;
#elif NACL_LINUX
    /* NaCl's signal handler is always enabled on Linux. */
#elif NACL_OSX
    if (!NaClInterceptMachExceptions()) {
      fprintf(stderr, "ERROR setting up Mach exception interception.\n");
      return -1;
    }
#else
# error Unknown host OS
#endif
  }

  errcode = LOAD_OK;

  /*
   * in order to report load error to the browser plugin through the
   * secure command channel, we do not immediate jump to cleanup code
   * on error.  rather, we continue processing (assuming earlier
   * errors do not make it inappropriate) until the secure command
   * channel is set up, and then bail out.
   */

  /*
   * Ensure the platform qualification checks pass.
   *
   * NACL_DANGEROUS_SKIP_QUALIFICATION_TEST is used by tsan / memcheck
   * (see src/third_party/valgrind/).
   */
  if (!skip_qualification &&
      getenv("NACL_DANGEROUS_SKIP_QUALIFICATION_TEST") != NULL) {
    fprintf(stderr, "PLATFORM QUALIFICATION DISABLED BY ENVIRONMENT - "
            "Native Client's sandbox will be unreliable!\n");
    skip_qualification = 1;
  }

  if (!skip_qualification) {
    // yiwen: temporarily skip this(caused gdb segmentation fault, the seg fault signal was ignored somehow when not running gdb.)
    // NaClErrorCode pq_error = NACL_FI_VAL("pq", NaClErrorCode,
    //                                     NaClRunSelQualificationTests());
    // yiwen: temporarily define pq_error here, and assume that everything is Okay. 
    NaClErrorCode pq_error = LOAD_OK;
    if (LOAD_OK != pq_error) {
      errcode = pq_error;
      nap->module_load_status = pq_error;
      // yiwen
      nap2->module_load_status = pq_error;

      fprintf(stderr, "Error while loading \"%s\": %s\n",
              NULL != nacl_file ? nacl_file
                                : "(no file, to-be-supplied-via-RPC)",
              NaClErrorString(errcode));
    }
  }

#if NACL_LINUX
  NaClSignalHandlerInit();
#endif
  /*
   * Patch the Windows exception dispatcher to be safe in the case of
   * faults inside x86-64 sandboxed code.  The sandbox is not secure
   * on 64-bit Windows without this.
   */
#if (NACL_WINDOWS && NACL_ARCH(NACL_BUILD_ARCH) == NACL_x86 && \
     NACL_BUILD_SUBARCH == 64)
  NaClPatchWindowsExceptionDispatcher();
#endif
  NaClSignalTestCrashOnStartup();

  /*
   * Open both files first because (on Mac OS X at least)
   * NaClAppLoadFile() enables an outer sandbox.
   */
  if (NULL != blob_library_file) {
    NaClFileNameForValgrind(blob_library_file);
    blob_file = (struct NaClDesc *) NaClDescIoDescOpen(blob_library_file,
                                                       NACL_ABI_O_RDONLY, 0);
    if (NULL == blob_file) {
      perror("sel_main");
      fprintf(stderr, "Cannot open \"%s\".\n", blob_library_file);
      exit(1);
    }
    NaClPerfCounterMark(&time_all_main, "SnapshotBlob");
    NaClPerfCounterIntervalLast(&time_all_main);
  }

  NaClAppInitialDescriptorHookup(nap);
  // yiwen
  NaClAppInitialDescriptorHookup(nap2);
  NaClAppInitialDescriptorHookup(nap3);
  // yiwen
  NaClAppInitialDescriptorHookup(nap0);
  NaClAppInitialDescriptorHookup(nap0_2);
  NaClAppInitialDescriptorHookup(nap_ready);
  NaClAppInitialDescriptorHookup(nap_ready_2);

  if (!rpc_supplies_nexe) {
    if (LOAD_OK == errcode) {
      NaClLog(2, "Loading nacl file %s (non-RPC)\n", nacl_file);
      // yiwen: this is where an nexe binary got loaded as an nap. 
      //        we should load a second nap here. 
      nacl_file2 = (char*) malloc(22 * sizeof(char));
      strncpy(nacl_file2, "/glibc/runnable-ld.so", 22);

      // yiwen
      // time_start = clock();
      errcode = NaClAppLoadFileFromFilename(nap, nacl_file2);
      // time_end = clock();
      // time_counter = (double)(time_end - time_start) / CLOCKS_PER_SEC;

      if (LOAD_OK != errcode) {
        fprintf(stderr, "Error while loading \"%s\": %s\n",
                nacl_file,
                NaClErrorString(errcode));
        fprintf(stderr,
                ("Using the wrong type of nexe (nacl-x86-32"
                 " on an x86-64 or vice versa)\n"
                 "or a corrupt nexe file may be"
                 " responsible for this error.\n"));
      }

      // yiwen: load NaCl file to nap2
      errcode = NaClAppLoadFileFromFilename(nap2, nacl_file);    
      if (LOAD_OK != errcode) {
        fprintf(stderr, "Error while loading \"%s\": %s\n",
                nacl_file,
                NaClErrorString(errcode));
        fprintf(stderr,
                ("Using the wrong type of nexe (nacl-x86-32"
                 " on an x86-64 or vice versa)\n"
                 "or a corrupt nexe file may be"
                 " responsible for this error.\n"));
      }

      // yiwen: load NaCl file to nap3
      errcode = NaClAppLoadFileFromFilename(nap3, nacl_file);    
      if (LOAD_OK != errcode) {
        fprintf(stderr, "Error while loading \"%s\": %s\n",
                nacl_file,
                NaClErrorString(errcode));
        fprintf(stderr,
                ("Using the wrong type of nexe (nacl-x86-32"
                 " on an x86-64 or vice versa)\n"
                 "or a corrupt nexe file may be"
                 " responsible for this error.\n"));
      }

      // yiwen: load NaCl file to nap0
      errcode = NaClAppLoadFileFromFilename(nap0, nacl_file);    
      if (LOAD_OK != errcode) {
        fprintf(stderr, "Error while loading \"%s\": %s\n",
                nacl_file,
                NaClErrorString(errcode));
        fprintf(stderr,
                ("Using the wrong type of nexe (nacl-x86-32"
                 " on an x86-64 or vice versa)\n"
                 "or a corrupt nexe file may be"
                 " responsible for this error.\n"));
      } 

      // yiwen: load NaCl file to nap0_2
      errcode = NaClAppLoadFileFromFilename(nap0_2, nacl_file);    
      if (LOAD_OK != errcode) {
        fprintf(stderr, "Error while loading \"%s\": %s\n",
                nacl_file,
                NaClErrorString(errcode));
        fprintf(stderr,
                ("Using the wrong type of nexe (nacl-x86-32"
                 " on an x86-64 or vice versa)\n"
                 "or a corrupt nexe file may be"
                 " responsible for this error.\n"));
      }

      // yiwen: load NaCl file to nap_ready
      errcode = NaClAppLoadFileFromFilename(nap_ready, nacl_file);    
      if (LOAD_OK != errcode) {
        fprintf(stderr, "Error while loading \"%s\": %s\n",
                nacl_file,
                NaClErrorString(errcode));
        fprintf(stderr,
                ("Using the wrong type of nexe (nacl-x86-32"
                 " on an x86-64 or vice versa)\n"
                 "or a corrupt nexe file may be"
                 " responsible for this error.\n"));
      } 

      // yiwen: load NaCl file to nap_ready_2
      errcode = NaClAppLoadFileFromFilename(nap_ready_2, nacl_file);    
      if (LOAD_OK != errcode) {
        fprintf(stderr, "Error while loading \"%s\": %s\n",
                nacl_file,
                NaClErrorString(errcode));
        fprintf(stderr,
                ("Using the wrong type of nexe (nacl-x86-32"
                 " on an x86-64 or vice versa)\n"
                 "or a corrupt nexe file may be"
                 " responsible for this error.\n"));
      } 

      NaClPerfCounterMark(&time_all_main, "AppLoadEnd");
      NaClPerfCounterIntervalLast(&time_all_main);

      NaClXMutexLock(&nap->mu);
      nap->module_load_status = errcode;
      NaClXCondVarBroadcast(&nap->cv);
      NaClXMutexUnlock(&nap->mu);

      // yiwen
      NaClXMutexLock(&nap2->mu);
      nap2->module_load_status = errcode;
      NaClXCondVarBroadcast(&nap2->cv);
      NaClXMutexUnlock(&nap2->mu);

      NaClXMutexLock(&nap3->mu);
      nap3->module_load_status = errcode;
      NaClXCondVarBroadcast(&nap3->cv);
      NaClXMutexUnlock(&nap3->mu);

      // yiwen
      NaClXMutexLock(&nap0->mu);
      nap0->module_load_status = errcode;
      NaClXCondVarBroadcast(&nap0->cv);
      NaClXMutexUnlock(&nap0->mu);

      NaClXMutexLock(&nap0_2->mu);
      nap0_2->module_load_status = errcode;
      NaClXCondVarBroadcast(&nap0_2->cv);
      NaClXMutexUnlock(&nap0_2->mu);

      // yiwen
      NaClXMutexLock(&nap_ready->mu);
      nap_ready->module_load_status = errcode;
      NaClXCondVarBroadcast(&nap_ready->cv);
      NaClXMutexUnlock(&nap_ready->mu);

      NaClXMutexLock(&nap_ready_2->mu);
      nap_ready_2->module_load_status = errcode;
      NaClXCondVarBroadcast(&nap_ready_2->cv);
      NaClXMutexUnlock(&nap_ready_2->mu);
    }

    if (fuzzing_quit_after_load) {
      exit(0);
    }
  }

  /*
   * Execute additional I/O redirections.  NB: since the NaClApp
   * takes ownership of host / IMC socket descriptors, all but
   * the first run will not get access if the NaClApp closes
   * them.  Currently a normal NaClApp process exit does not
   * close descriptors, since the underlying host OS will do so
   * as part of service runtime exit.
   */
  NaClLog(4, "Processing I/O redirection/inheritance from command line\n");
  for (entry = redir_queue; NULL != entry; entry = entry->next) {
    switch (entry->tag) {
      case HOST_DESC:
        NaClAddHostDescriptor(nap, entry->u.host.d,
                              entry->u.host.mode, entry->nacl_desc);
        break;
      case IMC_DESC:
        NaClAddImcHandle(nap, entry->u.handle, entry->nacl_desc);
        break;
    }
  }

  /*
   * If export_addr_to is set to a non-negative integer, we create a
   * bound socket and socket address pair and bind the former to
   * descriptor NACL_SERVICE_PORT_DESCRIPTOR (3 [see sel_ldr.h]) and
   * the latter to descriptor NACL_SERVICE_ADDRESS_DESCRIPTOR (4).
   * The socket address is sent to the export_addr_to descriptor.
   *
   * The service runtime also accepts a connection on the bound socket
   * and spawns a secure command channel thread to service it.
   */
  if (0 <= export_addr_to) {
    NaClCreateServiceSocket(nap);
    /*
     * LOG_FATAL errors that occur before NaClSetUpBootstrapChannel will
     * not be reported via the crash log mechanism (for Chromium
     * embedding of NaCl, shown in the JavaScript console).
     *
     * Some errors, such as due to NaClRunSelQualificationTests, do not
     * trigger a LOG_FATAL but instead set module_load_status to be sent
     * in the start_module RPC reply.  Log messages associated with such
     * errors would be seen, since NaClSetUpBootstrapChannel will get
     * called.
     */
    NaClSetUpBootstrapChannel(nap, (NaClHandle) export_addr_to);
    /*
     * NB: spawns a thread that uses the command channel.  we do
     * this after NaClAppLoadFile so that NaClApp object is more
     * fully populated.  Hereafter any changes to nap should be done
     * while holding locks.
     */
    NaClSecureCommandChannel(nap);
  }

  /*
   * May have created a thread, so need to synchronize uses of nap
   * contents henceforth.
   */

  if (rpc_supplies_nexe) {
    errcode = NaClWaitForLoadModuleStatus(nap);
    NaClPerfCounterMark(&time_all_main, "WaitForLoad");
    NaClPerfCounterIntervalLast(&time_all_main);
  } else {
    /**************************************************************************
     * TODO(bsy): This else block should be made unconditional and
     * invoked after the LoadModule RPC completes, eliminating the
     * essentially dulicated code in latter part of NaClLoadModuleRpc.
     * This cannot be done until we have full saucer separation
     * technology, since Chrome currently uses sel_main_chrome.c and
     * relies on the functionality of the duplicated code.
     *************************************************************************/
    if (LOAD_OK == errcode) {
      if (verbosity) {
        gprintf((struct Gio *) &gout, "printing NaClApp details\n");
        NaClAppPrintDetails(nap, (struct Gio *) &gout);
      }

      /*
       * Finish setting up the NaCl App.  On x86-32, this means
       * allocating segment selectors.  On x86-64 and ARM, this is
       * (currently) a no-op.
       */
      errcode = NaClAppPrepareToLaunch(nap);
      // yiwen: my code
      errcode = NaClAppPrepareToLaunch(nap2);
      errcode = NaClAppPrepareToLaunch(nap3);
      // yiwen
      errcode = NaClAppPrepareToLaunch(nap0);
      errcode = NaClAppPrepareToLaunch(nap_ready);
      errcode = NaClAppPrepareToLaunch(nap0_2);
      errcode = NaClAppPrepareToLaunch(nap_ready_2);

      if (LOAD_OK != errcode) {
        nap->module_load_status = errcode;
        // yiwen: my code
        nap2->module_load_status = errcode;
        fprintf(stderr, "NaClAppPrepareToLaunch returned %d", errcode);
      }
      NaClPerfCounterMark(&time_all_main, "AppPrepLaunch");
      NaClPerfCounterIntervalLast(&time_all_main);
    }

    /* Give debuggers a well known point at which xlate_base is known.  */
    NaClGdbHook(&state);
  }

  /*
   * Tell the debug stub to bind a TCP port before enabling the outer
   * sandbox.  This is only needed on Mac OS X since that is the only
   * platform where we have an outer sandbox in standalone sel_ldr.
   * In principle this call should work on all platforms, but Windows
   * XP seems to have some problems when we do bind()/listen() on a
   * separate thread from accept().
   */
  if (enable_debug_stub && NACL_OSX) {
    if (!NaClDebugBindSocket()) {
      exit(1);
    }
  }

  /*
   * Enable the outer sandbox, if one is defined.  Do this as soon as
   * possible.
   *
   * This must come after NaClWaitForLoadModuleStatus(), which waits
   * for another thread to have called NaClAppLoadFile().
   * NaClAppLoadFile() does not work inside the Mac outer sandbox in
   * standalone sel_ldr when using a dynamic code area because it uses
   * NaClCreateMemoryObject() which opens a file in /tmp.
   *
   * We cannot enable the sandbox if file access is enabled.
   */
  if (!NaClAclBypassChecks && g_enable_outer_sandbox_func != NULL) {
    g_enable_outer_sandbox_func();
  }

  if (NULL != blob_library_file) {
    if (nap->irt_loaded) {
      NaClLog(LOG_INFO, "IRT loaded via command channel; ignoring -B irt\n");
    } else if (LOAD_OK == errcode) {
      NaClLog(2, "Loading blob file %s\n", blob_library_file);
      errcode = NaClAppLoadFileDynamically(nap, blob_file,
                                           NULL);
      if (LOAD_OK == errcode) {
        nap->irt_loaded = 1;
      } else {
        fprintf(stderr, "Error while loading \"%s\": %s\n",
                blob_library_file,
                NaClErrorString(errcode));
      }
      NaClPerfCounterMark(&time_all_main, "BlobLoaded");
      NaClPerfCounterIntervalLast(&time_all_main);
    }

    NaClDescUnref(blob_file);
    if (verbosity) {
      gprintf((struct Gio *) &gout, "printing post-IRT NaClApp details\n");
      NaClAppPrintDetails(nap, (struct Gio *) &gout);
    }
  }

  /*
   * Print out a marker for scripts to use to mark the start of app
   * output.
   */
  NaClLog(1, "NACL: Application output follows\n");

  /*
   * Make sure all the file buffers are flushed before entering
   * the application code.
   */
  fflush((FILE *) NULL);

  if (NULL != nap->secure_service) {
    NaClErrorCode start_result;
    /*
     * wait for start_module RPC call on secure channel thread.
     */
    start_result = NaClWaitForStartModuleCommand(nap);
    NaClPerfCounterMark(&time_all_main, "WaitedForStartModuleCommand");
    NaClPerfCounterIntervalLast(&time_all_main);
    if (LOAD_OK == errcode) {
      errcode = start_result;
    }
  }

  /*
   * error reporting done; can quit now if there was an error earlier.
   */
  if (LOAD_OK != errcode) {
    NaClLog(4,
            "Not running app code since errcode is %s (%d)\n",
            NaClErrorString(errcode),
            errcode);
    goto done;
  }

  if (!DynArraySet(&env_vars, env_vars.num_entries, NULL)) {
    NaClLog(LOG_FATAL, "Adding env_vars NULL terminator failed\n");
  }

  NaClEnvCleanserCtor(&env_cleanser, 0);
  if (!NaClEnvCleanserInit(&env_cleanser, envp,
          (char const *const *)env_vars.ptr_array)) {
    NaClLog(LOG_FATAL, "Failed to initialise env cleanser\n");
  }
  
  if (!NaClAppLaunchServiceThreads(nap)) {
    fprintf(stderr, "Launch service threads failed\n");
    goto done;
  } 
  // yiwen: my code 
  if (!NaClAppLaunchServiceThreads(nap2)) {
    fprintf(stderr, "Launch service threads failed\n");
    goto done;
  }
  if (!NaClAppLaunchServiceThreads(nap3)) {
    fprintf(stderr, "Launch service threads failed\n");
    goto done;
  }
  // yiwen
  if (!NaClAppLaunchServiceThreads(nap0)) {
    fprintf(stderr, "Launch service threads failed\n");
    goto done;
  } 
  if (!NaClAppLaunchServiceThreads(nap_ready)) {
    fprintf(stderr, "Launch service threads failed\n");
    goto done;
  } 
  if (!NaClAppLaunchServiceThreads(nap0_2)) {
    fprintf(stderr, "Launch service threads failed\n");
    goto done;
  } 
  if (!NaClAppLaunchServiceThreads(nap_ready_2)) {
    fprintf(stderr, "Launch service threads failed\n");
    goto done;
  } 
  if (enable_debug_stub) {
    if (!NaClDebugInit(nap)) {
      goto done;
    }
  }
  NACL_TEST_INJECTION(BeforeMainThreadLaunches, ());
  
  // yiwen: set up cage 0 (currently used by fork and execv) 
  // right now, nap0 is reserved for fork()
  InitializeCage(nap0, 1000);
  InitializeCage(nap_ready, 1000);
  InitializeCage(nap0_2, 1001);
  InitializeCage(nap_ready_2, 1001);

  // yiwen: set up cage 1
  // InitializeCage(nap, 1);

  // yiwen: debug
  // NaClLog(LOG_WARNING, "[NaCl Main][Cage 1] argv[3]: %s \n\n", (argv + optind)[3]);
  // NaClLog(LOG_WARNING, "[NaCl Main][Cage 1] argv[4]: %s \n\n", (argv + optind)[4]);
  // NaClLog(LOG_WARNING, "[NaCl Main][Cage 1] argv num: %d \n\n", argc - optind);

  /*
  nap->command_num = argc - optind - 3;

  nap->binary_path = (char*) malloc((strlen((argv + optind)[3]) + 1) * sizeof(char));
  strncpy(nap->binary_path, (argv + optind)[3], strlen((argv + optind)[3]) + 1);
  if (nap->command_num > 1) {
     nap->binary_command = (char*) malloc((strlen((argv + optind)[4]) + 1) * sizeof(char));
     strncpy(nap->binary_command, (argv + optind)[4], strlen((argv + optind)[4]) + 1);
  } 

  printf("nap->command_num = %d \n", nap->command_num);
  printf("nap->binary_path = %s \n", nap->binary_path);
  */

  // yiwen: this records the finishing time of the NaCl initialization / setup
  nacl_initialization_finish = clock();

  // yiwen: before the creation of the first cage
  // NaClLog(LOG_WARNING, "[NaCl Main Loader] NaCl Loader: before creation of the cage to run user program! \n\n");

  // yiwen: this is cage1, start a new thread with program given and run
  /*
  if (!NaClCreateMainThread(nap,
                            argc - optind,
                            argv + optind,
                            NaClEnvCleanserEnvironment(&env_cleanser))) {
    fprintf(stderr, "creating main thread failed\n");
    goto done;
  } */
  // NaClPrintAddressSpaceLayout(nap);

  // yiwen: here we tries to create a second thread to run nap2
  /* yiwen: arg setup for running grep.nexe
  argc2 = 6;
  argv2 = (char**) malloc(6 * sizeof(char*));
  argv2[0] = (char*) malloc(9 * sizeof(char)); 
  strncpy(argv2[0], "NaClMain", 9);
  argv2[1] = (char*) malloc(15 * sizeof(char)); 
  strncpy(argv2[1], "--library-path", 15);
  argv2[2] = (char*) malloc(7 * sizeof(char)); 
  strncpy(argv2[2], "/glibc", 7);
  argv2[3] = (char*) malloc(36 * sizeof(char)); 
  strncpy(argv2[3], "./test_case/pipe/cat_grep/grep.nexe", 36);
  argv2[4] = (char*) malloc(9 * sizeof(char)); 
  strncpy(argv2[4], "testfile", 9);
  argv2[5] = (char*) malloc(34 * sizeof(char)); 
  strncpy(argv2[5], "./test_case/files/testfile_01.txt", 34); 

  argc2 = 4;
  argv2 = (char**) malloc(4 * sizeof(char*));
  argv2[0] = (char*) malloc(9 * sizeof(char)); 
  strncpy(argv2[0], "NaClMain", 9);
  argv2[1] = (char*) malloc(15 * sizeof(char)); 
  strncpy(argv2[1], "--library-path", 15);
  argv2[2] = (char*) malloc(7 * sizeof(char)); 
  strncpy(argv2[2], "/glibc", 7);
  argv2[3] = (char*) malloc(43 * sizeof(char)); 
  strncpy(argv2[3], "./test_case/hello_world/hello_world_2.nexe", 43);
  
  argc2 = 6;
  argv2 = (char**) malloc(6 * sizeof(char*));
  argv2[0] = (char*) malloc(9 * sizeof(char)); 
  strncpy(argv2[0], "NaClMain", 9);
  argv2[1] = (char*) malloc(15 * sizeof(char)); 
  strncpy(argv2[1], "--library-path", 15);
  argv2[2] = (char*) malloc(7 * sizeof(char)); 
  strncpy(argv2[2], "/glibc", 7);
  argv2[3] = (char*) malloc(25 * sizeof(char)); 
  strncpy(argv2[3], "./test_case/cat/cat.nexe", 25);
  argv2[4] = (char*) malloc(34 * sizeof(char)); 
  strncpy(argv2[4], "./test_case/files/testfile_01.txt", 34);
  argv2[5] = (char*) malloc(34 * sizeof(char)); 
  strncpy(argv2[5], "./test_case/files/testfile_02.txt", 34); */
  
  // yiwen: set up cage 2
  /*
  argc2 = 4;
  argv2 = (char**) malloc(4 * sizeof(char*));
  argv2[0] = (char*) malloc(9 * sizeof(char)); 
  strncpy(argv2[0], "NaClMain", 9);
  argv2[1] = (char*) malloc(15 * sizeof(char)); 
  strncpy(argv2[1], "--library-path", 15);
  argv2[2] = (char*) malloc(7 * sizeof(char)); 
  strncpy(argv2[2], "/glibc", 7);
  argv2[3] = (char*) malloc(43 * sizeof(char)); 
  strncpy(argv2[3], "./test_case/hello_world/hello_world_2.nexe", 43);

  InitializeCage(nap2, 2); 
  */
  // yiwen: debug
  // NaClLog(LOG_WARNING, "[NaCl Main][Cage 2] executable path: %s \n\n", argv2[3]);
  /*
  if (!NaClCreateMainThread(nap2,
                            argc2,
                            argv2,
                            NaClEnvCleanserEnvironment(&env_cleanser))) {
    fprintf(stderr, "creating main thread failed\n");
    goto done;
  } */

  // yiwen: for gdb debug purpose only
  /*  
  while(1) {
  } */
  
  /*
  free(argv2[0]);
  free(argv2[1]);
  free(argv2[2]);
  free(argv2[3]);
  free(argv2); 
  */
  // yiwen: here we have an empty cage nap2
  //        let's try to use mmap to do memory mapping between nap2 and a memory cache region 
  /*
  InitializeCage(nap2, 2);
  data_size = 8;
  reg1_ptr = (void*) 0x5000000; // this is a NaCl sys_addr, outside of any cage
  reg2_ptr = (void *) NaClUserToSys(nap2, 0x11030000); // this is addr inside of cage 2

  printf(" \n");
  printf("*************************************************************************************** \n");
  printf("Testing shared memory mapping starts! \n\n");
  NaClLog(LOG_WARNING, "[Shm] reg1_ptr = %p \n", reg1_ptr); 
  NaClLog(LOG_WARNING, "[Shm] reg2_ptr = %p \n", reg2_ptr); */

  // yiwen: permission in the memory at this moment
  // 596c11030000-596c11040000 r--p 00020000 08:01 16452000                   /usr/lind_project/repy/repy/linddata.226 (226, '/glibc/tls/libgcc_s.so.1')
  // 596c11040000-596c11050000 rw-p 00020000 08:01 16452000                   /usr/lind_project/repy/repy/linddata.226
  // 78e410050000-78e4ff000000 ---p 00000000 00:00 0
  /*
  shmid = shmget(IPC_PRIVATE, data_size, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);

  reg1 = (char *) shmat (shmid,  reg1_ptr, 0);
  reg2 = (char *) shmat (shmid,  reg2_ptr, SHM_REMAP); // need to remap the memory because this region in the cage has already been mapped before but with content 0
  */
  // yiwen: permission of the shared memory in cage 2, changed after the shmat(, , SHM_REMAP) 
  // 1db011030000-1db011031000 rw-s 00000000 00:04 31260749                   /SYSV00000000 (deleted)
  /*
  printf("Successfully created regions at %p and %p of length %d \n", reg1, reg2, data_size);
  reg1[0] = 'X';
  printf("Initial data value: reg1[0] = '%c', reg2[0] = '%c' \n", reg1[0], reg2[0]);
  reg1[0] = 'Y';
  printf("Write new data 'Y' to reg1[0] \n");
  printf("New data value: reg1[0] = '%c', reg2[0] = '%c' \n", reg1[0], reg2[0]);

  reg3_ptr = (void *) NaClUserToSys(nap3, 0x11030000); // this is addr inside of cage 3
  NaClLog(LOG_WARNING, "[Shm] reg3_ptr = %p \n", reg3_ptr); 
  reg3 = (char *) shmat (shmid,  reg3_ptr, SHM_REMAP); // need to remap the memory because this region in the cage has already been mapped before but with content 0
  printf("Successfully created region at %p of length %d \n", reg3, data_size);
  printf("Current data value: reg1[0] = '%c', reg2[0] = '%c', reg3[0] = '%c' \n", reg1[0], reg2[0], reg3[0]);
  reg3[0] = 'Z';
  printf("Write new data 'Z' to reg3[0] \n");
  printf("Current data value: reg1[0] = '%c', reg2[0] = '%c', reg3[0] = '%c' \n", reg1[0], reg2[0], reg3[0]);
  printf("Change permission of reg3 to READ_ONLY! \n");
  mprotect(reg3, data_size, PROT_READ);  
  printf("The shared memory for reg3 should still work fine. \n");
  reg1[0] = 'Q';
  printf("Write new data 'Q' to reg1[0] \n");
  printf("Current data value: reg1[0] = '%c', reg2[0] = '%c', reg3[0] = '%c' \n", reg1[0], reg2[0], reg3[0]);
  printf("But trying to write to reg3 now should fail and cause a crash. \n");
  */
  // reg3[0] = 'P';
  /*
  printf(" \n");
  printf("Testing shared memory mapping ends! \n");
  printf("*************************************************************************************** \n\n");
  */
  // printf("errno = %s\n", strerror(errno));

  // yiwen: testing cow shared memory mapping here
  /*
  printf(" \n");
  printf("*************************************************************************************** \n");
  printf("Testing cow mapping starts! \n\n");

  cage1_ptr = (void *) NaClUserToSys(nap2, 0x11040000); // this is addr inside of cage 2
  NaClLog(LOG_WARNING, "[Shm] cage1_ptr = %p \n", cage1_ptr); 

  munmap(cage1_ptr, SHM_SIZE); // need to remap the memory because this region in the cage has already been mapped before but with content 0

  shm_fd = shm_open("/tmpmem", O_RDWR | O_CREAT, 0666);
  shm_buf1 = mmap((void*) 0x1000000, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
  shm_buf2 = mmap((void*) cage1_ptr, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE, shm_fd, 0);
  shm_buf1[0] = 41;
  shm_buf1[1] = 42;
  printf("buf1 = %p, buf2 = %p \n", shm_buf1, shm_buf2);
  printf("buf1[0]: %i, buf1[1]: %i, buf2[0]: %i, buf2[1]: %i \n",
      shm_buf1[0],
      shm_buf1[1],
      shm_buf2[0],
      shm_buf2[1]);

  shm_buf2[0] = 43;
  shm_buf2[1] = 44;
  printf("buf1 = %p, buf2 = %p \n", shm_buf1, shm_buf2);
  printf("buf1[0]: %i, buf1[1]: %i, buf2[0]: %i, buf2[1]: %i \n",
      shm_buf1[0],
      shm_buf1[1],
      shm_buf2[0],
      shm_buf2[1]);

  printf(" \n");
  printf("Testing cow mapping ends! \n");
  printf("*************************************************************************************** \n\n");
  */
  /* yiwen: we try to map memory of a shared lib, libgcc_s.so.1
  7a3911030000-7a3911040000 r--p 00020000 08:01 16452000                   /usr/lind_project/repy/repy/linddata.226
  7a3911040000-7a3911050000 rw-p 00020000 08:01 16452000                   /usr/lind_project/repy/repy/linddata.226
  */

  // yiwen: for gdb debug purpose only
  /*  
  while(1) {
  } */

  // yiwen: development testing, using nap2 and nap3 here. 
  /*
  argc2 = 4;
  argv2 = (char**) malloc(4 * sizeof(char*));
  argv2[0] = (char*) malloc(9 * sizeof(char)); 
  strncpy(argv2[0], "NaClMain", 9);
  argv2[1] = (char*) malloc(15 * sizeof(char)); 
  strncpy(argv2[1], "--library-path", 15);
  argv2[2] = (char*) malloc(7 * sizeof(char)); 
  strncpy(argv2[2], "/glibc", 7);
  argv2[3] = (char*) malloc(43 * sizeof(char)); 
  strncpy(argv2[3], "./test_case/hello_world/hello_world_1.nexe", 43);

  InitializeCage(nap2, 2); 

  if (!NaClCreateMainThread(nap2,
                            argc2,
                            argv2,
                            NaClEnvCleanserEnvironment(&env_cleanser))) {
    fprintf(stderr, "creating main thread failed\n");
    goto done;
  } 

  InitializeCage(nap3, 3); 

  if (!NaClCreateMainThread(nap3,
                            argc2,
                            argv2,
                            NaClEnvCleanserEnvironment(&env_cleanser))) {
    fprintf(stderr, "creating main thread failed\n");
    goto done;
  } 
  
  free(argv2[0]);
  free(argv2[1]);
  free(argv2[2]);
  free(argv2[3]);
  free(argv2); */

  InitializeCage(nap0, 0); 

  // ******************************************************************************************************************************
  // yiwen: run our loader as a background daemon, which takes in command-line parameters and starts the user program in our cages  
  // ******************************************************************************************************************************
  myfifo = (char*) malloc(12 * sizeof(char));
  strncpy(myfifo, "/tmp/myfifo", 12);
  
  // creating the named file(FIFO)
  // mkfifo(<pathname>, <permission>)
  mkfifo(myfifo, 0666);

  while (1)
  {
     // Open FIFO for Read only
     myfifo_fd = open(myfifo, O_RDONLY);
     // Read from FIFO
     read(myfifo_fd, user_input, sizeof(user_input));
 
     // Print the read message
     printf("User input: %s \n", user_input);
     printf("User input length: %d \n", (int)strlen(user_input));
     close(myfifo_fd);

     if (user_input[0] == '0') {
        break;
     }

     argc2 = 4;
     argv2 = (char**) malloc(4 * sizeof(char*));
     argv2[0] = (char*) malloc(9 * sizeof(char)); 
     strncpy(argv2[0], "NaClMain", 9);
     argv2[1] = (char*) malloc(15 * sizeof(char)); 
     strncpy(argv2[1], "--library-path", 15);
     argv2[2] = (char*) malloc(7 * sizeof(char)); 
     strncpy(argv2[2], "/glibc", 7);
     argv2[3] = (char*) malloc(strlen(user_input) * sizeof(char)); 

     is_new_argument = 1;
     k = 0;

     // yiwen: I am assuming that there is no space at the very beginning and very end of the user input,
     //        but multiple space characters are allowed between different arguments.
     for (j = 0; j < (int)(strlen(user_input)) - 1; j++) {
        if (user_input[j] == ' ') {
           if (is_new_argument == 1) {
              continue;
           }
           else {
              is_new_argument = 1; 
              argv2[argc2 - 1][k] = '\0';
              k = 0;
              argv2[argc2] = (char*) malloc(strlen(user_input) * sizeof(char));
              argc2++;
              continue;
           }
        }
        else {
           is_new_argument = 0;
           argv2[argc2 - 1][k] = user_input[j];
           k++;
        }
     } 

     argv2[argc2 - 1][k] = '\0';
     // debug
     printf("program args: %s \n", argv2[argc2 - 1]);

     InitializeCage(nap, 1); 
     nap->command_num = argc2 - 3;
     nap->binary_path = (char*) malloc((strlen(argv2[3]) + 1) * sizeof(char));
     strncpy(nap->binary_path, argv2[3], strlen(argv2[3]) + 1);
     if (nap->command_num > 1) {
        nap->binary_command = (char*) malloc((strlen(argv2[4]) + 1) * sizeof(char));
        strncpy(nap->binary_command, argv2[4], strlen(argv2[4]) + 1);
     } 
  
     nacl_user_program_begin = clock();    
     if (!NaClCreateMainThread(nap,
                               argc2,
                               argv2,
                               NaClEnvCleanserEnvironment(&env_cleanser))) {
        fprintf(stderr, "creating main thread failed\n");
        goto done;
     } 
 
     free(argv2[0]);
     free(argv2[1]);
     free(argv2[2]);
     free(argv2[3]);
     free(argv2);

     ret_code = NaClWaitForMainThreadToExit(nap);
     nacl_user_program_finish = clock();    
  }

  // ***********************************************************************
  // yiwen: testing
  // ***********************************************************************
  buffer_ptr = pipe_buffer;
  pipe_mutex = 0;
  pipe_transfer_over = 0;

  argc2 = 5;
  argv2 = (char**) malloc(5 * sizeof(char*));
  argv2[0] = (char*) malloc(9 * sizeof(char)); 
  strncpy(argv2[0], "NaClMain", 9);
  argv2[1] = (char*) malloc(15 * sizeof(char)); 
  strncpy(argv2[1], "--library-path", 15);
  argv2[2] = (char*) malloc(7 * sizeof(char)); 
  strncpy(argv2[2], "/glibc", 7);
  // argv2[3] = (char*) malloc(43 * sizeof(char)); 
  // strncpy(argv2[3], "./test_case/hello_world/hello_world_2.nexe", 43);
  argv2[3] = (char*) malloc(10 * sizeof(char)); 
  strncpy(argv2[3], "./bin/cat", 10);
  argv2[4] = (char*) malloc(29 * sizeof(char)); 
  strncpy(argv2[4], "./test_files/testfile_01.txt", 29);

  InitializeCage(nap2, 2);
  // fd_cage_table[2][1] = 8001;  
  if (!NaClCreateMainThread(nap2,
                            argc2,
                            argv2,
                            NaClEnvCleanserEnvironment(&env_cleanser))) {
     fprintf(stderr, "creating main thread failed\n");
     goto done;
  } 

  free(argv2[0]);
  free(argv2[1]);
  free(argv2[2]);
  free(argv2[3]);
  free(argv2[4]);
  free(argv2);

  argc2 = 5;
  argv2 = (char**) malloc(5 * sizeof(char*));
  argv2[0] = (char*) malloc(9 * sizeof(char)); 
  strncpy(argv2[0], "NaClMain", 9);
  argv2[1] = (char*) malloc(15 * sizeof(char)); 
  strncpy(argv2[1], "--library-path", 15);
  argv2[2] = (char*) malloc(7 * sizeof(char)); 
  strncpy(argv2[2], "/glibc", 7);
  // argv2[3] = (char*) malloc(43 * sizeof(char)); 
  // strncpy(argv2[3], "./test_case/hello_world/hello_world_2.nexe", 43);
  argv2[3] = (char*) malloc(11 * sizeof(char)); 
  strncpy(argv2[3], "./bin/grep", 11);
  argv2[4] = (char*) malloc(4 * sizeof(char)); 
  strncpy(argv2[4], "End", 4);

  InitializeCage(nap3, 3);
  // fd_cage_table[3][0] = 8000;  
  if (!NaClCreateMainThread(nap3,
                            argc2,
                            argv2,
                            NaClEnvCleanserEnvironment(&env_cleanser))) {
     fprintf(stderr, "creating main thread failed\n");
     goto done;
  } 
   
  free(argv2[0]);
  free(argv2[1]);
  free(argv2[2]);
  free(argv2[3]);
  free(argv2[4]);
  free(argv2);

  // ***********************************************************************
  // yiwen: cleanup and exit
  // ***********************************************************************
  NaClEnvCleanserDtor(&env_cleanser);

  NaClPerfCounterMark(&time_all_main, "CreateMainThread");
  NaClPerfCounterIntervalLast(&time_all_main);
  DynArrayDtor(&env_vars);

  // yiwen: waiting for running cages to exit
  ret_code = NaClWaitForMainThreadToExit(nap);
  ret_code = NaClWaitForMainThreadToExit(nap2);
  ret_code = NaClWaitForMainThreadToExit(nap3);
  ret_code = NaClWaitForMainThreadToExit(nap0);
  ret_code = NaClWaitForMainThreadToExit(nap_ready);
  if (fork_num == 2) {
      ret_code = NaClWaitForMainThreadToExit(nap0_2);
      ret_code = NaClWaitForMainThreadToExit(nap_ready_2);
  } 

  NaClPerfCounterMark(&time_all_main, "WaitForMainThread");
  NaClPerfCounterIntervalLast(&time_all_main);

  NaClPerfCounterMark(&time_all_main, "SelMainEnd");
  NaClPerfCounterIntervalTotal(&time_all_main);

  /*
   * exit_group or equiv kills any still running threads while module
   * addr space is still valid.  otherwise we'd have to kill threads
   * before we clean up the address space.
   */

  // yiwen: time measurement, record the finish time of the NaCl main program
  nacl_main_finish = clock();

  // yiwen: for evaluation measurement, we need to print out info here
  // NaClLog(LOG_WARNING, "[NaClMain] End of the program! \n\n");

  // calculate and print out time of running the NaCl main program 
  nacl_main_spent = (double)(nacl_main_finish - nacl_main_begin) / CLOCKS_PER_SEC;
  NaClLog(LOG_WARNING, "[NaClMain] NaCl main program time spent = %f \n", nacl_main_spent);

  nacl_initialization_spent = (double)(nacl_initialization_finish - nacl_main_begin) / CLOCKS_PER_SEC;
  NaClLog(LOG_WARNING, "[NaClMain] NaCl initialization time spent = %f \n", nacl_initialization_spent);

  nacl_user_program_spent = (double)(nacl_user_program_finish - nacl_user_program_begin) / CLOCKS_PER_SEC;
  NaClLog(LOG_WARNING, "[NaClMain] NaCl user program time spent = %f \n", nacl_user_program_spent);
  
  #ifdef SYSCALL_TIMING
  NaClLog(LOG_WARNING, "[NaClMain] NaCl system call timing enabled! \n");
  NaClLog(LOG_WARNING, "[NaClMain] Start printing out results now: \n");
  NaClLog(LOG_WARNING, "[NaClMain] NaCl global system call counter = %d \n", nacl_syscall_counter);
  NaClLog(LOG_WARNING, "[NaClMain] Print out system call timing table: \n");
  nacl_syscall_total_time = 0.0;
  for (i = 0; i < NACL_MAX_SYSCALLS; i++) {
    NaClLog(LOG_WARNING, "sys_num: %d, invoked times: %d, execution time: %f \n", i, nacl_syscall_invoked_times[i], nacl_syscall_execution_time[i]);
    nacl_syscall_total_time +=  nacl_syscall_execution_time[i];
  }
  NaClLog(LOG_WARNING, "[NaClMain] NaCl system call total time: %f \n\n", nacl_syscall_total_time);

  NaClLog(LOG_WARNING, "[NaClMain] Lind system call counter = %d \n", lind_syscall_counter);
  NaClLog(LOG_WARNING, "[NaClMain] Print out Lind system call timing table: \n");
  lind_syscall_total_time = 0.0;
  for (i = 0; i < LIND_MAX_SYSCALLS; i++) {
    NaClLog(LOG_WARNING, "sys_num: %d, invoked times: %d, execution time: %f \n", i, lind_syscall_invoked_times[i], lind_syscall_execution_time[i]);
    lind_syscall_total_time +=  lind_syscall_execution_time[i];
  }
  NaClLog(LOG_WARNING, "[NaClMain] Lind system call total time: %f \n", lind_syscall_total_time);
  
  NaClLog(LOG_WARNING, "[NaClMain] Results printing out: done! \n");
  #endif

  // yiwen: test output for cage->lib_table[CACHED_LIB_NUM_MAX]
  /*
  printf("[*** TESTING! ***] nap->num_lib = %d \n", nap->num_lib);
  for (j = 0; j < nap->num_lib; j++) {
     printf("[*** TESTING! ***] fd = %d, filepath = %s \n", j, nap->lib_table[j].path);
  } */

  NaClLog(LOG_WARNING, "[Performance results] LindPythonInit(): %f \n", time_counter);

  LindPythonFinalize();

  NaClExit(ret_code);

 done:
  fflush(stdout);

  if (verbosity) {
    gprintf((struct Gio *) &gout, "exiting -- printing NaClApp details\n");
    NaClAppPrintDetails(nap, (struct Gio *) &gout);

    printf("Dumping vmmap.\n"); fflush(stdout);
    PrintVmmap(nap);
    fflush(stdout);
  }
  /*
   * If there is a secure command channel, we sent an RPC reply with
   * the reason that the nexe was rejected.  If we exit now, that
   * reply may still be in-flight and the various channel closure (esp
   * reverse channel) may be detected first.  This would result in a
   * crash being reported, rather than the error in the RPC reply.
   * Instead, we wait for the hard-shutdown on the command channel.
   */
  if (LOAD_OK != errcode) {
    NaClBlockIfCommandChannelExists(nap);
  }

  if (verbosity > 0) {
    printf("Done.\n");
  }
  fflush(stdout);

#if NACL_LINUX
  NaClSignalHandlerFini();
#endif
  NaClAllModulesFini();

  if(!LindPythonFinalize()) {
      fflush(NULL);
      exit(1);
  }

  NaClExit(ret_code);

  /* Unreachable, but having the return prevents a compiler error. */
  return ret_code;
}
