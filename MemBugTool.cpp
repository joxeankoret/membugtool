
#include "MemBugTool.h"

//------------------------------------------------------------------------------
// Global variables
CHooksInstaller *g_hooks = NULL;
CMemoryChecker *g_checker = NULL;
bool g_mitigate = false;
bool g_writes = false;
bool g_double_frees = false;

//------------------------------------------------------------------------------
// Command line switches

KNOB<bool> knob_memory_tracker(KNOB_MODE_WRITEONCE,  "pintool",
  "track", "1", "track malloc/free.");

KNOB<bool> knob_mitigate(KNOB_MODE_WRITEONCE,  "pintool",
  "mitigate", "0", "mitigate known bug classes?");

KNOB<bool> knob_writes(KNOB_MODE_WRITEONCE,  "pintool",
  "writes", "0", "track writes");

KNOB<bool> knob_double_frees(KNOB_MODE_WRITEONCE,  "pintool",
  "double-free", "0", "track double frees");

KNOB<bool> knob_break_always(KNOB_MODE_WRITEONCE,  "pintool",
  "breakpoint", "0", "trigger a breakpoint for each invalid memory access?");

//------------------------------------------------------------------------------
static void fini_cbk(INT32 code, void *v)
{
  if ( g_hooks != NULL )
  {
    delete g_hooks;
    g_hooks = NULL;
  }
  
  if ( g_checker != NULL )
  {
    delete g_checker;
    g_checker = NULL;
  }
}

//------------------------------------------------------------------------------
static void PIN_FAST_ANALYSIS_CALL ins_instruction_cbk(const CONTEXT *ctx)
{
  if ( g_checker != NULL && g_checker->breakpoint_set() )
  {
    if ( PIN_GetDebugStatus() == DEBUG_STATUS_CONNECTED )
      PIN_ApplicationBreakpoint(ctx, PIN_ThreadId(), FALSE, g_checker->breakpoint_msg());
    g_checker->remove_breakpoint();
  }
}

//------------------------------------------------------------------------------
static VOID memory_access_callback(VOID *ip, VOID *addr)
{
  if ( g_checker != NULL )
    g_checker->check_write((ADDRINT)addr, 0);
}

//------------------------------------------------------------------------------
static void ins_cbk(INS ins, void *v)
{
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_instruction_cbk,
                 IARG_FAST_ANALYSIS_CALL, IARG_CONST_CONTEXT,
                 IARG_END);

  if ( !g_writes )
    return;

  // Iterate over each memory operand of the instruction.
  UINT32 mem_ops = INS_MemoryOperandCount(ins);
  for ( UINT32 mem_op = 0; mem_op < mem_ops; mem_op++)
  {
    if ( INS_MemoryOperandIsWritten(ins, mem_op) )
    {
      INS_InsertPredicatedCall(
          ins, IPOINT_BEFORE, (AFUNPTR)memory_access_callback,
          IARG_INST_PTR,
          IARG_MEMORYOP_EA, mem_op,
          IARG_END);
    }
  }

}

//------------------------------------------------------------------------------
static void dump_areas(void)
{
  return;
  printf("---------------------------------------------------------\n");
  mem_area_vec_t::const_iterator it;
  for ( it = g_checker->areas.begin(); it != g_checker->areas.end(); ++it )
  {
    const char *line = "Area 0x" EA_FMT " Size " SIZE_FMT " TID %d Available? %d Ignored? %d\n";
    printf(line, it->ea, it->size, it->tid, it->available, it->ignore);
  }
  printf("---------------------------------------------------------\n");
}

//------------------------------------------------------------------------------
void CMemoryChecker::add_breakpoint(string msg)
{
  bpt_msg = msg;
  _breakpoint = true;
}

//------------------------------------------------------------------------------
void CMemoryChecker::remove_breakpoint(void)
{
  _breakpoint = false;
  bpt_msg = "";
}

//------------------------------------------------------------------------------
bool CMemoryChecker::is_in_allocator(void)
{
  THREADID tid = PIN_ThreadId();
  thread_bool_map_t::const_iterator it = inside_alloc.find(tid);
  if ( it != inside_alloc.end() )
    return it->second;
  return false;
}

//------------------------------------------------------------------------------
void CMemoryChecker::check_before_free(ADDRINT a1,
  ADDRINT a2,
  FUNC_TYPE_T type,
  ADDRINT *ref_a1)
{
  PIN_LockClient();

  bool found = false;
  mem_area_vec_t::reverse_iterator it;
  //printf("[%d]    before free(): 0x" EA_FMT "\n", PIN_GetTid(), a1);
  for ( it = areas.rbegin(); it != areas.rend() && a1 != 0; ++it )
  {
    if ( it->ea == 0 )
      continue;

    if ( it->tid == PIN_GetTid() && a1 == it->ea )
    {
      found = true;
      if ( !it->available && !it->unknown )
      {
        if ( g_double_frees )
        {
          printf("WARNING! Freeing already available memory (0x" EA_FMT " - 0x" EA_FMT ", ptr 0x" EA_FMT ")!\n", it->ea, it->ea + it->size, a1);
          if ( break_always )
            add_breakpoint("Freeing already available memory!");

          if ( g_mitigate )
          {
            printf("NOTICE: Mitigation is enabled, returning a null pointer...\n");
            *ref_a1 = 0;
          }
        }

        it->ignore = true;
      }

      //printf("[%d]    before free(): Marking 0x" EA_FMT " as freed\n", PIN_GetTid(), it->ea);
      it->available = false;
      break;
    }
  }

  if ( !found && a1 != 0 )
  {
    // Trick to avoid false positives: try to read 4 bytes from that
    // memory page we don't have information about.
    char buf[4];
    size_t bytes = PIN_SafeCopy(buf, (ADDRINT*)a1, sizeof(buf));
    if ( bytes < 4 )
    {
      printf("WARNING! Freeing an invalid memory page at 0x" EA_FMT "!\n", a1);
      add_breakpoint("Freeing an invalid memory page");

      if ( g_mitigate )
      {
        printf("NOTICE: Mitigation is enabled, returning a null pointer #2...\n");
        *ref_a1 = 0;
      }
    }
    else
    {
      //printf("[%d]    before free(): UNKNOWN PAGE 0x" EA_FMT "\n", PIN_GetTid(), a1);
      mem_area_t area;
      area.ea = a1;
      area.size = sizeof(void*);
      area.available = false;
      area.unknown = true;
      area.ignore = false;
      area.ignore_write = false;
      area.tid = PIN_GetTid();
      areas.push_back(area);
    }
  }

  g_checker->inside_alloc[PIN_ThreadId()] = true;
  PIN_UnlockClient();
}

//------------------------------------------------------------------------------
void CMemoryChecker::check_alloc(size_t size)
{
  if ( (signed)size < 0 )
  {
    printf("WARNING! Negative size given to a malloc call!\n");
    add_breakpoint("Negative size given to a malloc call");
  }
  else if ( size == 0 )
  {
    printf("WARNING! Zero allocation detected!\n");
    add_breakpoint("WARNING! Zero allocation detected!\n");
  }
}

//------------------------------------------------------------------------------
void CMemoryChecker::check_before_malloc(size_t size, FUNC_TYPE_T type)
{
  PIN_LockClient();

  //printf("[%d]  before malloc(): size %zu\n", PIN_GetTid(), size);
  check_alloc(size);

  mem_area_t area;
  area.ea = (ADDRINT)-1;
  area.size = size;
  area.available = true;
  area.ignore = false;
  area.ignore_write = false;
  area.realloced = false;
  area.tid = PIN_GetTid();
  areas.push_back(area);

  g_checker->inside_alloc[PIN_ThreadId()] = true;
  PIN_UnlockClient();
}

//------------------------------------------------------------------------------
void CMemoryChecker::check_before_realloc(ADDRINT ptr, size_t size)
{
  if ( is_in_allocator() )
    return;

  PIN_LockClient();

  check_alloc(size);

  //printf("[%d] before realloc(): finding pointer 0x" EA_FMT "\n", PIN_GetTid(), ptr);
  mem_area_vec_t::iterator it;
  for ( it = areas.begin(); it != areas.end(); ++it )
  {
    ADDRINT ea = it->ea;
    if ( ea == ptr )
    {
      //printf("[%d] before realloc(): 0x" EA_FMT ", old size %zu, new size %zu\n", it->tid, it->ea, it->size, size);
      it->prev_ea = ea;
      it->realloced = true;
      it->prev_size = it->size;
      it->size = size;
      break;
    }
  }

  g_checker->inside_alloc[PIN_ThreadId()] = true;
  PIN_UnlockClient();
}

//------------------------------------------------------------------------------
__inline ADDRINT align_pointer(ADDRINT size)
{
  ADDRINT align = 2 * 16 * 16;
  return (size + align - 1) & ~(align - 1);
}

//------------------------------------------------------------------------------
void CMemoryChecker::check_after_realloc(ADDRINT ptr)
{
  PIN_LockClient();

  ADDRINT align_ea = 0;
  mem_area_vec_t::iterator it;
  for ( it = areas.begin(); it != areas.end(); ++it )
  {
    if ( it->tid == PIN_GetTid() )
    {
      if ( it->realloced )
      {
        if ( !it->available )
        {
          printf("WARNING! Reallocating a previously freed buffer!\n");
          if ( break_always )
            add_breakpoint("Reallocating a previously freed buffer!");
        }

        align_ea = align_pointer(it->ea + it->size);
        //printf("[%d]  after realloc(): 0x" EA_FMT " -> 0x" EA_FMT " : 0x" EA_FMT ", old size %zu, new size %zu\n", it->tid, it->prev_ea, it->ea, align_ea, it->prev_size, it->size);
        it->realloced = false;
        it->available = true;
        it->ea = ptr;
        break;
      }
    }
  }

  for ( it = areas.begin(); it != areas.end(); ++it )
  {
    if ( it->available )
      continue;

    if ( it->ea > ptr && it->ea <= align_ea )
    {
      //printf("[%d]  after realloc(): removing reused area 0x" EA_FMT " -> 0x" EA_FMT "\n", it->tid, it->ea, it->ea + it->size);
      areas.erase(it);
      it = areas.begin();
    }
  }

  g_checker->inside_alloc[PIN_ThreadId()] = false;
  PIN_UnlockClient();
}

//------------------------------------------------------------------------------
void CMemoryChecker::check_after_malloc(ADDRINT ret, FUNC_TYPE_T type)
{
  PIN_LockClient();

  //printf("[%d]   after malloc(): 0x" EA_FMT "\n", PIN_GetTid(), ret);

  mem_area_vec_t::iterator fwd_it;
  for ( fwd_it = areas.begin(); fwd_it != areas.end(); ++fwd_it )
  {
    if ( fwd_it->tid == PIN_GetTid() )
    {
      if ( fwd_it->ea == 0 )
      {
        areas.erase(fwd_it);
        fwd_it = areas.begin();
      }
    }
  }

  size_t size = 0;
  mem_area_vec_t::reverse_iterator it;
  for ( it = areas.rbegin(); it != areas.rend(); ++it )
  {
    if ( it->ea == (ADDRINT)-1 )
    {
      //printf("[%d]   after malloc(): size %zu -> 0x" EA_FMT "\n", PIN_GetTid(), it->size, ret);
      it->ea = ret;
      it->available = true;
      it->ignore_write = false;
      it->ignore = false;
      it->realloced = false;
      size = it->size;
      break;
    }
  }

  for ( fwd_it = areas.begin(); fwd_it != areas.end(); ++fwd_it )
  {
    if ( fwd_it->tid == PIN_GetTid() )
    {
      if ( fwd_it->ea == (ADDRINT)-1 || (fwd_it->ea >= ret && fwd_it->ea <= (ret + size) && !fwd_it->available ) )
      {
        //printf("[%d]   after malloc(): removing reused page at 0x" EA_FMT "\n", fwd_it->tid, fwd_it->ea);
        /*printf("AREAS BEFORE\n");
        dump_areas();
        printf("AREAS AFTER\n");*/
        areas.erase(fwd_it);
        dump_areas();
        fwd_it = areas.begin();
      }
    }
  }

  g_checker->inside_alloc[PIN_ThreadId()] = false;
  PIN_UnlockClient();
}

//------------------------------------------------------------------------------
void CMemoryChecker::check_after_free(void)
{
  PIN_LockClient();
  inside_alloc[PIN_ThreadId()] = false;
  PIN_UnlockClient();
}

//------------------------------------------------------------------------------
size_t CMemoryChecker::check_write(ADDRINT ea, size_t size)
{
  PIN_LockClient();

  bool in_alloc = is_in_allocator();

  size_t ret = size;
  bool found = false;
  mem_area_vec_t::iterator it;
  for ( it = areas.end()-1; it != areas.begin() && ea != 0; --it )
  {
    if ( ea == it->ea )
    {
      found = true;
      if ( !it->available && !it->ignore_write && !it->unknown )
      {
        if ( !in_alloc )
        {
          // Only report once per area
          it->ignore_write = true;
          add_breakpoint("Writing into a freed page");
          printf("WARNING: Writing into a freed page, write to 0x" EA_FMT ", area 0x" EA_FMT "-0x" EA_FMT " of size " SIZE_FMT " byte(s)!\n", ea, it->ea, it->ea + it->size, it->size);

          dump_areas();

        }
      }
      break;
    }
  }

  if ( !found && ea != 0 && size != 0 )
  {
    VOID *buf = malloc(size);
    if ( buf )
    {
      size_t bytes = PIN_SafeCopy(buf, (ADDRINT*)ea, size);
      if ( bytes < size )
      {
        add_breakpoint("Writing to a page with less bytes than expected");
        printf("WARNING! Writing to a page with less bytes than expected!\n");
        ret = bytes;
      }
      free(buf);
    }
  }

  PIN_UnlockClient();
  return ret;
}

//------------------------------------------------------------------------------
void CMemoryChecker::add_image(IMG img)
{
  PIN_LockClient();

  for ( SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec) )
  {
    mem_area_t area;
    area.ea = SEC_Address(sec);
    area.size = SEC_Size(sec);
    area.available = true;
    area.tid = PIN_GetTid();
    areas.push_back(area);
  }

  PIN_UnlockClient();
}

//------------------------------------------------------------------------------
static void PIN_FAST_ANALYSIS_CALL mem_before_cbk(
  ADDRINT a1,
  ADDRINT a2,
  FUNC_TYPE_T type,
  ADDRINT *ref_a1)
{
  if ( g_checker == NULL )
    return;

  if ( type == FTT_MALLOC )
    g_checker->check_before_malloc(a1, type);
  else if ( type == FTT_CALLOC )
    g_checker->check_before_malloc(a1 * a2, type);
  else if ( type == FTT_FREE )
    g_checker->check_before_free(a1, a2, type, ref_a1);
  else if ( type == FTT_REALLOC )
    g_checker->check_before_realloc((ADDRINT)a1, (size_t)a2);

}

//------------------------------------------------------------------------------
static void PIN_FAST_ANALYSIS_CALL mem_after_cbk(ADDRINT ret, FUNC_TYPE_T type)
{
  if ( g_checker == NULL )
    return;

  if ( type == FTT_MALLOC || type == FTT_CALLOC )
    g_checker->check_after_malloc(ret, type);
  else if ( type == FTT_REALLOC )
    g_checker->check_after_realloc(ret);
  else if ( type == FTT_FREE )
    g_checker->check_after_free();

  g_checker->inside_alloc[PIN_ThreadId()] = false;
}

//------------------------------------------------------------------------------
void CHooksInstaller::install_hooks(IMG img)
{
  str_vec_t malloc_funcs;
  malloc_funcs.push_back("malloc");
  malloc_funcs.push_back("_malloc");

  str_vec_t calloc_funcs;
  calloc_funcs.push_back("calloc");
  calloc_funcs.push_back("_calloc");

  str_vec_t free_funcs;
  free_funcs.push_back("free");
  free_funcs.push_back("_free");

  str_vec_t realloc_funcs;
  realloc_funcs.push_back("realloc");
  realloc_funcs.push_back("_realloc");

  hook_functions(img, malloc_funcs, FTT_MALLOC);
  hook_functions(img, calloc_funcs, FTT_CALLOC);
  hook_functions(img, free_funcs, FTT_FREE);
  hook_functions(img, realloc_funcs, FTT_REALLOC);
}

//------------------------------------------------------------------------------
void CHooksInstaller::hook_functions(
  IMG img,
  const str_vec_t &funcs,
  FUNC_TYPE_T type)
{
  str_vec_t::const_iterator it;
  str_vec_t::const_iterator end = funcs.end();
  for ( it = funcs.begin(); it != end; ++it )
  {
    if ( hook_one_function(img, (*it).c_str(), type) )
      break;
  }
}

//------------------------------------------------------------------------------
bool CHooksInstaller::hook_one_function(
  IMG img,
  const char *func,
  FUNC_TYPE_T type)
{
  bool ret = false;
  RTN target_rtn = RTN_FindByName(img, func);
  if (RTN_Valid(target_rtn))
  {
    RTN_Open(target_rtn);
    RTN_InsertCall(target_rtn, IPOINT_BEFORE, (AFUNPTR)mem_before_cbk,
                   IARG_FAST_ANALYSIS_CALL, 
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_ADDRINT, type,
                   IARG_FUNCARG_ENTRYPOINT_REFERENCE, 0,
                   IARG_END);
    RTN_InsertCall(target_rtn, IPOINT_AFTER, (AFUNPTR)mem_after_cbk,
                   IARG_FAST_ANALYSIS_CALL, 
                   IARG_FUNCRET_EXITPOINT_VALUE, 
                   IARG_ADDRINT, type,
                   IARG_END);

    RTN_Close(target_rtn);
    ret = true;
  }
  
  return ret;
}

//------------------------------------------------------------------------------
static VOID image_cbk(IMG img, VOID *v)
{
  if ( g_hooks != NULL )
    g_hooks->install_hooks(img);
  
  if ( g_checker != NULL )
    g_checker->add_image(img);
}

//------------------------------------------------------------------------------
static VOID image_unload_cbk(IMG img, VOID *v)
{
  //printf("Unloading image %s\n", IMG_Name(img).c_str());
}

//------------------------------------------------------------------------------
// Utilities
static int usage()
{
  const char *line = "This tool is a dynamic memory bug finding tool.\n\n%s\n";
  fprintf(stderr, line, KNOB_BASE::StringKnobSummary().c_str());
  return -1;
}

//------------------------------------------------------------------------------
int main(int argc, char *argv[])
{
  // Initialize symbols
  PIN_InitSymbols();

  // Initialize PIN library. Print help message if -h(elp) is specified
  // in the command line or the command line is invalid 
  if ( PIN_Init(argc,argv) )
    return usage();

  g_mitigate     = (knob_mitigate.Value() != 0);
  g_writes       = (knob_writes.Value() != 0);
  g_double_frees = (knob_double_frees.Value() != 0);
  if ( knob_memory_tracker.Value() != 0 )
  {
    g_hooks = new CHooksInstaller();
    g_checker = new CMemoryChecker();
    g_checker->break_always = (knob_break_always.Value() != 0);
  }

  // Register Image to be called to instrument functions.
  IMG_AddInstrumentFunction(image_cbk, 0);
  IMG_AddUnloadFunction(image_unload_cbk, 0);

  // Register function to be called to instrument instructions
  INS_AddInstrumentFunction(ins_cbk, 0);

  // Register function to be called when the application exits
  PIN_AddFiniFunction(fini_cbk, 0);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}
