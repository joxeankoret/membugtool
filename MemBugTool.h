#ifndef MEM_BUG_TOOL_H
#define MEM_BUG_TOOL_H

#include <iterator>
#include <iostream>
#include <vector>
#include <map>

#include <string.h>
#include <assert.h>

#include "pin.H"

#ifdef __x86_64__
#  define PIN_64
#define EA_FMT "%lx"
#define SIZE_FMT "%ld"
#else
#define EA_FMT "%x"
#define SIZE_FMT "%d"
#endif

//------------------------------------------------------------------------------
enum FUNC_TYPE_T
{
  FTT_MALLOC = 0,
  FTT_CALLOC,
  FTT_FREE,
  FTT_REALLOC
};

typedef std::vector<std::string> str_vec_t;

struct mem_area_t
{
  ADDRINT ea;
  ADDRINT from; // Where it was allocated?
  ADDRINT prev_ea; // Previous address (used with realloc)
  size_t size;
  size_t prev_size; // Previous size (used with realloc)
  THREADID tid;
  bool unknown:1; // The page is unknown, we haven't managed it!
  bool available:1; // True if malloc()ed, False is free()d
  bool ignore:1; // Ignore this page?
  bool ignore_write:1; // Ignore writes to this page?
  bool realloced:1;

  mem_area_t() : ea(0), from(0), prev_ea(0), size(0), prev_size(0), tid(0),
                 unknown(false), available(true), ignore(false),
                 ignore_write(false), realloced(false)
                 {};
};
typedef std::vector<mem_area_t> mem_area_vec_t;

typedef std::map<THREADID, bool> thread_bool_map_t;

//------------------------------------------------------------------------------
class CHooksInstaller
{
  private:
    void hook_functions(IMG img, const str_vec_t &funcs, FUNC_TYPE_T type);
    bool hook_one_function(IMG img, const char *func, FUNC_TYPE_T type);

  public:
    void install_hooks(IMG img);
};

//------------------------------------------------------------------------------
class CMemoryChecker
{
  private:
    bool ignore_writes;
    bool _breakpoint;
    std::string bpt_msg;

  public:
    bool break_always;

    mem_area_vec_t areas;
    thread_bool_map_t inside_alloc;
    CMemoryChecker() : ignore_writes(true), _breakpoint(false),
                       bpt_msg(""), break_always(false)
    {
      areas.clear();
    }

    bool breakpoint_set(void) { return _breakpoint; }
    const char *breakpoint_msg(void) { return bpt_msg.c_str(); }
    void remove_breakpoint(void);
    void add_breakpoint(std::string msg);
    void add_image(IMG img);
    bool is_in_allocator(void);
    void check_alloc(size_t size);
    void check_before_malloc(size_t size, FUNC_TYPE_T type);
    void check_before_free(ADDRINT a1,
      ADDRINT a2,
      FUNC_TYPE_T type,
      ADDRINT *ref_a1);
    void check_before_realloc(ADDRINT ptr, size_t size);
    void check_after_free(void);
    void check_after_malloc(ADDRINT ret, FUNC_TYPE_T type);
    void check_after_realloc(ADDRINT ret);
    size_t check_write(ADDRINT ea, size_t size);
};

#endif
