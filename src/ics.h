/* Implicit Call Stack.  Written by Luca Saiu */

// This is wrong from every possible point of view, of course.  This is a quick hack, not meant for public use.
#define ICS_LARGE_STRING_SIZE 1000
#define ICS_LARGE 1000

typedef volatile unsigned long ics_local_type;

/* A conventional depth value used for the automatic variable _ics_local before
   the depth is actually set. */
#define ICS_UNINITIALIZED_DEPTH -1

#define ICS_LOCAL_DECLARATION \
  ics_local_type _ics_local /*__attribute__ ((unused))*/ = (ics_local_type) & _ics_local; \
  /* This nest level is stored as an automatic variable, out of the struct; \
     it may be useful to know whether the latest stack activation is still \
     current at a certain program point. */ \
  int _ics_nest_level __attribute__ ((unused)) = /* invalid at initialisation */ ICS_UNINITIALIZED_DEPTH; \
  /*asm ("# %=":"=X"(_ics_local):"X"(_ics_local));*/ \
  /*asm ("# %=":"+X"(_ics_local));*/

struct ics_stack_element
{
  ics_local_type *local_p;
  const char *file_name;
  int line_no;
  const char *function_name;
};

struct ics_state
{
  int stack_growth_direction;
  int bump_no;
  int nest_level;
  struct ics_stack_element stack [ICS_LARGE];

  ics_local_type the_big_lie;
};

void
ics_initialize(struct ics_state *s);

void
ics_finalize(struct ics_state *s);

void
ics_bump(struct ics_state *s,
         ics_local_type *local_p,
         const char *file_name,
         int line_no,
         const char *function_name);

#define ICS_ENTER(ics_state_p) \
  ICS_LOCAL_DECLARATION; \
  do \
    { \
      /*ICS_LOCAL_DECLARATION;*/ \
      struct ics_state *_ics_state_p = (ics_state_p); \
      ics_bump(_ics_state_p, & _ics_local, \
               __FILE__, (int) __LINE__, __func__); \
      /*char _header[ICS_LARGE_STRING_SIZE]; \
      sprintf(_header, "%s:%i %s", __FILE__, (int) __LINE__, __func__); \
      int _i; \
      for (_i = 0; _i < _ics_state_p->nest_level; _i ++) \
        printf("  "); \
      printf("%s", _header); \
      for (_i = 0; _i < _ics_state_p->nest_level; _i ++) \
        printf(" "); \
      printf("\n");*/ \
      /* Set the a automatic variable as well, which may be useful later \
         in this block, after some callees have been called, altering the \
         struct. */ \
      _ics_nest_level = _ics_state_p->nest_level; \
    } \
  while (false)
