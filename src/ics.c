/* Implicit Call Stack.  Written by Luca Saiu */

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>

#include "ics.h"

#define ICS_IS_DEEPER_THAN(first_pointer, second_pointer, state_p) \
  (((first_pointer) - (second_pointer)) * (state_p)->stack_growth_direction > 0)

#define ICS_IS_NOT_SHALLOWER_THAN(first_pointer, second_pointer, state_p) \
  (((first_pointer) - (second_pointer)) * (state_p)->stack_growth_direction >= 0)

static int ics_sign (int n)
{
  if (n == 0)
    return 0;
  else if (n < 0)
    return -1;
  else
    return 1;
}

/* Return -1 if callee locals have addresses numerically smaller than caller
   locals; +1 if the callee locals have addresses numerically larger than caller
   locals. */
__attribute__((noclone, noinline, no_icf, no_split_stack, no_stack_limit))
static int
ics_stack_growth_direction (ics_local_type *caller_pointer,
                            unsigned nest_level)
{
  ICS_LOCAL_DECLARATION;
  /* printf("local: %li\n", (long) & _ics_local); */
  if (nest_level == 0) {
    ptrdiff_t last_callee_minus_caller = & _ics_local - caller_pointer;
    assert(last_callee_minus_caller != 0);
    return ics_sign(last_callee_minus_caller);
  }
  else if (nest_level % 3 == 0)
    return ics_stack_growth_direction (& _ics_local, nest_level - 1);
  else
    return ics_stack_growth_direction (caller_pointer, nest_level - 1);
}

void
ics_initialize(struct ics_state *s)
{
  s->stack_growth_direction = ics_stack_growth_direction(NULL, 10);
  s->bump_no = 0;
  s->nest_level = 0;
  //printf("On this machine the stack growth direction is %i\n", s->stack_growth_direction);
}

void
ics_finalize(struct ics_state *s)
{
    /* Do nothing. */
}

void
ics_bump(struct ics_state *s,
         ics_local_type *local_p,
         const char *file_name,
         int line_no,
         const char *function_name)
{
  static bool initialized = false;
  static ics_local_type *first __attribute__ ((unused));
  if (! initialized) {
    first = local_p;
    initialized = true;
  }

  /* Estimate the new nesting level, by comparing the current pointer with the
     next. */
  if (s->bump_no == 0)
    {
      s->nest_level = 0;
      //printf("(%s seems to be the outermost call)\n", function_name);
    }
  else
    {
      assert(s->nest_level >= 0);
      //printf("%p %p %i\n", first, local_p, (int) ((char*) local_p - (char*) first));
      //printf("%i %s\n", (int) ((char*) local_p - (char*) first), function_name);

      ics_local_type *previous_local_p = s->stack [s->nest_level].local_p;

      /* There are three possible cases. */
      int delta_depth;
      if (local_p == previous_local_p){
        /* First case, very easy: this call is at exactly the same level as the
           last one. */
        delta_depth = 0;
        //printf("A ");
      }
      else if (ICS_IS_DEEPER_THAN(local_p, previous_local_p, s)){
        /* Second case, almost as easy: if this call is deeper than the previous
           one, by any amount, then the new call belongs just above the previous
           one on the stack. */
        delta_depth = 1;
        //printf("B ");
      }
      else
        {
          //printf("C ");
          /* Third and most involved case: this call is shallower than the
             previous one, but we do not know by how much. */
          delta_depth = 0;
          while (s->nest_level + delta_depth >= 0
                 && ICS_IS_NOT_SHALLOWER_THAN(
                      s->stack [s->nest_level + delta_depth].local_p,
                      local_p,
                      s))
            delta_depth --;
          /* We went one step below what we were looking for. */
          delta_depth ++;
        }
      //printf("[delta %1i %s] ", delta_depth, ICS_IS_DEEPER_THAN(local_p, previous_local_p, s) ? "    DEEPER" : "NOT deeper");
      if (delta_depth == 0)
        {
          /*
          printf("(%s could be a tail-call from %s", function_name, s->stack [s->nest_level].function_name);
          if (s->nest_level > 0)
            printf(" or a call from %s",s->stack [s->nest_level - 1].function_name);
          printf(")\n");
          */
        }
      else if (s->nest_level + delta_depth > 0)
        /*printf("(the caller of %s is probably %s)\n", function_name, s->stack [s->nest_level + delta_depth - 1].function_name)*/;
      else
        /*printf("(%s seems to have replaced the outermost call (!))\n", function_name)*/;
      s->nest_level += delta_depth;
    }

  assert(s->nest_level >= 0);

  /* Save information about the current call, overwriting any previous
     information at the same nesting level. */
  s->stack [s->nest_level].local_p = local_p;
  s->stack [s->nest_level].file_name = file_name;
  s->stack [s->nest_level].line_no = line_no;
  s->stack [s->nest_level].function_name = function_name;

  /* This is one more call. */
  s->bump_no ++;

  s->the_big_lie += * local_p;
}
/*

void
ics_unbump(struct ics_state *s,
           ics_local_type *local_p,
           const char *file_name,
           int line_no,
           const char *function_name)
{
  // unimplemented, but not difficult.  This requires a loop.
  assert(false);
}

#define ICS_EXIT(ics_state_p) \
  do \
    { \
      struct ics_state *_ics_state_p = (ics_state_p); \
      ics_unbump(_ics_state_p, & _ics_local, __FILE__, (int) __LINE__, __func__); \
    } \
  while (false)

#define ENTER ICS_ENTER(& ics_state)
#define EXIT  ICS_EXIT(& ics_state)

//#define return return ({EXIT;}), 

unsigned
s (unsigned x)
{
  ENTER;
  return x + 1;
}

unsigned
p (unsigned x, unsigned y)
{
  ENTER;
  int i;
  for (i = y; i > 0; i --)
    x = s(x);
  return x;
}

unsigned
m (unsigned x, unsigned y)
{
  ENTER;
  if (x == 0)
    return 0;
  else
    return p (x, m (x - 1, y));
}

unsigned
t (unsigned x, unsigned y)
{
  ENTER;
  return x * y;
}

unsigned
foo (unsigned x)
{
  ENTER;
  return 42;
}

unsigned
bar (unsigned x)
{
  ENTER;
  return 10;
}

unsigned
quux (unsigned x)
{
  ENTER;
  return 3;
}

unsigned
rs (unsigned a, unsigned b)
{
  ENTER;
  if (a == 0)
    return b;
  else
    return rs (a - 1, b + 1);
}

void
qq (void)
{
  ENTER;
  fprintf(stderr, "%u\n", p (10, 3));  fflush(stderr);
  fprintf(stderr, "%u\n", m (2, 2));  fflush(stderr);
  fprintf(stderr, "%u\n", foo(0));  fflush(stderr);
  fprintf(stderr, "%u\n", bar(0));  fflush(stderr);
  fprintf(stderr, "%u\n", quux(0));  fflush(stderr);
  fprintf(stderr, "%u\n", rs(10, 0));  fflush(stderr);
}

static struct ics_state ics_state;
int
main (void)
{
  ics_initialize (& ics_state);
  ENTER;
  qq();
  ics_finalize (& ics_state);
  return 0;
}
*/