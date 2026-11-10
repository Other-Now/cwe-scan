#include <stdlib.h>
void printLine(const char *s);

static char *source_null(void) { return NULL; }
static char *source_alloc(void) {
  char *d = malloc(10);
  if (!d) exit(1);
  return d;
}
static int sink_deref(char *d) { return d[0]; }
static int sink_checked(char *d) { return d ? d[0] : 0; }
static void sink_free(char *d) { free(d); }
static void sink_keep(char *d) { printLine(d); }

int null_through_calls(void) {
  char *d = source_null();
  return sink_deref(d);  // expect: CWE-476
}

int null_checked_callee(void) {
  char *d = source_null();
  return sink_checked(d);
}

void freed_by_callee(void) {
  char *d = source_alloc();
  sink_free(d);
}

void leaked_through_callee(void) {
  char *d = source_alloc();  // expect: CWE-401
  sink_keep(d);
}

void uaf_after_callee_free(void) {
  char *d = source_alloc();
  sink_free(d);
  printLine(d);  // expect: CWE-416
}

int via_fnptr(void) {
  int (*f)(char *) = sink_deref;
  char *d = NULL;
  return f(d);  // expect: CWE-476
}
