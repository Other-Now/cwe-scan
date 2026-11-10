#include <stdlib.h>
#include <string.h>
void printLine(const char *s);
void take(char *s);

void use_after_free(void) {
  char *d = malloc(10);
  if (d == NULL) exit(1);
  strcpy(d, "x");
  free(d);
  printLine(d);  // expect: CWE-416
}

void deref_after_free(void) {
  int *p = malloc(sizeof *p);
  if (!p) return;
  free(p);
  *p = 1;  // expect: CWE-416
}

void alias_after_free(void) {
  char *d = malloc(10);
  if (!d) return;
  char *copy = d;
  free(d);
  copy[0] = 'a';  // expect: CWE-416
}

void freed_then_reset(void) {
  char *d = malloc(10);
  if (!d) return;
  free(d);
  d = NULL;
  if (d) d[0] = 0;
}

char *return_freed(void) {
  char *d = malloc(10);
  if (!d) return NULL;
  free(d);
  return d;  // expect: CWE-416
}

void double_free(int c) {
  char *d = malloc(10);
  if (!d) return;
  if (c) free(d);
  free(d);  // expect: CWE-415
}

void free_in_branches(int c) {
  char *d = malloc(10);
  if (!d) return;
  if (c) { free(d); } else { free(d); }
}
