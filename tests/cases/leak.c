#include <stdlib.h>
#include <string.h>
void printLine(const char *s);
void take(char *s);
char *g;

void leak(void) {
  char *d = malloc(10);  // expect: CWE-401
  if (d == NULL) exit(1);
  strcpy(d, "x");
  printLine(d);
}

void no_leak(void) {
  char *d = malloc(10);
  if (d == NULL) exit(1);
  printLine(d);
  free(d);
}

void escapes_to_unknown(void) {
  char *d = malloc(10);
  take(d);
}

void escapes_to_global(void) {
  char *d = malloc(10);
  g = d;
}

char *returned(void) {
  char *d = malloc(10);
  return d;
}

void branch_leak(int c) {
  char *d = malloc(10);  // expect: CWE-401
  if (!d) return;
  if (c) free(d);
}

void overwrite(void) {
  char *d = malloc(10);  // expect: CWE-401
  d = malloc(20);
  free(d);
}

void realloc_idiom(void) {
  char *d = malloc(10);
  if (!d) return;
  d = realloc(d, 100);  // expect: CWE-401
  if (d) free(d);
}

void realloc_tmp(void) {
  char *d = malloc(10);
  if (!d) return;
  char *t = realloc(d, 100);
  if (t != NULL) d = t;
  free(d);
}

void strdup_leak(const char *s) {
  char *d = strdup(s);  // expect: CWE-401
  if (d) printLine(d);
}

void calloc_null_path(void) {
  int *p = calloc(4, sizeof *p);
  if (p == NULL) return;
  free(p);
}
