#include <stdlib.h>
#include <string.h>

int straight(void) {
  int *p = NULL;
  return *p;  // expect: CWE-476
}

int checked(int *p) {
  if (p != NULL) return *p;
  return 0;
}

int param_unknown(int *p) { return *p; }

int one_branch(int c) {
  int x = 1;
  int *p = &x;
  if (c) p = NULL;
  return *p;  // expect: CWE-476
}

int deref_after_check(int *p) {
  if (p == NULL) {
    return *p;  // expect: CWE-476
  }
  return 0;
}

int check_after_deref(int *p) {
  int v = *p;
  if (p != NULL)  // expect: CWE-476
    v++;
  return v;
}

int bitwise_and(void) {
  struct S { int a; } *s = NULL;
  if ((s != NULL) & (s->a == 5))  // expect: CWE-476
    return 1;
  return 0;
}

int logical_and(void) {
  struct S { int a; } *s = NULL;
  if ((s != NULL) && (s->a == 5)) return 1;
  return 0;
}

void nonnull_arg(char *dst) {
  char *src = NULL;
  strcpy(dst, src);  // expect: CWE-476
}

int malloc_checked(void) {
  int *p = malloc(sizeof *p);
  if (p == NULL) exit(1);
  *p = 3;
  int v = *p;
  free(p);
  return v;
}

int reassigned(void) {
  int x = 0;
  int *p = NULL;
  p = &x;
  return *p;
}

int loop(int n) {
  int x = 0;
  int *p = NULL;
  for (int i = 0; i < n; i++) p = &x;
  return *p;  // expect: CWE-476
}
