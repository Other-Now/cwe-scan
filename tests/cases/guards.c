#include <stdlib.h>
static int staticTrue = 1;
static int staticFalse = 0;
static const int CONST_FIVE = 5;
static int returnsTrue(void) { return 1; }
int flip;  /* external and written below: not a constant */

int folded_bad(void) {
  int *p = NULL;
  if (staticTrue) return *p;  // expect: CWE-476
  return 0;
}

int folded_dead(void) {
  int *p = NULL;
  if (staticFalse) return *p;
  if (CONST_FIVE != 5) return *p;
  if (!returnsTrue()) return *p;
  return 0;
}

void leak_good(void) {
  char *d = malloc(10);
  if (d == NULL) exit(1);
  if (staticFalse) { d[0] = 0; } else { free(d); }
}

void set_flip(void) { flip = 1; }

int not_folded(void) {
  int *p = NULL;
  if (flip) return *p;  // expect: CWE-476
  return 0;
}
