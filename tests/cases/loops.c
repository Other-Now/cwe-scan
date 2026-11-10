#include <stdlib.h>
void printLine(const char *s);

void freed_in_once_loop(void) {
  int i;
  char *d = malloc(10);
  if (!d) return;
  for (i = 0; i < 1; i++) {
    free(d);
  }
}

void maybe_zero_trips(int n) {
  int i;
  char *d = malloc(10);  // expect: CWE-401
  if (!d) return;
  for (i = 0; i < n; i++) {
    free(d);  // expect: CWE-415
  }
}

void writes_counter(void) {
  int i;
  char *d = malloc(10);  // expect: CWE-401
  if (!d) return;
  for (i = 0; i < 1; i++) {
    i = -1;
    free(d);  // expect: CWE-415
  }
}
