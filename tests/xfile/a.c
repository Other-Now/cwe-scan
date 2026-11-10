#include <stddef.h>
char *xf_source(void);
int xf_sink(char *d);
int xf_bad(void) {
  char *d = xf_source();
  return xf_sink(d);  // expect: CWE-476 whole-program
}
