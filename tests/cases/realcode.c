/* Patterns from real code (cJSON, Lua, zlib) that produced false positives. */
#include <stdlib.h>
#include <string.h>
struct buf { const char *content; size_t offset, length; };
#define can_access(b, i) ((b != NULL) && (((b)->offset + (i)) < (b)->length))
#define l_unlikely(x) __builtin_expect(((x) != 0), 0)
void printLine(const char *s);

int defensive_macro(struct buf *b) {
  int n = 0;
  if (b->length == 0) return 0;
  while (can_access(b, 0) && b->content[b->offset] == ' ') { b->offset++; n++; }
  return b->content[0] + n;
}

static struct buf *find(struct buf *all, int k) { return k ? all : NULL; }

int sometimes_null_callee(struct buf *all) {
  struct buf *b = find(all, 1);
  return (int)b->length;
}

int unlikely_check(struct buf *all, int k) {
  struct buf *b = NULL;
  if (k) b = all;
  if (l_unlikely(b != NULL)) return (int)b->length;
  return 0;
}

char *assign_in_condition(int fd) {
  char *path;
  if (fd < 0 || (path = malloc(16)) == NULL) return NULL;
  strcpy(path, "x");
  printLine(path);
  free(path);
  return NULL;
}

int still_reported(void) {
  struct buf *b = NULL;
  if (l_unlikely(b == NULL)) printLine("null");
  return (int)b->length;  // expect: CWE-476
}
