#include <cstddef>
struct Two { int a, b; };
void printIntLine(int);

int via_ref() {
  int *data;
  int *&ref = data;
  ref = NULL;
  return *data;  // expect: CWE-476
}

int via_ptr_to_ptr() {
  int *data;
  int **p1 = &data;
  *p1 = NULL;
  int *copy = *p1;
  return *copy;  // expect: CWE-476
}

void delete_then_use() {
  Two *t = new Two;
  t->a = 1;
  delete t;
  printIntLine(t->a);  // expect: CWE-416
}

void array_delete_then_use() {
  int *a = new int[10];
  a[0] = 1;
  delete[] a;
  printIntLine(a[0]);  // expect: CWE-416
}

void new_leak() {
  Two *t = new Two;  // expect: CWE-401
  t->a = 1;
  printIntLine(t->a);
}

void new_ok() {
  Two *t = new Two;
  t->a = 1;
  delete t;
}

void address_escapes(void (*f)(int **)) {
  int *data = NULL;
  f(&data);
  printIntLine(*data);
}
