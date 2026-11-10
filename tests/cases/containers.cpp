#include <cstdlib>
#include <vector>
void keep(std::vector<char *> &v);

void stored_in_vector() {
  std::vector<char *> v;
  char *d = (char *)malloc(10);
  v.insert(v.end(), 1, d);
  keep(v);
}
