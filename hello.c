int printf(const char * restrict format, ...);

int main() {
  printf("%lu", sizeof(unsigned long long));
}
