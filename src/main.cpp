#include <iostream>
#include "utils.hpp"
#include "mwspsi.hpp"

int main(int argc, char **argv) {
  init();

//  size_t n = 100;
//  if (argc > 1) {
//    n = strtol(argv[1], nullptr, 10);
//  }
//  test(n);

  benchDDH(100);
  benchDDH(1000);
  benchDDH(10000);
  benchDDH(100000);
  benchOPRF(100);
  benchOPRF(1000);
  benchOPRF(10000);
  benchOPRF(100000);
}
