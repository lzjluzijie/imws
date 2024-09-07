#include <iostream>
#include "utils.hpp"
#include "mwspsi.hpp"

void dlog() {
  //  test(n);
  //  testDlog();
  benchDlog(100, 0);
  benchDlog(256, 0);
  benchDlog(1000, 0);
  benchDlog(10000, 0);
  benchDlog(100, 1);
  benchDlog(256, 1);
  benchDlog(1000, 1);
  benchDlog(10000, 1);
}

void ours() {
  benchDDH(100);
  benchDDH(1000);
  benchDDH(10000);
  benchDDH(100000);
  benchOPRF(100);
  benchOPRF(1000);
  benchOPRF(10000);
  benchOPRF(100000);
}

void together(u64 n) {
  benchDDH(n);
  benchOPRF(n);
  benchBXR(n, 1000);
  benchBXR(n, 10000);
  benchBXR(n, 100000);
  benchBXR(n, 1000000);
  printf("\n");
}

void b0814() {
  vector<u64> ns = {100, 1000, 10000, 100000};
  vector<double> ratios = {1, 3.162328, 10, 31.6228, 100};

  for (auto n : ns) {
    benchDDH(n);
    benchOPRF(n);
    for (auto ratio : ratios) {
      benchBXR(n, u64(double(n) * ratio));
    }
    printf("\n");
  }
}

void b0826() {
  u64 n = 10000;
  vector<u64> intersections = {0, 2500, 5000, 7500, 10000};
  for (auto intersection : intersections) {
    benchDDH(n, intersection);
    benchOPRF(n, intersection);
    benchBXR(n, n * 10, intersection);
    printf("\n");
  }
}

int main(int argc, char **argv) {
  init();

  size_t n = 100;
  if (argc > 1) {
    n = strtol(argv[1], nullptr, 10);
  }

  print = 0;

//  ours();
//  testBlind(100);

//  benchBXR(100, 1000);
//  benchBXR(1000, 1000);
//  benchBXR(10000, 1000);
//  benchBXR(100000, 1000);

//  benchBXR(100, 10000);
//  benchBXR(1000, 10000);
//  benchBXR(10000, 10000);
//  benchBXR(100000, 10000);

//  benchBXR(100, 1000000000);
//  benchBXR(1000, 1000000000);
//  benchBXR(10000, 1000000000);
//  benchBXR(100000, 1000000000);

//  together(100);
//  together(1000);
//  together(10000);
//  together(100000);

//  b0814();
  b0826();
}
