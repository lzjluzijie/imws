#include "mwspsi.hpp"

void benchDDH(size_t n) {
  PRNG prng(oc::sysRandomSeed());
  ipcl::KeyPair key = ipcl::generateKeypair(768);
  ipcl::PublicKey pk = key.pub_key;
  ipcl::PrivateKey sk = key.priv_key;
  vector<block> xx(n);
  prng.get<block>(xx);
  vector<uint32_t> xu(n);
  for (size_t i = 0; i < n; i++) {
    xu[i] = i;
  }
  vector<block> yy(n);
  prng.get<block>(yy);
  yy[0] = xx[n - 3];
  yy[1] = xx[n - 2];
  yy[2] = xx[n - 1];
  vector<uint32_t> yv(n);
  for (size_t i = 0; i < n; i++) {
    yv[i] = 1000 - 2 * i;
  }

  thread t0 = std::thread([&] {
    serverDDH(xx, xu, pk, sk);
  });
  thread t1 = std::thread([&] {
    clientDDH(yy, yv, pk);
  });

  t0.join();
  t1.join();
}

void benchOPRF(size_t n) {
  PRNG prng(oc::sysRandomSeed());
  ipcl::KeyPair key = ipcl::generateKeypair(768);
  ipcl::PublicKey pk = key.pub_key;
  ipcl::PrivateKey sk = key.priv_key;
  vector<block> xx(n);
  prng.get<block>(xx);
  vector<uint32_t> xu(n);
  for (size_t i = 0; i < n; i++) {
    xu[i] = i;
  }
  vector<block> yy(n);
  prng.get<block>(yy);
  yy[0] = xx[n - 3];
  yy[1] = xx[n - 2];
  yy[2] = xx[n - 1];
  vector<uint32_t> yv(n);
  for (size_t i = 0; i < n; i++) {
    yv[i] = 1000 - 2 * i;
  }

  thread t0 = std::thread([&] {
    serverOPRF(xx, xu, pk, sk);
  });
  thread t1 = std::thread([&] {
    clientOPRF(yy, yv, pk);
  });

  t0.join();
  t1.join();
}

