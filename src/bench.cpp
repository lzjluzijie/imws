#include "mwspsi.hpp"

void benchDDH(u64 n, u64 intersection) {
  ipcl::KeyPair key = ipcl::generateKeypair(768);
  ipcl::PublicKey pk = key.pub_key;
  ipcl::PrivateKey sk = key.priv_key;

  vector<block> xx(n);
  vector<uint32_t> xu(n);
  vector<block> yy(n);
  vector<uint32_t> yv(n);
//  genData0(xx, xu, yy, yv, n);
//  genData1(xx, xu, yy, yv, n);
  genData2(xx, xu, yy, yv, n, n, intersection);

  thread t0 = std::thread([&] {
    serverDDH(xx, xu, pk, sk);
  });
  thread t1 = std::thread([&] {
    clientDDH(yy, yv, pk);
  });

  t0.join();
  t1.join();
}

void benchOPRF(u64 n, u64 intersection) {
  ipcl::KeyPair key = ipcl::generateKeypair(768);
  ipcl::PublicKey pk = key.pub_key;
  ipcl::PrivateKey sk = key.priv_key;

  vector<block> xx(n);
  vector<uint32_t> xu(n);
  vector<block> yy(n);
  vector<uint32_t> yv(n);
//  genData0(xx, xu, yy, yv, n);
//  genData1(xx, xu, yy, yv, n);
  genData2(xx, xu, yy, yv, n, n , intersection);

  thread t0 = std::thread([&] {
    serverOPRF(xx, xu, pk, sk);
  });
  thread t1 = std::thread([&] {
    clientOPRF(yy, yv, pk);
  });

  t0.join();
  t1.join();
}

void benchDlog(u64 n, u64 type) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<u64> dis(0, n);
  PRNG prng(oc::sysRandomSeed());

  u64 trials = 1000;

  auto start = std::chrono::high_resolution_clock::now();
  for (u64 i = 0; i < trials; ++i) {
    u64 x = dis(gen);
    char data[16];
    prng.get(data, 16);
    EC_POINT *g = toPoint(data, 16);
    EC_POINT *a = EC_POINT_new(group);
    if (EC_POINT_mul(group, a, nullptr, g, bn(x), ctx) != 1) {
      std::cerr << "Error: Unable to perform point multiplication\n";
      exit(1);
    }

    u64 xx = -2;
    if (type == 0) {
      xx = dlog0(group, g, a, n);
    } else if (type == 1) {
      xx = dlog1(group, g, a, n);
    } else {
      xx = dlog(group, g, a, n);
    }
    if (xx != x) {
      std::cerr << "Error: Dlog failed " << xx << " != " << x << std::endl;
      exit(1);
    }
  }
  auto end = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
  if (type == 0) {
    cout << "Dlog0: n=" << n << " " << duration << " ms" << endl;
  } else if (type == 1) {
    cout << "Dlog1: n=" << n << " " << duration << " ms" << endl;
  } else {
    cout << "Dlog: n=" << n << " " << duration << " ms" << endl;
  }
}
