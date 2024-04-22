#include "mwspsi.hpp"

void testEC() {
  std::string input = "Hello, world";
  EC_POINT *g = toPoint(input.data(), input.size());

  BIGNUM *na = bn(123456);
  BIGNUM *nb = bn(654321);

  EC_POINT *ag = EC_POINT_new(group);
  EC_POINT *bg = EC_POINT_new(group);
  EC_POINT *bag = EC_POINT_new(group);
  EC_POINT *abg = EC_POINT_new(group);
  if (!EC_POINT_mul(group, ag, nullptr, g, na, ctx)) {
    std::cerr << "Error: Unable to perform point multiplication\n";
  }
  if (!EC_POINT_mul(group, bg, nullptr, g, nb, ctx)) {
    std::cerr << "Error: Unable to perform point multiplication\n";
  }
  if (!EC_POINT_mul(group, bag, nullptr, ag, nb, ctx)) {
    std::cerr << "Error: Unable to perform point multiplication\n";
  }
  if (!EC_POINT_mul(group, abg, nullptr, bg, na, ctx)) {
    std::cerr << "Error: Unable to perform point multiplication\n";
  }

  std::cout << "g: " << EC_POINT_point2hex(group, g, POINT_CONVERSION_UNCOMPRESSED, ctx) << std::endl;
  std::cout << "ag: " << EC_POINT_point2hex(group, ag, POINT_CONVERSION_UNCOMPRESSED, ctx) << std::endl;
  std::cout << "bg: " << EC_POINT_point2hex(group, bg, POINT_CONVERSION_UNCOMPRESSED, ctx) << std::endl;
  std::cout << "bag: " << EC_POINT_point2hex(group, bag, POINT_CONVERSION_UNCOMPRESSED, ctx) << std::endl;
  std::cout << "abg: " << EC_POINT_point2hex(group, abg, POINT_CONVERSION_UNCOMPRESSED, ctx) << std::endl;
}

void testDDH0() {
  PRNG prng(oc::sysRandomSeed());

  size_t n = 100;
  ipcl::KeyPair key = ipcl::generateKeypair(768, true);
  ipcl::PublicKey pk = key.pub_key;
  ipcl::PrivateKey sk = key.priv_key;

  // Alice
  std::vector<block> xx(n);
//  for (size_t i = 0; i < n; i++) {
//    xx[i] = block(i);
//  }
  prng.get<block>(xx);
  std::vector<uint32_t> xu(n);
  for (size_t i = 0; i < n; i++) {
    xu[i] = i;
  }
  std::vector<EC_POINT *> xxg(n);
  std::vector<EC_POINT *> xxct(n);

  for (size_t i = 0; i < n; i++) {
    xxg[i] = toPoint(xx[i].data(), sizeof(block));
  }
  ipcl::PlainText xupl(xu);

  BIGNUM *alice = BN_new();
  BIGNUM *ainv = BN_new();
  BN_rand_range(alice, q);
  BN_mod_inverse(ainv, alice, q, ctx);
  std::cout << "Alice: " << BN_bn2hex(alice) << std::endl;
  std::cout << "Random " << BN_bn2hex(q) << std::endl;

  for (size_t i = 0; i < n; i++) {
    xxct[i] = EC_POINT_new(group);
    if (EC_POINT_mul(group, xxct[i], nullptr, xxg[i], alice, ctx) != 1) {
      std::cerr << "Error: Unable to perform point multiplication\n";
      exit(1);
    }
  }
  ipcl::CipherText xuct = pk.encrypt(xupl);


  // Bob
  std::vector<block> yy(n);
//  for (size_t i = 0; i < n; i++) {
//    yy[i] = block(n - 3 + i);
//  }
  prng.get<block>(yy);
  yy[0] = xx[n - 3];
  yy[1] = xx[n - 2];
  yy[2] = xx[n - 1];
  std::vector<uint32_t> yv(n);
  for (size_t i = 0; i < n; i++) {
    yv[i] = 1000 - 2 * i;
  }
  std::vector<uint32_t> yr(n);
  for (size_t i = 0; i < n; i++) {
    yr[i] = i * i + 3 * i - 227229;
  }

  std::vector<EC_POINT *> yyg(n);
  ipcl::PlainText yvpl(yr);
  ipcl::CipherText yvct = pk.encrypt(yvpl);

  std::vector<BIGNUM *> bobs(n);
  for (size_t i = 0; i < n; i++) {
    bobs[i] = BN_new();
    BN_rand_range(bobs[i], q);
  }
  std::vector<EC_POINT *> xxctb(n);
  for (size_t i = 0; i < n; i++) {
    xxctb[i] = EC_POINT_new(group);
    if (EC_POINT_mul(group, xxctb[i], nullptr, xxct[i], bobs[i], ctx) != 1) {
      std::cerr << "Error: Unable to perform point multiplication\n";
      exit(1);
    }
  }

  for (size_t i = 0; i < n; i++) {
    yyg[i] = toPoint(yy[i].data(), sizeof(block));
  }

  ipcl::CipherText wwct = xuct + yvct;

  // Alice
  std::vector<EC_POINT *> zz(n);
  for (size_t i = 0; i < n; i++) {
    zz[i] = EC_POINT_new(group);
    if (EC_POINT_mul(group, zz[i], nullptr, xxctb[i], ainv, ctx) != 1) {
      std::cerr << "Error: Unable to perform point multiplication\n";
      exit(1);
    }
  }
  ipcl::PlainText wwpl = sk.decrypt(wwct);
  HASH zzhash;
  std::vector<uint64_t> zzh(n);
  for (size_t i = 0; i < n; i++) {
    unsigned char *pointData;
    size_t length = EC_POINT_point2buf(group, zz[i], POINT_CONVERSION_COMPRESSED, &pointData, ctx);
    if (length == 0) {
      std::cerr << "Error: Unable to perform point conversion\n";
      exit(1);
    } else if (length != 33) {
      std::cerr << "Error: Invalid point size\n";
      exit(1);
    }
    SHA256(pointData, length, zzhash); // check
    zzh[i] = (*(uint64_t *) zzhash);
  }

  // Bob
  std::vector<std::vector<uint64_t>> ajs(n, std::vector<uint64_t>(n));
  EC_POINT *yyct = EC_POINT_new(group);
//  unsigned char data[pointSize];
  HASH yycth;
  for (size_t j = 0; j < n; j++) {
    for (size_t i = 0; i < n; i++) {
      EC_POINT_mul(group, yyct, nullptr, yyg[j], bobs[i], ctx);
      unsigned char *pointData;
      size_t length = EC_POINT_point2buf(group, yyct, POINT_CONVERSION_COMPRESSED, &pointData, ctx);
      if (length == 0) {
        std::cerr << "Error: Unable to perform point conversion\n";
        exit(1);
      } else if (length != 33) {
        std::cerr << "Error: Invalid point size\n";
        exit(1);
      }
      SHA256(pointData, length, yycth); // check
      uint32_t value = yv[j] - yr[i];
      ajs[j][i] = (*(uint64_t *) yycth) ^ (uint64_t) value;
    }
  }

  // Alice
  for (size_t j = 0; j < n; j++) {
    for (size_t i = 0; i < n; i++) {
      uint64_t dec = zzh[i] ^ ajs[j][i];
      if ((dec >> 32) == 0) {
        uint32_t value = dec;
        value += wwpl.getElementVec(i)[0];
        std::printf("DDH ok %zu %zu %d\n", i, j, value);
      }
    }
  }
}

void testCuckoo() {
  uint64_t n = 1000;

  CuckooIndex<> cuckoo;
  auto param = CuckooIndex<>::selectParams(n, 40, 0, 3);
  std::cout << param.mN << std::endl;
  std::cout << param.mBinScaler << std::endl;

//  cuckoo.mParams.mNumHashes = 3;
//  cuckoo.mParams.mBinScaler = 1;
//  cuckoo.mParams.mN = n;
//  cuckoo.mParams.mStashSize = 400;
//  cuckoo.init(cuckoo.mParams);
  cuckoo.init(n, 40, 0, 3);

  PRNG prng(oc::sysRandomSeed());
  std::vector<block> items(n);
  prng.get<block>(items);

  cuckoo.insert(items);
  cuckoo.print();
}

void testDDH1() {
  PRNG prng(oc::sysRandomSeed());

  size_t n = 10000;
  auto param = CuckooIndex<>::selectParams(n, 40, 0, 3);
  size_t N = n * param.mBinScaler;

  ipcl::KeyPair key = ipcl::generateKeypair(768);
  ipcl::PublicKey pk = key.pub_key;
  ipcl::PrivateKey sk = key.priv_key;

  // Alice
  std::vector<block> xx(n);
//  for (size_t i = 0; i < n; i++) {
//    xx[i] = block(i);
//  }
  prng.get<block>(xx);
  std::vector<uint32_t> xu(n);
  for (size_t i = 0; i < n; i++) {
    xu[i] = i;
  }
  CuckooIndex<> cuckooA;
  cuckooA.init(param);
  cuckooA.insert(oc::span<block>(xx.data(), n));
//  cuckooA.print();

  std::vector<EC_POINT *> xxg(N);
  std::vector<EC_POINT *> xxct(N);
  std::vector<uint32_t> xuraw(N);
  for (size_t i = 0; i < N; i++) {
    if (cuckooA.mBins[i].isEmpty()) {
      block randBlock = prng.get<block>();
      xxg[i] = toPoint(randBlock.data(), sizeof(block));
      xuraw[i] = prng.get<uint32_t>();
    } else {
      uint64_t id = cuckooA.mBins[i].idx();
      xxg[i] = toPoint(xx[id].data(), sizeof(block));
      xuraw[i] = xu[id];
    }
  }
  ipcl::PlainText xupl(xuraw);

  BIGNUM *alice = BN_new();
  BIGNUM *ainv = BN_new();
  BN_rand_range(alice, q);
  BN_mod_inverse(ainv, alice, q, ctx);
  std::cout << "Alice: " << BN_bn2hex(alice) << std::endl;
  std::cout << "Random " << BN_bn2hex(q) << std::endl;

  for (size_t i = 0; i < N; i++) {
    xxct[i] = EC_POINT_new(group);
    if (EC_POINT_mul(group, xxct[i], nullptr, xxg[i], alice, ctx) != 1) {
      std::cerr << "Error: Unable to perform point multiplication\n";
      exit(1);
    }
  }
  ipcl::CipherText xuct = pk.encrypt(xupl);


  // Bob
  std::vector<block> yy(n);
//  for (size_t i = 0; i < n; i++) {
//    yy[i] = block(n - 3 + i);
//  }
  prng.get<block>(yy);
  yy[0] = xx[n - 3];
  yy[1] = xx[n - 2];
  yy[2] = xx[n - 1];
  std::vector<uint32_t> yv(N);
  for (size_t i = 0; i < n; i++) {
    yv[i] = 1000 - 2 * i;
  }
  std::vector<uint32_t> yr(N);
  for (size_t i = 0; i < n; i++) {
    yr[i] = i * i + 3 * i - 227229;
  }
  CuckooIndex<> cuckooB;
  cuckooB.init(param);
//  cuckooB.insert(yy);
//  cuckooB.print();
  Matrix<uint32_t> locations(n, 3);
  cuckooB.computeLocations(yy, locations);
//  for (size_t i = 0; i < n; i++) {
//    std::cout << "Location of " << n - 3 + i << ": " << locations[i][0] << " " << locations[i][1] << " "
//              << locations[i][2] << std::endl;
//  }

  std::vector<EC_POINT *> yyg(n);
  ipcl::PlainText yvpl(yr);
  ipcl::CipherText yvct = pk.encrypt(yvpl);

  std::vector<BIGNUM *> bobs(N);
  for (size_t i = 0; i < N; i++) {
    bobs[i] = BN_new();
    BN_rand_range(bobs[i], q);
  }
  std::vector<EC_POINT *> xxctb(N);
  for (size_t i = 0; i < N; i++) {
    xxctb[i] = EC_POINT_new(group);
    if (EC_POINT_mul(group, xxctb[i], nullptr, xxct[i], bobs[i], ctx) != 1) {
      std::cerr << "Error: Unable to perform point multiplication\n";
      exit(1);
    }
  }

  for (size_t i = 0; i < n; i++) {
    yyg[i] = toPoint(yy[i].data(), sizeof(block));
  }

  ipcl::CipherText wwct = xuct + yvct;

  // Alice
  std::vector<EC_POINT *> zz(N);
  for (size_t i = 0; i < N; i++) {
    zz[i] = EC_POINT_new(group);
    if (EC_POINT_mul(group, zz[i], nullptr, xxctb[i], ainv, ctx) != 1) {
      std::cerr << "Error: Unable to perform point multiplication\n";
      exit(1);
    }
  }
  ipcl::PlainText wwpl = sk.decrypt(wwct);
  HASH zzhash;
  std::vector<uint64_t> zzh(N);
  unsigned char *pointData;
  for (size_t i = 0; i < N; i++) {
    size_t length = EC_POINT_point2buf(group, zz[i], POINT_CONVERSION_COMPRESSED, &pointData, ctx);
    if (length == 0) {
      std::cerr << "Error: Unable to perform point conversion\n";
      exit(1);
    } else if (length != 33) {
      std::cerr << "Error: Invalid point size\n";
      exit(1);
    }
    SHA256(pointData, length, zzhash); // check
    zzh[i] = (*(uint64_t *) zzhash);
  }

  // Bob
  Matrix<uint64_t> ajs(n, 3);
  EC_POINT *yyct = EC_POINT_new(group);
  HASH yycth;
  for (size_t j = 0; j < n; j++) {
    for (size_t k = 0; k < 3; k++) {
      size_t i = locations[j][k];
      if (EC_POINT_mul(group, yyct, nullptr, yyg[j], bobs[i], ctx) != 1) {
        std::cerr << "Error: Unable to perform point multiplication\n";
        exit(1);
      }
      size_t length = EC_POINT_point2buf(group, yyct, POINT_CONVERSION_COMPRESSED, &pointData, ctx);
      if (length == 0) {
        std::cerr << "Error: Unable to perform point conversion\n";
        exit(1);
      } else if (length != 33) {
        std::cerr << "Error: Invalid point size\n";
        exit(1);
      }
      SHA256(pointData, length, yycth); // check
      uint32_t value = yv[j] - yr[i];
      ajs[j][k] = (*(uint64_t *) yycth) ^ (uint64_t) value;
    }
  }

  // Alice
  for (size_t j = 0; j < n; j++) {
    for (size_t k = 0; k < 3; k++) {
      for (size_t i = 0; i < N; i++) {
        uint64_t dec = zzh[i] ^ ajs[j][k];
        if ((dec >> 32) == 0) {
          uint32_t value = dec;
          value += wwpl.getElementVec(i)[0];
          std::printf("DDH ok %zu %zu %zu %d\n", cuckooA.mBins[i].idx(), j, k, value);
        }
      }
    }
  }
}

void testSerialize() {
  const uint32_t num_values = 100;
  auto keys = ipcl::generateKeypair(768);
  auto pk = keys.pub_key;
  auto sk = keys.priv_key;

  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist(0, UINT_MAX);
  std::vector<uint32_t> exp_value(num_values);
  for (int i = 1; i < num_values; i++) {
    exp_value[i] = dist(rng);
  }

  ipcl::PlainText pt = ipcl::PlainText(exp_value);
  ipcl::CipherText ct = pk.encrypt(pt);

  std::ostringstream os;
  ipcl::serializer::serialize(os, ct);

  std::vector<uint32_t> values(num_values);
  ipcl::CipherText ct_after = ipcl::CipherText(pk, values);
  std::istringstream is(os.str());
  ipcl::serializer::deserialize(is, ct_after);

  ipcl::PlainText pt_after = sk.decrypt(ct_after);
  for (int i = 0; i < num_values; i++) {
    std::vector<uint32_t> v = pt.getElementVec(i);
    std::vector<uint32_t> v_after = pt_after.getElementVec(i);
    std::cout << v[0] << " " << v_after[0] << std::endl;

    if (v[0] != v_after[0]) {
      std::cerr << "Error: " << v[0] << " != " << v_after[0] << std::endl;
      exit(1);
    }
  }
}

void testOPRF() {
  size_t n = 100;
  PRNG prng(oc::sysRandomSeed());
  PRNG prng0(oc::sysRandomSeed());
  PRNG prng1(oc::sysRandomSeed());
  auto chls = coproto::LocalAsyncSocket::makePair();
  auto &chl0 = chls[0];
  auto &chl1 = chls[1];

  oc::KkrtNcoOtSender sender;
  oc::KkrtNcoOtReceiver receiver;
  sender.configure(false, 40, 128);
  receiver.configure(false, 40, 128);
  auto tInit0 = sender.init(128, prng0, chl0) | macoro::make_eager();
  auto tInit1 = receiver.init(128, prng1, chl1) | macoro::make_eager();

  macoro::sync_wait(std::move(tInit0));
  macoro::sync_wait(std::move(tInit1));

  vector<block> xx(n);
  prng.get<block>(xx);
  vector<block> yy(n);
  prng.get<block>(yy);
  for (size_t i = 0; i < 3; i++) {
    yy[i] = xx[i];
  }
//  yy[0] = xx[n - 3];
//  yy[1] = xx[n - 2];
//  yy[2] = xx[n - 1];

  vector<block> encoding0(n);
  vector<block> encoding1(n);
  for (size_t i = 0; i < n; i++) {
    receiver.encode(i, &yy[i], &encoding1[i], sizeof(block));
  }
  auto tSend1 = receiver.sendCorrection(chl1, n) | macoro::make_eager(); //need to run first !!!
  auto tSend0 = sender.recvCorrection(chl0, n) | macoro::make_eager();
  macoro::sync_wait(std::move(tSend1));
  macoro::sync_wait(std::move(tSend0));

  for (size_t i = 0; i < n; i++) {
    sender.encode(i, &xx[i], &encoding0[i], sizeof(block));
    for (size_t j = 0; j < n; j++) {
      if (encoding0[i] == encoding1[j]) {
        printf("Match %zu %zu\n", i, j);
      }
    }
  }
}

void testSerialize1() {
  PRNG prng(oc::sysRandomSeed());
  const uint32_t n = 100;
  auto keys = ipcl::generateKeypair(768);
  auto pk = keys.pub_key;
  auto sk = keys.priv_key;

  std::random_device dev;
  std::mt19937 rng(dev());
  std::uniform_int_distribution<std::mt19937::result_type> dist(0, UINT_MAX);
  std::vector<block> values(n);
  prng.get<block>(values);

  std::vector<BigNumber> bns(n);
  for (int i = 0; i < n; i++) {
    bns[i] = BigNumber((uint32_t *) &values[i], 4);
  }
  ipcl::PlainText pt(bns);
  ipcl::CipherText ct = pk.encrypt(pt);

  std::ostringstream os;
  ipcl::serializer::serialize(os, ct);

  ipcl::CipherText ct_after = ipcl::CipherText(pk, bns);
  std::istringstream is(os.str());
  ipcl::serializer::deserialize(is, ct_after);

  ipcl::PlainText pt_after = sk.decrypt(ct_after);
  for (int i = 0; i < n; i++) {
    BigNumber v = pt.getElement(i);
    BigNumber v_after = pt_after.getElement(i);
    std::cout << v << " " << v_after << std::endl;
    if (v != v_after) {
      std::cerr << "Error: " << v << " != " << v_after << std::endl;
      exit(1);
    }
//    std::vector<uint32_t> v = pt.getElementVec(i);
//    std::vector<uint32_t> v_after = pt_after.getElementVec(i);
//    std::cout << v[0] << " " << v_after[0] << std::endl;
//    if (v[0] != v_after[0]) {
//      std::cerr << "Error: " << v[0] << " != " << v_after[0] << std::endl;
//      exit(1);
//    }
  }
}

void test(size_t n) {
//  testEC();
//  testDDH0();
//  testDDH1();
//  testCuckoo();
  benchDDH(n);
//  testSerialize();
//  testOPRF();
//  testORPF2(n);
//  testSerialize1();
}
