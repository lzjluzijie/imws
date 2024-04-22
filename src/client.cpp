#include "utils.hpp"
#include "mwspsi.hpp"

void clientDDH(vector<block> &yy, vector<uint32_t> yv, ipcl::PublicKey pk) {
  size_t n = yy.size();
  PRNG prng(oc::sysRandomSeed());
  auto param = CuckooIndex<>::selectParams(n, 40, 0, 3);
  size_t N = n * param.mBinScaler;
  BN_CTX *bnCtx = BN_CTX_new();

  std::vector<uint32_t> yr(N);
  prng.get<uint32_t>(yr);
  CuckooIndex<> cuckooB;
  cuckooB.init(param);
//  cuckooB.insert(yy);
//  cuckooB.print();
  Matrix<uint32_t> locations(n, 3);
  cuckooB.computeLocations(yy, locations);

  std::vector<EC_POINT *> yyg(n);
  ipcl::PlainText yvpl(yr);
  ipcl::CipherText yvct = pk.encrypt(yvpl);

  std::vector<BIGNUM *> bobs(N);
  for (size_t i = 0; i < N; i++) {
    bobs[i] = BN_new();
    BN_rand_range(bobs[i], q);
  }
  for (size_t i = 0; i < n; i++) {
    yyg[i] = toPoint(yy[i].data(), sizeof(block));
  }

  size_t xuctSize = 0;
  string xuctStr;
  auto chl = coproto::asioConnect("127.0.0.1:7700", false);
  sync_wait(chl.recv(xuctSize));
  xuctStr.resize(xuctSize);
  sync_wait(chl.recv(xuctStr));

  vector<uint32_t> dummy(N);
  ipcl::CipherText xuct(pk, dummy); // check
  std::istringstream xuctISS(xuctStr);
  ipcl::serializer::deserialize(xuctISS, xuct);

  Matrix<unsigned char> xxctData(N, pointSize);
  sync_wait(chl.recv(xxctData));
  std::vector<EC_POINT *> xxctb(N);
  Matrix<unsigned char> xxctbData(N, pointSize);
  for (size_t i = 0; i < N; i++) {
    xxctb[i] = EC_POINT_new(group);
    if (EC_POINT_oct2point(group, xxctb[i], xxctData[i].data(), pointSize, bnCtx) != 1) {
      std::cerr << "Error: Unable to convert octet string to point\n";
      exit(1);
    }
    if (EC_POINT_mul(group, xxctb[i], nullptr, xxctb[i], bobs[i], bnCtx) != 1) {
      std::cerr << "Error: Unable to perform point multiplication\n";
      exit(1);
    }
    if (EC_POINT_point2oct(group, xxctb[i], POINT_CONVERSION_COMPRESSED, xxctbData[i].data(), pointSize, bnCtx)
        != pointSize) {
      std::cerr << "Error: Unable to convert point to octet string\n";
      exit(1);
    }
  }
  ipcl::CipherText wwct = xuct + yvct;
  std::ostringstream oss;
  ipcl::serializer::serialize(oss, wwct);
  string wwctStr = oss.str();
  size_t wwctSize = wwctStr.size();
  sync_wait(chl.send(wwctSize));
  sync_wait(chl.send(wwctStr));
  sync_wait(chl.send(xxctbData));

  unsigned char *pointData;
  Matrix<block> ajs(n, 3);
  EC_POINT *yyct = EC_POINT_new(group);
  HASH yycth;
  for (size_t j = 0; j < n; j++) {
    for (size_t k = 0; k < 3; k++) {
      size_t i = locations[j][k];
      if (EC_POINT_mul(group, yyct, nullptr, yyg[j], bobs[i], bnCtx) != 1) {
        std::cerr << "Error: Unable to perform point multiplication\n";
        exit(1);
      }
      size_t length = EC_POINT_point2buf(group, yyct, POINT_CONVERSION_COMPRESSED, &pointData, bnCtx);
      if (length == 0) {
        std::cerr << "Error: Unable to perform point conversion\n";
        exit(1);
      } else if (length != 33) {
        std::cerr << "Error: Invalid point size\n";
        exit(1);
      }
      SHA256(pointData, length, yycth);
      uint32_t value = yv[j] - yr[i];
      ajs[j][k] = (*(block *) yycth) ^ (block) value;
    }
  }
  sync_wait(chl.send(ajs));

  sync_wait(chl.flush());
}

void clientOPRF(vector<block> &yy, vector<uint32_t> yv, ipcl::PublicKey pk) {
  size_t n = yy.size();
  PRNG prng(oc::sysRandomSeed());
  auto param = CuckooIndex<>::selectParams(n, 40, 0, 3);
  size_t N = n * param.mBinScaler;

  std::vector<uint32_t> yr(N);
  prng.get<uint32_t>(yr);
  CuckooIndex<> cuckooB;
  cuckooB.init(param);
//  cuckooB.insert(yy);
//  cuckooB.print();
  Matrix<uint32_t> locations(n, 3);
  cuckooB.computeLocations(yy, locations);

  vector<BigNumber> yrr(N);
  block tmp = ZeroBlock;
  for (size_t i = 0; i < N; i++) {
    tmp = prng.get<block>();
    yrr[i] = BigNumber((uint32_t *) &tmp, 4);
  }
  ipcl::PlainText yrrpl(yrr);
  ipcl::PlainText yrpl(yr);

  KkrtNcoOtSender sender;
  sender.configure(false, 40, 128);
  vector<block> encoding0(n);
  auto chl = coproto::asioConnect("127.0.0.1:7700", false);
  sync_wait(sender.init(N, prng, chl));
  sync_wait(sender.recvCorrection(chl, N));

  size_t ctxxoSize = 0;
  sync_wait(chl.recv(ctxxoSize));
  string ctxxoStr;
  ctxxoStr.resize(ctxxoSize);
  sync_wait(chl.recv(ctxxoStr));
  std::istringstream ctxxoISS(ctxxoStr);
  ipcl::CipherText ctxxo(pk, yrr); // check
  ipcl::serializer::deserialize(ctxxoISS, ctxxo);
  ctxxoISS.clear();
  ctxxoStr.clear();

  size_t ctxuSize = 0;
  sync_wait(chl.recv(ctxuSize));
  string ctxuStr;
  ctxuStr.resize(ctxuSize);
  sync_wait(chl.recv(ctxuStr));
  std::istringstream ctxuISS(ctxuStr);
  ipcl::CipherText ctxu(pk, yr); // check
  ipcl::serializer::deserialize(ctxuISS, ctxu);
  ctxuISS.clear();
  ctxuStr.clear();

  ipcl::CipherText ctz = ctxxo + yrrpl;
  std::ostringstream ctzOSS;
  ipcl::serializer::serialize(ctzOSS, ctz);
  string ctzStr = ctzOSS.str();
  size_t ctzSize = ctzStr.size();
  sync_wait(chl.send(ctzSize));
  sync_wait(chl.send(ctzStr));
  ctzOSS.clear();
  ctzStr.clear();

  ipcl::CipherText ctw = ctxu + yrpl;
  std::ostringstream ctwOSS;
  ipcl::serializer::serialize(ctwOSS, ctw);
  string ctwStr = ctwOSS.str();
  size_t ctwSize = ctwStr.size();
  sync_wait(chl.send(ctwSize));
  sync_wait(chl.send(ctwStr));
  ctwOSS.clear();
  ctwStr.clear();

  unsigned char *data;
  Matrix<block> ajs(n, 3);
  HASH yycth;
  for (size_t j = 0; j < n; j++) {
    for (size_t k = 0; k < 3; k++) {
      size_t i = locations[j][k];
      sender.encode(i, &yy[j], &tmp, sizeof(block));
      BigNumber keyN = BigNumber((uint32_t *) &tmp, 4) + yrr[i];
      int bnLen = 0;
      ippsRef_BN(nullptr, &bnLen, (Ipp32u **) &data, keyN);
      SHA256(data, sizeof(block), yycth);
      uint32_t value = yv[j] - yr[i];
      ajs[j][k] = (*(block *) yycth) ^ (block) value;
    }
  }
  sync_wait(chl.send(ajs));

  sync_wait(chl.flush());
}
