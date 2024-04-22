#include "utils.hpp"
#include "mwspsi.hpp"

void serverDDH(vector<block> &xx, vector<uint32_t> &xu, ipcl::PublicKey pk, ipcl::PrivateKey sk) {
  auto start = std::chrono::high_resolution_clock::now();

  size_t n = xx.size();
  PRNG prng(oc::sysRandomSeed());
  auto param = CuckooIndex<>::selectParams(n, 40, 0, 3);
  size_t N = n * param.mBinScaler;
  BN_CTX *bnCtx = BN_CTX_new();

  CuckooIndex<> cuckooA;
  cuckooA.init(param);
  cuckooA.insert(oc::span<block>(xx.data(), n));
  //  cuckooA.print();

  vector<EC_POINT *> xxg(N);
  vector<EC_POINT *> xxct(N);
  Matrix<unsigned char> xxctData(N, pointSize);
  vector<uint32_t> xuraw(N);
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
  BN_mod_inverse(ainv, alice, q, bnCtx);

  auto ecStart = std::chrono::high_resolution_clock::now();
  for (size_t i = 0; i < N; i++) {
    xxct[i] = EC_POINT_new(group);
    if (EC_POINT_mul(group, xxct[i], nullptr, xxg[i], alice, bnCtx) != 1) {
      cerr << "Error: Unable to perform point multiplication\n";
      exit(1);
    }
    if (EC_POINT_point2oct(group, xxct[i], POINT_CONVERSION_COMPRESSED, xxctData[i].data(), pointSize, bnCtx)
        != pointSize) {
      cerr << "Error: Unable to convert point to octet string\n";
      exit(1);
    }
  }
  auto ecEnd = std::chrono::high_resolution_clock::now();
  auto ecDuration = std::chrono::duration_cast<std::chrono::milliseconds>(ecEnd - ecStart).count();

  auto aheStart = std::chrono::high_resolution_clock::now();
  ipcl::CipherText xuct = pk.encrypt(xupl);
  std::ostringstream oss;
  ipcl::serializer::serialize(oss, xuct);
  auto aheEnd = std::chrono::high_resolution_clock::now();
  auto aheDuration = std::chrono::duration_cast<std::chrono::milliseconds>(aheEnd - aheStart).count();

  auto xuctStr = oss.str();
  size_t xuctSize = xuctStr.size();

  auto chl = coproto::asioConnect("127.0.0.1:7700", true);
  sync_wait(chl.send(xuctSize));
  sync_wait(chl.send(xuctStr));
  sync_wait(chl.send(xxctData));

  size_t wwctSize = 0;
  string wwctStr;
  sync_wait(chl.recv(wwctSize));
  wwctStr.resize(wwctSize);
  sync_wait(chl.recv(wwctStr));
  std::istringstream wwctISS(wwctStr);
  ipcl::CipherText wwct(pk, xuraw); // check
  ipcl::serializer::deserialize(wwctISS, wwct);
  Matrix<unsigned char> xxctbData(N, pointSize);
  sync_wait(chl.recv(xxctbData));

  ecStart = std::chrono::high_resolution_clock::now();
  EC_POINT *xxctb = EC_POINT_new(group);
  std::vector<EC_POINT *> zz(N);
  for (size_t i = 0; i < N; i++) {
    if (EC_POINT_oct2point(group, xxctb, xxctbData[i].data(), pointSize, bnCtx) != 1) {
      std::cerr << "Error: Unable to convert octet string to point\n";
      exit(1);
    }
    zz[i] = EC_POINT_new(group);
    if (EC_POINT_mul(group, zz[i], nullptr, xxctb, ainv, bnCtx) != 1) {
      std::cerr << "Error: Unable to perform point multiplication\n";
      exit(1);
    }
  }
  ecEnd = std::chrono::high_resolution_clock::now();
  ecDuration += std::chrono::duration_cast<std::chrono::milliseconds>(ecEnd - ecStart).count();

  aheStart = std::chrono::high_resolution_clock::now();
  ipcl::PlainText wwpl = sk.decrypt(wwct);
  vector<uint32_t> ww(N);
  for (size_t i = 0; i < N; i++) {
    ww[i] = wwpl.getElementVec(i)[0];
  }
  aheEnd = std::chrono::high_resolution_clock::now();
  aheDuration += std::chrono::duration_cast<std::chrono::milliseconds>(aheEnd - aheStart).count();

  HASH zzhash;
  std::vector<block> zzh(N);
  unsigned char *pointData;
  for (size_t i = 0; i < N; i++) {
    size_t length = EC_POINT_point2buf(group, zz[i], POINT_CONVERSION_COMPRESSED, &pointData, bnCtx);
    if (length == 0) {
      std::cerr << "Error: Unable to perform point conversion\n";
      exit(1);
    } else if (length != 33) {
      std::cerr << "Error: Invalid point size\n";
      exit(1);
    }
    SHA256(pointData, length, zzhash);
    zzh[i] = (*(block *) zzhash);
  }

  Matrix<block> ajs(n, 3);
  sync_wait(chl.recv(ajs));
  auto cmpStart = std::chrono::high_resolution_clock::now();
  for (size_t j = 0; j < n; j++) {
    for (size_t k = 0; k < 3; k++) {
      for (size_t i = 0; i < N; i++) {
        block dec = zzh[i] ^ ajs[j][k];
        if ((dec >> 32) == ZeroBlock) {
          uint32_t value = *(uint32_t *) &dec;
          value += ww[i];
          std::printf("DDH ok %zu %zu %zu %d\n", cuckooA.mBins[i].idx(), j, k, value);
        }
      }
    }
  }
  auto cmpEnd = std::chrono::high_resolution_clock::now();
  auto cmpDuration = std::chrono::duration_cast<std::chrono::milliseconds>(cmpEnd - cmpStart).count();

  sync_wait(chl.flush());
  auto end = std::chrono::high_resolution_clock::now();
  uint64_t duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
  size_t transfer = chl.bytesReceived() + chl.bytesSent();
  printf("Transfer: %lu bytes, %02.2f KiB, %02.2f MiB, %lu ms\n",
         transfer,
         (double) transfer / 1024,
         (double) transfer / 1048576,
         duration);
  printf("EC: %lu ms, AHE: %lu ms, CMP: %lu ms\n", ecDuration, aheDuration, cmpDuration);
  size_t ecTransfer = xxctData.size() + xxctbData.size();
  size_t aheTransfer = xuctSize + wwctSize;
  size_t cmpTransfer = ajs.size() * sizeof(block);
  printf("EC: %lu bytes, AHE: %lu bytes, CMP: %lu bytes\n",
         ecTransfer,
         aheTransfer,
         cmpTransfer);
}

void serverOPRF(vector<block> &xx, vector<uint32_t> &xu, ipcl::PublicKey pk, ipcl::PrivateKey sk) {
  auto start = std::chrono::high_resolution_clock::now();
  size_t n = xx.size();
  PRNG prng(oc::sysRandomSeed());
  auto param = CuckooIndex<>::selectParams(n, 40, 0, 3);
  size_t N = n * param.mBinScaler;

  CuckooIndex<> cuckooA;
  cuckooA.init(param);
  cuckooA.insert(oc::span<block>(xx.data(), n));

  auto chl = coproto::asioConnect("127.0.0.1:7700", true);
  auto oprfStart = std::chrono::high_resolution_clock::now();
  KkrtNcoOtReceiver receiver;
  receiver.configure(false, 40, 128);
  sync_wait(receiver.init(N, prng, chl));

  vector<BigNumber> xxo(N);
  vector<uint32_t> xuraw(N);
  block OPRFi = ZeroBlock;
  block OPRFv = ZeroBlock;
  for (size_t i = 0; i < N; i++) {
    if (cuckooA.mBins[i].isEmpty()) {
      OPRFi = prng.get<block>();
      receiver.encode(i, &OPRFi, &OPRFv, sizeof(block));
      xuraw[i] = prng.get<uint32_t>();
    } else {
      uint64_t id = cuckooA.mBins[i].idx();
      receiver.encode(i, &xx[id], &OPRFv, sizeof(block));
      xuraw[i] = xu[id];
    }
    xxo[i] = BigNumber((uint32_t *) &OPRFv, 4);
  }
  sync_wait(receiver.sendCorrection(chl, N)); //need to run first !!!
  sync_wait(chl.flush());
  auto oprfEnd = std::chrono::high_resolution_clock::now();
  auto oprfDuration = std::chrono::duration_cast<std::chrono::milliseconds>(oprfEnd - oprfStart).count();
  size_t oprfTransfer = chl.bytesReceived() + chl.bytesSent();

  auto aheStart = std::chrono::high_resolution_clock::now();
  ipcl::CipherText ctxxo = pk.encrypt(ipcl::PlainText(xxo));
  std::ostringstream ctxxoOSS;
  ipcl::serializer::serialize(ctxxoOSS, ctxxo);
  string ctxxoStr = ctxxoOSS.str();
  size_t ctxxoSize = ctxxoStr.size();
  sync_wait(chl.send(ctxxoSize));
  sync_wait(chl.send(ctxxoStr));
  ctxxoOSS.clear();
  ctxxoStr.clear();

  ipcl::CipherText ctxu = pk.encrypt(ipcl::PlainText(xuraw));
  std::ostringstream ctxuOSS;
  ipcl::serializer::serialize(ctxuOSS, ctxu);
  string ctxuStr = ctxuOSS.str();
  size_t ctxuSize = ctxuStr.size();
  sync_wait(chl.send(ctxuSize));
  sync_wait(chl.send(ctxuStr));
  ctxuOSS.clear();
  ctxu.clear();

  ipcl::CipherText ctz(pk, xxo); // check
  size_t ctzSize = 0;
  string ctzStr;
  sync_wait(chl.recv(ctzSize));
  ctzStr.resize(ctzSize);
  sync_wait(chl.recv(ctzStr));
  std::istringstream ctzISS(ctzStr);
  ipcl::serializer::deserialize(ctzISS, ctz);
  ctzISS.clear();
  ctzStr.clear();
  ipcl::PlainText zzpt = sk.decrypt(ctz);

  ipcl::CipherText ctw(pk, xuraw); // check
  size_t ctwSize = 0;
  string ctwStr;
  sync_wait(chl.recv(ctwSize));
  ctwStr.resize(ctwSize);
  sync_wait(chl.recv(ctwStr));
  std::istringstream ctwISS(ctwStr);
  ipcl::serializer::deserialize(ctwISS, ctw);
  ctwISS.clear();
  ctwStr.clear();
  ipcl::PlainText wwpl = sk.decrypt(ctw);
  vector<uint32_t> ww(N);
  for (size_t i = 0; i < N; i++) {
    ww[i] = wwpl.getElementVec(i)[0];
  }
  auto aheEnd = std::chrono::high_resolution_clock::now();
  auto aheDuration = std::chrono::duration_cast<std::chrono::milliseconds>(aheEnd - aheStart).count();

  HASH zzhash;
  std::vector<block> zzh(N);
  unsigned char *data;
  for (size_t i = 0; i < N; i++) {
    BigNumber keyN = zzpt.getElement(i);
    string s;
    keyN.num2hex(s);
    int bnLen = 0;
    ippsRef_BN(nullptr, &bnLen, (Ipp32u **) &data, keyN);
    SHA256(data, sizeof(block), zzhash);
    zzh[i] = (*(block *) zzhash);
  }

  Matrix<block> ajs(n, 3);
  sync_wait(chl.recv(ajs));
  auto cmpStart = std::chrono::high_resolution_clock::now();
  for (size_t j = 0; j < n; j++) {
    for (size_t k = 0; k < 3; k++) {
      for (size_t i = 0; i < N; i++) {
        block dec = zzh[i] ^ ajs[j][k];
        if ((dec >> 32) == ZeroBlock) {
          uint32_t value = *(uint32_t *) &dec;
          value += ww[i];
          std::printf("OPRF ok %zu %zu %zu %d\n", cuckooA.mBins[i].idx(), j, k, value);
        }
      }
    }
  }
  auto cmpEnd = std::chrono::high_resolution_clock::now();
  auto cmpDuration = std::chrono::duration_cast<std::chrono::milliseconds>(cmpEnd - cmpStart).count();

  sync_wait(chl.flush());
  auto end = std::chrono::high_resolution_clock::now();
  uint64_t duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
  size_t transfer = chl.bytesReceived() + chl.bytesSent();
  printf("Transfer: %lu bytes, %02.2f KiB, %02.2f MiB, %lu ms\n",
         transfer,
         (double) transfer / 1024,
         (double) transfer / 1048576,
         duration);
  printf("OPRF: %lu ms, AHE: %lu ms, CMP: %lu ms\n", oprfDuration, aheDuration, cmpDuration);
  size_t aheTransfer = ctxxoSize + ctxuSize + ctzSize + ctwSize;
  size_t cmpTransfer = ajs.size() * sizeof(block);
  printf("OPRF: %lu bytes, AHE: %lu bytes, CMP: %lu bytes\n",
         oprfTransfer,
         aheTransfer,
         cmpTransfer);
}

