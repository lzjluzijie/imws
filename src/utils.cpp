#include "utils.hpp"

BIGNUM *bn(uint x) {
  BIGNUM *result = BN_new();
  BN_set_word(result, x);
  return result;
}

BIGNUM *b3 = bn(3);
EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
EC_POINT *basePoint = EC_POINT_dup(EC_GROUP_get0_generator(group), group);
size_t pointSize = EC_POINT_point2oct(group, basePoint, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx);
BIGNUM *p, *a, *b, *q;
BN_CTX *ctx = BN_CTX_new();
int print = 0;

void init() {
  p = BN_new();
  a = BN_new();
  b = BN_new();
  q = BN_new();
  BN_hex2bn(&p, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
  BN_hex2bn(&a, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
  BN_hex2bn(&b, "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
  BN_hex2bn(&q, "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
//  std::cout << pointSize << std::endl;
}

BIGNUM *YSquare(BIGNUM *x) {
  BIGNUM *y2 = BN_dup(x);
  BN_mod_sqr(y2, y2, p, ctx);
  BN_mod_add(y2, y2, a, p, ctx);
  BN_mod_mul(y2, y2, x, p, ctx);
  BN_mod_add(y2, y2, b, p, ctx);
  return y2;
}

EC_POINT *toPoint(const unsigned char *data, size_t len) {
  HASH hash;
  SHA256(data, len, hash);

  EC_POINT *result = EC_POINT_new(group);
  while (true) {
    BIGNUM *x = BN_new();
    BN_bin2bn(hash, SHA256_DIGEST_LENGTH, x);
    BIGNUM *y2 = YSquare(x);
    BIGNUM *y = BN_new();
    if (BN_mod_sqrt(y, y2, p, ctx)) {
      if (EC_POINT_set_affine_coordinates(group, result, x, y, ctx) == 1) {
        return result;
      } else {
        std::cout << "EC_POINT_set_affine_coordinates failed" << std::endl;
        SHA256(hash, SHA256_DIGEST_LENGTH, hash);
        // should not happen
        continue;
      }
    } else {
//      std::cout << "y2 is not a square" << std::endl;
      SHA256(hash, SHA256_DIGEST_LENGTH, hash);
      continue;
    }
  }
}

EC_POINT *toPoint(const char *data, size_t len) {
  return toPoint(reinterpret_cast<const unsigned char *>(data), len);
}

EC_POINT *toPoint(block data) {
  return toPoint(reinterpret_cast<const unsigned char *>(&data), sizeof(block));
}

void genData0(vector<block> &xx, vector<u32> &xu, vector<block> &yy, vector<u32> &yv, u64 n, u64 max, block seed) {
  PRNG prng(oc::sysRandomSeed());
  prng.get<block>(xx);
  for (size_t i = 0; i < n; i++) {
    xu[i] = i % max;
  }
  prng.get<block>(yy);
  yy[0] = xx[n - 3];
  yy[1] = xx[n - 2];
  yy[2] = xx[n - 1];
  for (size_t i = 0; i < n; i++) {
    yv[i] = (max - 2 * i) % max;
  }
}

void genData1(vector<block> &xx, vector<u32> &xu, vector<block> &yy, vector<u32> &yv, u64 n, u64 max, block seed) {
  PRNG prng(seed);
  prng.get<block>(xx);
  for (size_t i = 0; i < n; i++) {
    xu[i] = i % max;
  }
  prng.get<block>(yy);
  for (size_t i = 0; i < n / 2; i++) {
    yy[i] = xx[i];
  }
  for (size_t i = 0; i < n; i++) {
    yv[i] = (max - 2 * i) % max;
  }
}

void genData2(vector<block> &xx, vector<u32> &xu, vector<block> &yy, vector<u32> &yv, u64 n, u64 max, u64 intersection, block seed) {
  if (intersection == -1) {
    intersection = n / 2;
  }
  cout << "intersection: " << intersection << endl;

  PRNG prng(seed);
  prng.get<block>(xx);
  prng.get<u32>(xu);
  for (size_t i = 0; i < n; i++) {
    xu[i] = xu[i] % max;
  }
  prng.get<block>(yy);
  prng.get<u32>(yv);
  for (size_t i = 0; i < intersection; i++) {
    yy[i] = xx[i];
  }
  for (size_t i = 0; i < n; i++) {
    yv[i] = yv[i] % max;
  }

  vector<size_t> indices(n);
  std::iota(indices.begin(), indices.end(), 0);
  std::shuffle(indices.begin(), indices.end(), prng);
  for (size_t i = 0; i < n ; i++) {
    if (i != indices[i]) {
      std::swap(yy[i], yy[indices[i]]);
      std::swap(yv[i], yv[indices[i]]);
      std::swap(indices[i], indices[indices[i]]);
    }
  }
  std::shuffle(indices.begin(), indices.end(), prng);
  for (size_t i = 0; i < n ; i++) {
    if (i != indices[i]) {
      std::swap(yy[i], yy[indices[i]]);
      std::swap(yv[i], yv[indices[i]]);
      std::swap(indices[i], indices[indices[i]]);
    }
  }
}
