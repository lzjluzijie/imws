#ifndef UTILS_HPP
#define UTILS_HPP

#include <climits>

#include <chrono>
#include <iostream>
#include <random>
#include <vector>

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include "ipcl/ipcl.hpp"
#include "ipcl/bignum.h"

#include "cryptoTools/Common/CuckooIndex.h"
#include "cryptoTools/Common/Matrix.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"

#include <coproto/Socket/AsioSocket.h>
#include <coproto/Socket/LocalAsyncSock.h>

#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h>
#include <libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h>

using oc::block;
using oc::ZeroBlock;
using oc::PRNG;
using oc::CuckooIndex;
using oc::Matrix;
using std::vector;
using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::thread;
using macoro::sync_wait;
using oc::KkrtNcoOtSender;
using oc::KkrtNcoOtReceiver;
//using u128 = unsigned __int128;
using oc::Timer;

using HASH = unsigned char[SHA256_DIGEST_LENGTH];

BIGNUM *bn(uint x);

extern BIGNUM *b3;
extern EC_GROUP *group;
extern EC_POINT *basePoint;
extern size_t pointSize;
extern BIGNUM *p, *a, *b, *q;
extern BN_CTX *ctx;

void init();

BIGNUM *YSquare(BIGNUM *x);

EC_POINT *toPoint(const unsigned char *data, size_t len);

EC_POINT *toPoint(const char *data, size_t len);

#endif
