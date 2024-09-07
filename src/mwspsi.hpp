#ifndef MWSPSI_HPP
#define MWSPSI_HPP

#include "utils.hpp"

void test(size_t n);
void serverDDH(vector<block> &xx, vector<uint32_t> &xu, ipcl::PublicKey pk, ipcl::PrivateKey sk);
void clientDDH(vector<block> &yy, vector<uint32_t> yv, ipcl::PublicKey pk);
void serverOPRF(vector<block> &xx, vector<uint32_t> &xu, ipcl::PublicKey pk, ipcl::PrivateKey sk);
void clientOPRF(vector<block> &yy, vector<uint32_t> yv, ipcl::PublicKey pk);
void benchDDH(size_t n, u64 intersection = -1);
void benchOPRF(size_t n, u64 intersection = -1);

u64 dlog(EC_GROUP* G, EC_POINT* g, EC_POINT *a, u64 max);
u64 dlog0(EC_GROUP* G, EC_POINT* g, EC_POINT *a, u64 max);
u64 dlog1(EC_GROUP* G, EC_POINT* g, EC_POINT *a, u64 max);
void testDlog();
void benchDlog(u64 n, u64 type);

macoro::task<> clientBlind(coproto::Socket& chl, vector<EC_POINT*>& xx, vector<EC_POINT*>& res);
macoro::task<> serverBlind(coproto::Socket &chl, BIGNUM *b);
void testBlind(size_t n);

void clientBXR(vector<block> xx, vector<u32> xu, u64 max);
void serverBXR(vector<block> yy, vector<u32> yv);
void benchBXR(size_t n, u64 max = 1000, u64 intersection = -1);

#endif
