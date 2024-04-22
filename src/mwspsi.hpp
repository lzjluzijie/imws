#ifndef MWSPSI_HPP
#define MWSPSI_HPP

#include "utils.hpp"

void test(size_t n);
void serverDDH(vector<block> &xx, vector<uint32_t> &xu, ipcl::PublicKey pk, ipcl::PrivateKey sk);
void clientDDH(vector<block> &yy, vector<uint32_t> yv, ipcl::PublicKey pk);
void serverOPRF(vector<block> &xx, vector<uint32_t> &xu, ipcl::PublicKey pk, ipcl::PrivateKey sk);
void clientOPRF(vector<block> &yy, vector<uint32_t> yv, ipcl::PublicKey pk);
void benchDDH(size_t n);
void benchOPRF(size_t n);

#endif
