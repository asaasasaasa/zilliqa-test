/*
 * Copyright (C) 2021 Zilliqa
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "DnsUtils.h"
#include "DataConversion.h"
#include "Logger.h"

#include "common/Constants.h"
#include "libUtils/DetachedFunction.h"
#include "libUtils/IPConverter.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <condition_variable>
#include <unordered_map>

using namespace std;

namespace {

atomic<bool> isShuttingDown;

using DnsIpListData = vector<string>;
using DnsPubKeyListData = unordered_map<uint128_t, bytes>;

struct DnsCacheList {
  mutex dataAccessMutex;

  DnsIpListData ipList;
  DnsPubKeyListData pubKeyList;
};

unordered_map<DnsListType, string> dnsAddresses;

// End of dsepoch, a separate thread will be spawned to query
// To avoid coupling dns lookup delay
// At the next dsepoch, we will update our local list to this cache
// And the above starts over again
unordered_map<DnsListType, DnsCacheList> dnsCacheListDataMap;

bool QueryIpStrListFromDns(DnsListType listType) {
  LOG_MARKER();
  const auto &url = dnsAddresses[listType];

  if (url.empty()) {
    LOG_GENERAL(INFO, "DNS is empty");
    return false;
  }

  struct addrinfo hints {
  }, *res, *result;
  int errcode = 0;
  char addrstr[100];
  void *ptr = nullptr;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  for (unsigned int retry = 0; retry < QUERY_DNS_MAX_TRIES; ++retry) {
    if (isShuttingDown) break;

    errcode = getaddrinfo(url.c_str(), NULL, &hints, &result);
    if (errcode != 0) {
      LOG_GENERAL(WARNING, "Unable to connect "
                               << url << " Err: " << errcode
                               << ", Msg: " << gai_strerror(errcode)
                               << ", retry: " << retry);
      continue;
    }
    break;  // If we are here, means success
  }

  if (isShuttingDown) return false;

  if (errcode != 0) {
    LOG_GENERAL(WARNING, "Unable to connect " << url << ", Err: " << errcode);
    return false;
  }

  res = result;

  auto &ipStrList = dnsCacheListDataMap[listType].ipList;
  ipStrList.clear();

  while (res) {
    switch (res->ai_family) {
      case AF_INET:
        ptr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
        break;
      case AF_INET6:
        ptr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
        break;
    }

    if (ptr) {
      inet_ntop(res->ai_family, ptr, addrstr, 100);
      LOG_GENERAL(DEBUG, "Address: " << addrstr);
      ipStrList.emplace_back(addrstr);
    }
    res = res->ai_next;
    ptr = nullptr;
  }

  freeaddrinfo(result);

  return true;
}

// Pub key are stored in the TXT record
bool QueryPubKeyFromUrl(bytes &output, const string &pubKeyUrl) {
  LOG_MARKER();

  unsigned char query_buffer[256];
  int resLen = 0;

  for (unsigned int retry = 0; retry < QUERY_DNS_MAX_TRIES; ++retry) {
    if (isShuttingDown) return false;

    resLen = res_query(pubKeyUrl.c_str(), C_IN, ns_t_txt, query_buffer,
                       sizeof(query_buffer));
    if (resLen < 0) {
      LOG_GENERAL(WARNING, "Failed to query pub key from "
                               << pubKeyUrl << " Retry: " << retry);
      continue;
    }
    break;  // If we are here, means success
  }

  if (isShuttingDown) return false;

  if (resLen < 0) {
    LOG_GENERAL(WARNING, "Unable to obtain pubkey from " << pubKeyUrl
                                                         << " Res: " << resLen);
    return false;
  }

  ns_msg nsMsg;
  ns_initparse(query_buffer, resLen, &nsMsg);

  if (ns_msg_count(nsMsg, ns_s_an) <= 0) {
    LOG_GENERAL(WARNING, "No data found from pub key from " << pubKeyUrl);
    return false;
  }

  ns_rr rr;
  ns_parserr(&nsMsg, ns_s_an, 0, &rr);
  auto rrData = ns_rr_rdata(rr) + 1;

  string p(rrData, rrData + rr.rdlength - 1);

  if (p.compare("0") == 0 || p.empty()) {
    LOG_GENERAL(WARNING, "Pubkey from dns is 0 or empty: " << pubKeyUrl);
    return false;
  }

  if (!DataConversion::HexStrToUint8Vec(p, output)) {
    LOG_GENERAL(WARNING, "Invalid data obtained from pub key " << pubKeyUrl);
    return false;
  }
  return true;
}

void QueryDnsList(DnsListType listType) {
  LOG_MARKER();
  if (isShuttingDown) return;

  if (dnsAddresses[listType].empty()) {
    LOG_GENERAL(INFO, "DNS address is empty for type " << (int)listType);
    return;
  }

  auto &dataListCache = dnsCacheListDataMap[listType];

  if (!dataListCache.dataAccessMutex.try_lock()) {
    LOG_GENERAL(INFO, "Another thread is querying " << dnsAddresses[listType]);
    return;
  }

  if (!QueryIpStrListFromDns(listType)) {
    LOG_GENERAL(WARNING, "Failed to obtain ip list from "
                             << dnsAddresses[listType]
                             << ", try again on another DS epoch");
    dataListCache.dataAccessMutex.unlock();
    return;
  }

  vector<uint128_t> currentIpKeys;
  currentIpKeys.reserve(dataListCache.ipList.size());

  auto &pubKeyList = dataListCache.pubKeyList;
  auto url = dnsAddresses[listType];

  if (url.empty()) {
    LOG_GENERAL(WARNING, "url is empty");
    dataListCache.dataAccessMutex.unlock();
    return;
  }

  // Adding new pubkeys to our dns cache
  for (const auto &ipStr : dataListCache.ipList) {
    uint128_t ipKey;
    if (!IPConverter::ToNumericalIPFromStr(ipStr, ipKey)) {
      LOG_GENERAL(WARNING, "Unable to change IP to ipKey: " << ipKey);
      continue;
    }

    currentIpKeys.emplace_back(ipKey);

    if (pubKeyList.find(ipKey) != pubKeyList.end()) {
      // Already exists, don't need to query again, unlikely to change pubkey
      // for an ip
      continue;
    }

    if (ipStr.empty()) {
      LOG_GENERAL(WARNING, "Ip is empty");
      continue;
    }

    auto pubKeyUrl = GetPubKeyUrl(ipStr, url);
    bytes pubKeyResult;
    if (QueryPubKeyFromUrl(pubKeyResult, pubKeyUrl)) {
      pubKeyList[ipKey] = pubKeyResult;
    }
  }

  // Remove pubkeys that are no longer in the dns list
  for (auto itr = pubKeyList.begin(); itr != pubKeyList.end();) {
    if (find(currentIpKeys.begin(), currentIpKeys.end(), itr->first) ==
        currentIpKeys.end()) {
      itr = pubKeyList.erase(itr);
    } else {
      ++itr;
    }
  }

  dataListCache.dataAccessMutex.unlock();
}
}  // namespace

void InitDnsCacheList() {
  dnsCacheListDataMap[DnsListType::UPPER_SEED];
  dnsCacheListDataMap[DnsListType::L2L_DATA_PROVIDERS];
  dnsCacheListDataMap[DnsListType::MULTIPLIERS];

  dnsAddresses[DnsListType::UPPER_SEED] = UPPER_SEED_DNS;
  dnsAddresses[DnsListType::L2L_DATA_PROVIDERS] = L2L_DATA_PROVIDERS_DNS;
  dnsAddresses[DnsListType::MULTIPLIERS] = MULTIPLIER_DNS;

  isShuttingDown = false;
}

void ShutDownDnsCacheList() { isShuttingDown = true; }

void AttemptPopulateLookupsDnsCache() {
  LOG_MARKER();
  QueryDnsList(DnsListType::UPPER_SEED);
  QueryDnsList(DnsListType::L2L_DATA_PROVIDERS);
  QueryDnsList(DnsListType::MULTIPLIERS);
}

string GetPubKeyUrl(const std::string &ip, const std::string &url) {
  auto tmpIp = ip;
  std::replace(tmpIp.begin(), tmpIp.end(), '.', '-');
  return "pub-" + tmpIp + url.substr(url.find_first_of('.'));
}

bool GetIpStrListFromDnsCache(std::vector<std::string> &ipStrList,
                              DnsListType listType) {
  auto &dnsCacheList = dnsCacheListDataMap[listType];
  if (!dnsCacheList.dataAccessMutex.try_lock()) {
    LOG_GENERAL(INFO, "Unable to obtain data from "
                          << dnsAddresses[listType]
                          << ", data are still being queried");
    return false;
  }

  auto isEmptyCache = dnsCacheList.ipList.empty();

  if (isEmptyCache) {
    LOG_GENERAL(INFO, "Dns cache is empty for " << dnsAddresses[listType]);
  } else {
    ipStrList = dnsCacheList.ipList;
  }

  dnsCacheList.dataAccessMutex.unlock();
  return !isEmptyCache;
}

bool GetPubKeyFromDnsCache(bytes &output, const std::string &ipStr,
                           DnsListType listType) {
  auto &dnsCacheList = dnsCacheListDataMap[listType];
  if (!dnsCacheList.dataAccessMutex.try_lock()) {
    LOG_GENERAL(INFO, "Unable to obtain PubKey for "
                          << ipStr << ", data are still being queried");
    return false;
  }

  uint128_t ipKey;
  if (!IPConverter::ToNumericalIPFromStr(ipStr, ipKey)) {
    LOG_GENERAL(WARNING, "Unable to change IP to ipKey: " << ipKey);
    return false;
  }
  auto &pubKeyList = dnsCacheList.pubKeyList;
  auto itr = pubKeyList.find(ipKey);

  auto pubKeyNotFound = itr == pubKeyList.end();
  if (pubKeyNotFound) {
    LOG_GENERAL(INFO, "Unable to find pubkey in cache for " << ipStr);
  } else {
    output = itr->second;
  }

  dnsCacheList.dataAccessMutex.unlock();

  return !pubKeyNotFound;
}
