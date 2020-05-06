/*
 * Copyright (C) 2019 Zilliqa
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

#define BOOST_TEST_MODULE trietest
#include <json/json.h>
#include <boost/filesystem/path.hpp>
#include <boost/test/included/unit_test.hpp>

#include "depends/common/CommonIO.h"
#include "depends/common/FixedHash.h"
#include "depends/libTrie/TrieDB.h"
#include "depends/libTrie/TrieHash.h"
#include "libData/AccountData/Account.h"
#include "libData/AccountData/Address.h"
#include "libData/AccountData/Transaction.h"
#include "libPersistence/ContractStorage2.h"
#include "libUtils/DataConversion.h"
#include "libUtils/JsonUtils.h"
#include "libUtils/Logger.h"

using namespace std;
using namespace boost::multiprecision;
using namespace dev;
using namespace Contract;

BOOST_AUTO_TEST_SUITE(statetrietest)

BOOST_AUTO_TEST_CASE(state_trie_test) {
  INIT_STDOUT_LOGGER();

  LOG_MARKER();

  std::shared_ptr<LevelDB> mp_stateDataDB =
      make_shared<LevelDB>("contractStateData2");
  std::shared_ptr<std::map<std::string, bytes>> mp_stateDataMap =
      make_shared<std::map<string, bytes>>();
  std::shared_ptr<std::set<std::string>> mp_indexToBeDeleted =
      make_shared<std::set<string>>();

  PermOverlayMap m_permOM({mp_stateDataMap, mp_indexToBeDeleted},
                          {mp_stateDataDB});

  dev::GenericTrieDB<PermOverlayMap> m_permTrie(&m_permOM);

  m_permTrie.init();

  PairOfKey acct1, acct2 = Schnorr::GenKeyPair();
  Address addr1, addr2;
  addr1 = Account::GetAddressFromPublicKey(acct1.second);
  addr2 = Account::GetAddressFromPublicKey(acct2.second);

  h256 addr1Root, addr2Root;

  Json::Value addr1_depth, addr2_depth;
  Json::Value addr_depth_obj;

  // addr1 depth:
  // [
  //	{
  //		"vname" : "a",
  //		"depth" : 0
  //	},
  //	{
  //		"vname" : "b",
  //		"depth" : 1
  //    }
  // ]

  addr_depth_obj["vname"] = "a";
  addr_depth_obj["depth"] = 0;
  addr1_depth.append(addr_depth_obj);

  addr_depth_obj["vname"] = "b";
  addr_depth_obj["depth"] = 1;
  addr1_depth.append(addr_depth_obj);

  // addr2 depth:
  // [
  //	{
  //		"vname" : "a",
  //		"depth" : 0
  //	},
  //	{
  //		"vname" : "b",
  //		"depth" : 2
  //    }
  // ]

  addr_depth_obj["vname"] = "a";
  addr_depth_obj["depth"] = 0;
  addr2_depth.append(addr_depth_obj);

  addr_depth_obj["vname"] = "b";
  addr_depth_obj["depth"] = 2;
  addr2_depth.append(addr_depth_obj);

  // addr1:
  // 	a : "1",
  //  	b :
  // 	{
  //		a : "2",
  //		b : "3",
  //	}

  // addr1
  m_permTrie.insert(
      DataConversion::StringToCharArray(ContractStorage2::GenerateStorageKey(
          addr1, FIELDS_MAP_DEPTH_INDICATOR, {})),
      DataConversion::StringToCharArray(
          JSONUtils::GetInstance().convertJsontoStr(addr1_depth)));
  m_permTrie.insert(DataConversion::StringToCharArray(
                        ContractStorage2::GenerateStorageKey(addr1, "a", {})),
                    DataConversion::StringToCharArray("1"));

  addr1Root = m_permTrie.root();
  m_permTrie.init();
  m_permTrie.setRoot(addr1Root);
  LOG_GENERAL(
      INFO,
      "addr1-a result: " << m_permTrie.at(DataConversion::StringToCharArray(
          ContractStorage2::GenerateStorageKey(addr1, "a", {}))));

  m_permTrie.insert(DataConversion::StringToCharArray(
                        ContractStorage2::GenerateStorageKey(addr1, "b", {})),
                    DataConversion::StringToCharArray("{}"));
  m_permTrie.insert(
      DataConversion::StringToCharArray(
          ContractStorage2::GenerateStorageKey(addr1, "b", {"a"})),
      DataConversion::StringToCharArray("2"));
  m_permTrie.insert(
      DataConversion::StringToCharArray(
          ContractStorage2::GenerateStorageKey(addr1, "b", {"b"})),
      DataConversion::StringToCharArray("3"));

  addr1Root = m_permTrie.root();
  m_permTrie.init();

  // addr2:
  // 	a : "4",
  //	b :
  //	{
  //		a : "5",
  //		b :
  //		{
  //			a : "6",
  //			b : "7"
  //		}
  //	}

  m_permTrie.insert(
      DataConversion::StringToCharArray(ContractStorage2::GenerateStorageKey(
          addr2, FIELDS_MAP_DEPTH_INDICATOR, {})),
      DataConversion::StringToCharArray(
          JSONUtils::GetInstance().convertJsontoStr(addr2_depth)));
  m_permTrie.insert(DataConversion::StringToCharArray(
                        ContractStorage2::GenerateStorageKey(addr2, "a", {})),
                    DataConversion::StringToCharArray("4"));

  addr2Root = m_permTrie.root();
  m_permTrie.init();
  m_permTrie.setRoot(addr2Root);
  LOG_GENERAL(
      INFO,
      "addr2-a result: " << m_permTrie.at(DataConversion::StringToCharArray(
          ContractStorage2::GenerateStorageKey(addr2, "a", {}))));

  m_permTrie.insert(DataConversion::StringToCharArray(
                        ContractStorage2::GenerateStorageKey(addr1, "b", {})),
                    DataConversion::StringToCharArray("{}"));
  m_permTrie.insert(
      DataConversion::StringToCharArray(
          ContractStorage2::GenerateStorageKey(addr2, "b", {"a"})),
      DataConversion::StringToCharArray("5"));
  m_permTrie.insert(
      DataConversion::StringToCharArray(
          ContractStorage2::GenerateStorageKey(addr2, "b", {"b"})),
      DataConversion::StringToCharArray("{}"));
  m_permTrie.insert(
      DataConversion::StringToCharArray(
          ContractStorage2::GenerateStorageKey(addr2, "b", {"b", "a"})),
      DataConversion::StringToCharArray("6"));
  m_permTrie.insert(
      DataConversion::StringToCharArray(
          ContractStorage2::GenerateStorageKey(addr2, "b", {"b", "b"})),
      DataConversion::StringToCharArray("7"));

  addr2Root = m_permTrie.root();
  m_permTrie.init();
  m_permTrie.setRoot(addr2Root);
  LOG_GENERAL(
      INFO,
      "addr2-b-b-b result: " << m_permTrie.at(DataConversion::StringToCharArray(
          ContractStorage2::GenerateStorageKey(addr2, "b", {"b","b"}))));

  string addr2_b_b_str = ContractStorage2::GenerateStorageKey(addr2, "b", {"b"});
  bytes addr2_b_b = DataConversion::StringToCharArray(addr2_b_b_str);

  for (auto iter = m_permTrie.lower_bound(&addr2_b_b); iter != m_permTrie.end() && iter.at().first.toString().compare(0, addr2_b_b_str.size(), addr2_b_b_str) == 0; ++iter) {
  	LOG_GENERAL(INFO, "iter key:" << iter.at().first.toString() << " value:" << iter.at().second.toString());
  }
}

BOOST_AUTO_TEST_SUITE_END()