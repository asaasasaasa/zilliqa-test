
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

#include "libMediator/Mediator.h"
#include "common/Constants.h"
#include "libUtils/Logger.h"

#include "libServer/LookupServer.h"
#include "libServer/StakingServer.h"
//#include "libServer/StatusServer.h"
#include "depends/safeserver/safehttpserver.h"
#include "libTestUtils/TestUtils.h"

#define BOOST_TEST_MODULE safehttpserver
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>

using namespace std;
using namespace jsonrpc;
using namespace TestUtils;

BOOST_AUTO_TEST_SUITE(safehttpserver1)

BOOST_AUTO_TEST_CASE(stakingrpcserver1) {
  INIT_STDOUT_LOGGER();

  std::shared_ptr<LookupServer> m_lookupServer;
  std::shared_ptr<StakingServer> m_stakingServer;
  //std::unique_ptr<StatusServer> m_statusServer;
  std::unique_ptr<jsonrpc::AbstractServerConnector> m_lookupServerConnector;
  std::unique_ptr<jsonrpc::AbstractServerConnector> m_stakingServerConnector;
  //std::unique_ptr<jsonrpc::AbstractServerConnector> m_statusServerConnector;
    Mediator mediator(GenerateRandomKeyPair(), GenerateRandomPeer());

    m_lookupServerConnector = make_unique<SafeHttpServer>(4201);
      m_lookupServer =
          make_shared<LookupServer>(mediator, *m_lookupServerConnector);

      if (m_lookupServer == nullptr) {
        LOG_GENERAL(WARNING, "m_lookupServer NULL");
      } else {
          if (m_lookupServer->StartListening()) {
            LOG_GENERAL(INFO, "API Server started successfully");
          } else {
            LOG_GENERAL(WARNING, "API Server couldn't start");
          }
      }


    m_stakingServerConnector = make_unique<SafeHttpServer>(4203);
      m_stakingServer =
          make_shared<StakingServer>(mediator, *m_stakingServerConnector);

      if (m_stakingServer == nullptr) {
        LOG_GENERAL(WARNING, "m_stakingServer NULL");
      } else {
          if (m_stakingServer->StartListening()) {
            LOG_GENERAL(INFO, "Staking Server started successfully");
          } else {
            LOG_GENERAL(WARNING, "Staking Server couldn't start");
          }
      }

      if (m_stakingServer->StopListening()) {
          LOG_GENERAL(INFO, "Staking Server stopped successfully");
      } else {
          LOG_GENERAL(WARNING, "Staking Server couldn't start stop");
      }

      if (m_lookupServer->StopListening()) {
            LOG_GENERAL(INFO, "API Server stopped successfully");
      } else {
            LOG_GENERAL(WARNING, "API Server couldn't start stop");
      }



  //BOOST_CHECK_EQUAL(dsblock_str, orig);
}


BOOST_AUTO_TEST_SUITE_END()