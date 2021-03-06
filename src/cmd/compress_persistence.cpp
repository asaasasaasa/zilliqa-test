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

#include <iostream>

#include <boost/program_options.hpp>
#include "depends/libDatabase/LevelDB.h"
#include "libUtils/FileSystem.h"

/// Should be run with working directory where folder "persistence" consisting
/// of the individual dbs exists.

#define SUCCESS 0
#define ERROR_IN_COMMAND_LINE -1
#define ERROR_UNHANDLED_EXCEPTION -2
#define ERROR_UNEXPECTED -3

using namespace std;
namespace po = boost::program_options;

int main(int argc, const char* argv[]) {
  string dbname;
  try {
    po::options_description desc("Options");

    desc.add_options()("help,h", "Print help messages")(
        "db name,p",
        po::value<string>(&dbname)->default_value(bfs::current_path().string()),
        "name of leveldb that resides in persistence folder and is to be "
        "compressed");

    po::variables_map vm;
    try {
      po::store(po::parse_command_line(argc, argv, desc), vm);

      if (vm.count("help")) {
        cout << desc << endl;
        return SUCCESS;
      }
      po::notify(vm);
    } catch (boost::program_options::required_option& e) {
      std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
      std::cout << desc;
      return ERROR_IN_COMMAND_LINE;
    } catch (boost::program_options::error& e) {
      std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
      return ERROR_IN_COMMAND_LINE;
    }

    LOG_GENERAL(INFO, "Begin compression of " << dbname);
    auto dbptr = std::make_shared<LevelDB>(dbname);
    dbptr->compact();
    LOG_GENERAL(INFO, "Finished compression");
  } catch (std::exception& e) {
    std::cerr << "Unhandled Exception reached the top of main: " << e.what()
              << ", application will now exit" << std::endl;
    return ERROR_UNHANDLED_EXCEPTION;
  }

  return SUCCESS;
}
