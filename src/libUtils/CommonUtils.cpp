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

#include <malloc.h>
#include <chrono>
#include <mutex>
#include <random>

#include "libUtils/CommonUtils.h"
#include "libUtils/Logger.h"

using namespace std;

void CommonUtils ::ReleaseSTLMemoryCache() {
  // LOG_MARKER();
  static mutex relMemoryCacheMutex;
  if (relMemoryCacheMutex.try_lock()) {
    malloc_trim(0);
    relMemoryCacheMutex.unlock();
  }
}
uint64_t CommonUtils::GenerateRandomNumber(const uint64_t& low,
                                           const uint64_t& high) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dis(low, high);
  return dis(gen);
}