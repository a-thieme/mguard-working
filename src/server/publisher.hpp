/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2021-2023,  The University of Memphis
 *
 * This file is part of mGuard.
 * See AUTHORS.md for complete list of mGuard authors and contributors.
 *
 * mGuard is free software: you can redistribute it and/or modify it under the terms
 * of the GNU Lesser General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * mGuard is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * mGuard, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MGUARD_PUBLISHER_HPP
#define MGUARD_PUBLISHER_HPP

#include "file-processor.hpp"
#include "util/stream.hpp"
#include "util/async-repo-inserter.hpp"

#include <PSync/partial-producer.hpp>
#include <nac-abe/attribute-authority.hpp>
#include <nac-abe/cache-producer.hpp>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <unordered_map>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>

namespace mguard {

class Publisher
{
public:
  Publisher(ndn::Face& face, ndn::security::KeyChain& keyChain,
            const ndn::Name& producerPrefix,
            const ndn::security::Certificate& producerCert,
            const ndn::security::Certificate& attrAuthorityCertificate,
            const std::vector<std::string>& streamsToPublish);
  
  void
  onRegistrationSuccess(const ndn::Name& name);

  void
  onRegistrationFailed(const ndn::Name& name);


  void
  connectHandler(const mguard::util::AsyncRepoError& err);
  
  void 
  writeHandler(const ndn::Data& data, const mguard::util::AsyncRepoError& err);

  void
  doUpdate(ndn::Name namePrefix, uint64_t currSeqNum);

  void
  clearBuffer() 
  {
    m_ckBuffer.clear();
    m_dataBuffer.clear();
  }

  void
  publish(ndn::Name& dataName, std::string data, std::vector<std::string> attrList,
          ndn::Name& streamName);

  uint64_t
  publishManifest(util::Stream& stream);

  mguard::util::Stream&
  getOrCreateStream(ndn::Name& streamName);

  void
  scheduledManifestForPublication(util::Stream& stream);

  void
  cancleIfManifestScheduledForPublication(const ndn::Name& name)
  {
    auto itr = m_scheduledIds.find(name);
    if (itr != m_scheduledIds.end()) {
      itr->second.cancel();
    }
  }
  
  template<ndn::encoding::Tag TAG>
  size_t
  wireEncode(ndn::EncodingImpl<TAG>& block) const;

  const ndn::Block&
  wireEncode() const;
  
private:
  ndn::Face& m_face;
  ndn::security::KeyChain& m_keyChain;
  ndn::Scheduler m_scheduler;
  ndn::ScopedRegisteredPrefixHandle m_certServeHandle;

  std::map<ndn::Name, ndn::scheduler::ScopedEventId>m_scheduledIds;
  mutable ndn::Block m_wire;
  psync::PartialProducer m_partialProducer;
  util::AsyncRepoInserter m_asyncRepoInserter;

  std::vector<ndn::Name> m_temp;
  ndn::Name m_attrAuthorityPrefix;
  ndn::Name m_producerPrefix;
  ndn::security::Certificate m_producerCert;
  ndn::security::Certificate m_authorityCert;
  ndn::ValidatorConfig m_validator{m_face};
  ndn::nacabe::CacheProducer m_abe_producer;

  std::vector<ndn::Data> m_ckBuffer;
  std::vector<ndn::Data> m_dataBuffer;
  std::map<ndn::Name, mguard::util::Stream> m_streams;
};

} // mguard

#endif // MGUARD_PUBLISHER_HPP