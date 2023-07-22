/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2021-2022,  The University of Memphis
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

#include "publisher.hpp"
#include "../common.hpp"

#include <boost/bind.hpp>

NDN_LOG_INIT(mguard.Publisher);

namespace mguard {

Publisher::Publisher(ndn::Face& face, ndn::security::KeyChain& keyChain,
                    const ndn::Name& producerPrefix,
                    const ndn::security::Certificate& producerCert,
                    const ndn::security::Certificate& attrAuthorityCertificate,
                    const std::vector<std::string>& streamsToPublish)
: m_face(face)
, m_keyChain(keyChain)
, m_scheduler(m_face.getIoService())
/*
  40 = expected number of entries also will be used as IBF size
  syncPrefix = <producer-prefix> /ndn/org/md2k/, userPrefix = /ndn/org/md2k/mguard....
  we are using producer's prefix as sync prefix, may need to change this in the future
*/
, m_partialProducer(m_face, m_keyChain, 40, producerPrefix,
                    "/ndn/org/md2k/mguard/dd40c/data_analysis/gps_episodes_and_semantic_location/MANIFEST")
, m_asyncRepoInserter(m_face.getIoService())
, m_producerPrefix(producerPrefix)
, m_producerCert(producerCert)
, m_authorityCert(attrAuthorityCertificate)
, m_abe_producer(m_face, m_keyChain, m_validator, m_producerCert, m_authorityCert)
{
  m_validator.load("certs/trust-schema.conf");
  auto certName = ndn::security::extractIdentityFromCertName(m_producerCert.getName());

  NDN_LOG_INFO("Setting interest filter on name: " << certName);
  m_certServeHandle = m_face.setInterestFilter(ndn::InterestFilter(certName).allowLoopback(false),
                        [this] (auto&&...) {
                          m_face.put(this->m_producerCert);
                        },
                        std::bind(&Publisher::onRegistrationSuccess, this, _1),
                        std::bind(&Publisher::onRegistrationFailed, this, _1));

  m_asyncRepoInserter.AsyncConnectToRepo(std::bind(&Publisher::connectHandler, this, _1));
  std::this_thread::sleep_for (std::chrono::seconds(1));
  NDN_LOG_DEBUG("Connecting to repo...");

  if (streamsToPublish.empty()) {
    NDN_LOG_DEBUG("Streams to publish (streamsToPublish) cannot be empty");
    NDN_THROW(Error("Streams to publish (streamsToPublish) cannot be empty"));
  }

  // --------------- in duscussion, only for testing----------
  // Discussion: we will add all the possible stream to the psync at the begnning.
  // This is for the current testing and experiment only, the design needs to be better
  // reason: consumer kicks in, finds that the stream is still not available (sequential processing)
  // of the stream during the experiment, and thus keeps sending hello interest (causes a lot of overhead)
  // second, if we send hello interest less frequently, the overall data retrival delay increases.
  
  for (auto& name: streamsToPublish)
    m_partialProducer.addUserNode(name);

  // if we want to start sync with specific sequence number, we can do the following
  // m_partialProducer.updateSeqNo(<preifx>, <seq-num>);

  // sleep to init kp-abe producer
  std::this_thread::sleep_for (std::chrono::seconds(1));
}

void
Publisher::onRegistrationSuccess(const ndn::Name& name)
{
  NDN_LOG_INFO("Successfully registered prefix: " << name);
}

void
Publisher::onRegistrationFailed(const ndn::Name& name)
{
  NDN_LOG_INFO("ERROR: Failed to register prefix " << name << " in local hub's daemon");
}

void
Publisher::connectHandler(const mguard::util::AsyncRepoError& err)
{
  if (!err)
    NDN_LOG_DEBUG("Connection successful");
  else
    NDN_LOG_DEBUG("Connection failled");
}

void
Publisher::writeHandler(const ndn::Data& data, const mguard::util::AsyncRepoError& err)
{
  if (!err)
    NDN_LOG_DEBUG(data.getName() << " inserted into the repo");
  else
    NDN_LOG_DEBUG("failed to insert: " << data.getName());
}

void
Publisher::doUpdate(ndn::Name namePrefix, uint64_t currSeqNum)
{
  m_partialProducer.publishName(namePrefix, currSeqNum+1);
  auto seqNo =  m_partialProducer.getSeqNo(namePrefix).value();
  std::cout << "sequence number: " << seqNo << std::endl;
  NDN_LOG_DEBUG("Publish sync update for the name/manifest: " << namePrefix << " sequence Number: " << seqNo);
}

mguard::util::Stream&
Publisher::getOrCreateStream(ndn::Name& streamName)
{
  auto itr = m_streams.find(streamName);
  if (itr != m_streams.end()) // already exist
    return itr->second;

  auto [it, success] = m_streams.emplace(streamName, streamName);
  return it->second;
}

void
Publisher::scheduledManifestForPublication(util::Stream& stream)
{
  auto& manifestName = stream.getManifestName();
  auto itr = m_scheduledIds.find(manifestName);
  NDN_LOG_DEBUG("Scheduling manifest: " << manifestName << " for publication");
  
  if (itr != m_scheduledIds.end()) {
    NDN_LOG_DEBUG("Manifest: " << manifestName << " was already scheduled, updating the schedule");
    itr->second.cancel();
    auto scheduleId = m_scheduler.schedule(MAX_UPDATE_WAIT_TIME, [&] {
                      doUpdate(manifestName, publishManifest(stream));
                      NDN_LOG_DEBUG("Updated manifest: " << manifestName << " via scheduling");
                    });
    itr->second = scheduleId;
  }
  else {
    auto scheduleId = m_scheduler.schedule(MAX_UPDATE_WAIT_TIME, [&] {
                      doUpdate(manifestName, publishManifest(stream));
                      NDN_LOG_DEBUG("Updated manifest: " << manifestName << " via scheduling");
                    });
    m_scheduledIds.emplace(manifestName, scheduleId);
  }
}

void
Publisher::publish(ndn::Name& dataName, std::string data, 
                   std::vector<std::string> attrList,
                   ndn::Name& streamName)
{
  NDN_LOG_DEBUG("Publishing data name: " << dataName << " data: " << data << " and size: " << data.size());

  std::shared_ptr<ndn::Data> enc_data, ckData;
  try {
    NDN_LOG_DEBUG("Encrypting data: " << dataName << " with attributes: " << vectorToString(attrList));
    // gives suffix except /ndn/org/md2k/.....
    // TODO::: we should handle this in a better way
    auto dataSufix = dataName.getSubName(3);
    NDN_LOG_TRACE("--------- data suffix: " << dataSufix);
    std::tie(enc_data, ckData) = m_abe_producer.produce(dataSufix, attrList,
                                    {reinterpret_cast<const uint8_t *>(data.c_str()), data.size()},
                                    ndn::security::signingWithSha256()
                                  );
  }
  catch(const std::exception& e) {
    NDN_LOG_ERROR("Encryption for the data: " << dataName << " failled");
    std::cerr << e.what() << '\n';
    return;  // need to throw from here?
  }

  //  encrypted data is created, store it in the buffer and publish it
  NDN_LOG_INFO("full name of the data: " << enc_data->getFullName() << " and size: " << enc_data->getContent().size());
  NDN_LOG_INFO("full name of the ckData: " << ckData->getFullName() << " and size: " << ckData->getContent().size());

  try {
    NDN_LOG_INFO("start repo insertion for name: " << enc_data->getName());

    // insert data and CK data into repo
    m_asyncRepoInserter.AsyncWriteDataToRepo(*ckData, std::bind(&Publisher::writeHandler, this, _1, _2));
    m_asyncRepoInserter.AsyncWriteDataToRepo(*enc_data, std::bind(&Publisher::writeHandler, this, _1, _2));
  }
  catch(const std::exception& e) {
      NDN_LOG_ERROR("data and cKdata insertion failed");
      std::cerr << e.what() << '\n';
  }

  if (!USE_MANIFEST) {
    // if manifest is not used, the dataName is directly published in the sync
    m_partialProducer.addUserNode(dataName);
    uint64_t currSeqNum =  m_partialProducer.getSeqNo(dataName).value();
    doUpdate(dataName, currSeqNum);
    return;
  }

  auto& stream = getOrCreateStream(streamName);

  NDN_LOG_DEBUG("Manifest name: " << stream.getManifestName());

  bool doPublishManifest = stream.updateManifestList(enc_data->getFullName());
  // manifest are publihsed to sync after receiving X (e.g. 10) number of application data or if
  // "t" time has passed after receiving the last application data.
  if (!doPublishManifest) {
    scheduledManifestForPublication(stream);
    return;
  }
  cancleIfManifestScheduledForPublication(stream.getName());
  // create manifest data packet, and insert it into the repo
  doUpdate(stream.getManifestName(), publishManifest(stream));
}

uint64_t
Publisher::publishManifest(util::Stream& stream)
{
  auto dataName = stream.getManifestName();
  m_partialProducer.addUserNode(dataName);

  uint64_t currSeqNum =  m_partialProducer.getSeqNo(dataName).value();

  /* For testing, randomizing sequence number
  if (currSeqNum == 0)
    currSeqNum = rand() % 1000;
  */
  dataName.appendNumber(currSeqNum + 1);
  auto manifestData = std::make_shared<ndn::Data>(dataName);
  
  m_temp = stream.getManifestList();
  manifestData->setContent(wireEncode());
  NDN_LOG_DEBUG ("Manifest name: " << dataName << " manifest data size: " << manifestData->getContent().size()
                 << " and seqNumber: " << currSeqNum + 1);
  
  m_keyChain.sign(*manifestData, ndn::security::signingByCertificate(m_producerCert));

  try {
      NDN_LOG_INFO("start repo insertion for name: " << manifestData->getName());
      m_asyncRepoInserter.AsyncWriteDataToRepo(*manifestData, std::bind(&Publisher::writeHandler, this, _1, _2));

      m_temp.clear(); // clear temp variable
      stream.resetManifestList(); // clear manifest list
      m_wire.reset(); // reset the wire for new content
  }
  catch(const std::exception& e) {
    NDN_LOG_ERROR("Failed to insert mainfest into the repo");
    std::cerr << e.what() << '\n';
  }
  return currSeqNum; // this is next sequence number
}

const ndn::Block&
Publisher::wireEncode() const
{
  if (m_wire.hasWire()) {
    m_wire.reset();
  }

  ndn::EncodingEstimator estimator;
  size_t estimatedSize = wireEncode(estimator);

  ndn::EncodingBuffer buffer(estimatedSize, 0);
  wireEncode(buffer);

  m_wire = buffer.block();
  return m_wire;
}

template <ndn::encoding::Tag TAG>
size_t
Publisher::wireEncode(ndn::EncodingImpl<TAG> &encoder) const
{
  size_t totalLength = 0;
  
  for (auto it = m_temp.rbegin(); it != m_temp.rend(); ++it) {
    NDN_LOG_DEBUG ("Encoding data name: " << *it);
    totalLength += it->wireEncode(encoder);
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(mguard::tlv::mGuardPublisher);
  
  return totalLength;
}
} //mguard