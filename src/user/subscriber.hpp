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

#ifndef MGUARD_SUBSCRIBER_HPP
#define MGUARD_SUBSCRIBER_HPP

#include <PSync/consumer.hpp>
#include <nac-abe/attribute-authority.hpp>
#include <nac-abe/consumer.hpp>

#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validator-config.hpp>

#include <functional>
#include <string>
#include <chrono>
#include <thread>

using namespace ndn::time_literals;

const ndn::time::milliseconds SYNC_INTEREST_LIFETIME = 1600_ms;

namespace mguard {

struct ApplicationData
{
  ndn::Name dataName;
  std::string dataRows;
};

typedef std::function<void(const std::map<std::string, std::string>& updates)> DataCallback;
typedef std::function<void(const std::unordered_set<ndn::Name>& streams)> SubscriptionCallback;

namespace subscriber {
namespace tlv {
}

class Error : public std::runtime_error
{
public:
  using std::runtime_error::runtime_error;
};

class Subscriber
{
public:
  
  /*
  @brief mGuard subscriber, helps subscription/unsubscription to data streams and 
    receive data securly based on consumer's policy
  @param consumerPrefix The prefix of the consumer, also consumer's identity
  @param syncPrefix The prefix of the sync group
  @param controllerPrefix The prefix of mGuardController
  @param consumerCertPath The Path to consumer certificate
  @param aaCertPath The Path to attribute authority certificate, need to obtain out-of-band/bootstrapping? 
  @param syncInterestLifetime Lifetime of the sync interest, if not specified, default of 4_s will be used
  @param callback Callback to send application data to the consumer
  @param subCallback Callback to send available stream for subscription to the consumer
  */
  Subscriber(const ndn::Name& consumerPrefix, const ndn::Name& syncPrefix,
             const ndn::Name& controllerPrefix, const std::string& consumerCertPath,
             const std::string& aaCertPath, const DataCallback& callback,
             const SubscriptionCallback& subCallback,
             const ndn::time::microseconds syncInterestLifetime = SYNC_INTEREST_LIFETIME);

  void
  run();

  void
  stop();

  ~Subscriber() {
    m_face_thread.join();
  }

  /**
   * @brief Get the subscription list of the current user
     m_subscriptionList contains all the daa stream the consumer has subscribed to
  */
  std::vector<ndn::Name>&
  getSubscriptionList() {
    return m_subscriptionList;
  }

  /**
   * @brief This method adds a stream to the subscription list if not added already
   * @param name Data stream name
    @return 
  */
  void
  addToSubscriptionList(const ndn::Name& name) {
    auto it = std::find(m_subscriptionList.begin(), m_subscriptionList.end(), name);
    if (it != m_subscriptionList.end())
      m_subscriptionList.emplace_back();
  }

  /**
   * @brief This method returns highest recorded sequenc number of a manifest
   *  or Data stream (identified by preifx) that is already fetched by the consumer.
   *  If it was not recored (meaning the prefix wasn't received earlier via sync)
   *  it will return NOT_AVAILABLE (i.e. -1) 
   * 
   * @param prefix Manifest or Stream name received via Sync update
  */
  uint64_t
  getHighSeqFetchedOfPrefix(const ndn::Name& prefix) {
    auto it = m_prefixToLowSeq.find(prefix);
    return (it == m_prefixToLowSeq.end()) ? NOT_AVAILABLE : it->second;
  }

  /**
   * @brief This methods sets the highest sequence number of a prefix (i.e. manifest) or 
   *  data stream that is already received via sync updates. 
   * @param prefix Manifest or Data Stream name
   * @param seqNum highest sequence number fetched by the consumer
    @return 
  */
  void
  setHighSeqFetchedOfPrefix(const ndn::Name& prefix, uint64_t seqNum) {
    auto it = m_prefixToLowSeq.find(prefix);
    if (it == m_prefixToLowSeq.end()) // prefix doesn't exist in the map
      m_prefixToLowSeq.emplace(prefix, seqNum);
    else
      it->second = seqNum;
  }

  /**
   * @brief Set the subscription list for the current consumer
   * m_subscriptionList contains all the daa stream the consumer has subscribed to
   * @param subList A vector containing all the stream name that's been subscribed
   *  by the consumer
  */
  void
  setSubscriptionList(const std::vector<ndn::Name>& subList) {
    m_subscriptionList = subList;
  }

public:
  /**
   * @brief Subscribe to a Data stream or a Manifest
   * @param streamname The name of the stream to subscribe to
  */
  void
  subscribe(ndn::Name& streamName);
  
  /**
   * @brief Unsubscribe to a Data stream or a Manifest
   * @param streamname The name of the stream to un-subscribe to
  */
  void
  unsubscribe(ndn::Name& streamName);

  /**
   * @brief This method check if the decryption is already fetched by the consumer
   * It will internally call NAC-ABE's readyForDecryption() to get the information
   * @return bool True if available else false
  */
  bool
  checkConvergence();

private:
  
  void
  expressInterest(const ndn::Name& name, bool canBePrefix = false, bool mustBeFresh = false);

  /**
   * @brief This method will fetch the application data through NAC-ABE using 
   *  NAC-ABE consume(..) API. Callback abeOnData or abeOnError will be called after
   *  the async fetching.
   * @param name Application data name
   * 
  */
  void
  fetchABEData(const ndn::Name& name);

  /**
   * @brief Callback on expressInterest once the data is received
   *  The data can be from the mGuardController or mGuardPublisher
   * @param interest Interest that was sent to fetch the data
   * @param data Data received
    @return 
  */
  void
  onData(const ndn::Interest& interest, const ndn::Data& data);

  /**
   * @brief 
  */
  void
  onTimeout(const ndn::Interest& interest);

  /**
   * @brief Sync Callback after receiving hello data. 
   * @param availStreams Contains stream/manifest name as well as it 
   * latest sequence number
    @return 
  */
  void
  receivedHelloData(const std::map<ndn::Name, uint64_t>& availStreams);

  /**
   * @brief Sync Callback after receiving sync data.
   * @param updates Contains stream/manifest name as well as its latest
   * published sequence number
    @return 
  */
  void
  receivedSyncUpdates(const std::vector<psync::MissingDataInfo>& updates);
  
  void
  wireDecode(const ndn::Block& wire);

  // NAC-ABE callbacks
  void
  abeOnData(const ndn::Buffer& buffer, const ndn::Name& dataName);
  
  void
  abeOnError(const std::string& errorMessage, const ndn::Name& name);

private:
  ndn::Face m_face;
  ndn::security::KeyChain m_keyChain;
  ndn::Scheduler m_scheduler;
  std::thread m_face_thread;
  ndn::ValidatorConfig m_validator;

  ndn::Name m_consumerPrefix;
  ndn::Name m_syncPrefix;
  ndn::Name m_controllerPrefix;
  std::unordered_map<ndn::Name, uint64_t> m_prefixToLowSeq;
  std::vector<ndn::Name> m_subscriptionList;

  // available streams are the ones received from psync
  // and eligible streams are determined from the policy
  std::unordered_map<ndn::Name, uint64_t> m_availableStreams; // name, sequence number
  std::unordered_set<ndn::Name> m_eligibleStreams;
  std::map<ndn::Name, int> m_retransmissionCount;
  ndn::nacabe::Consumer m_abe_consumer;

  psync::Consumer m_psync_consumer;
  DataCallback m_ApplicationDataCallback;
  SubscriptionCallback m_subCallback;
};

} //namespace subscriber
} //namespace mguard

#endif // MGUARD_SUBSCRIBER_HPP