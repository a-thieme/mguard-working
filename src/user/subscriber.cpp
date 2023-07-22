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

#include "subscriber.hpp"
#include "../common.hpp"

#include <nac-abe/attribute-authority.hpp>

#include <boost/algorithm/string.hpp>

#include <iostream>
#include <vector>
#include <algorithm>

NDN_LOG_INIT(mguard.subscriber);

namespace mguard {
namespace subscriber {

Subscriber::Subscriber(const ndn::Name& consumerPrefix, const ndn::Name& syncPrefix,
                       const ndn::Name& controllerPrefix, const std::string& consumerCertPath,
                       const std::string& aaCertPath,
                       const DataCallback& callback,
                       const SubscriptionCallback& subCallback,
                       const ndn::time::microseconds syncInterestLifetime)
: m_scheduler(m_face.getIoService())
, m_validator(m_face)
, m_consumerPrefix(consumerPrefix)
, m_syncPrefix(syncPrefix)
, m_controllerPrefix(controllerPrefix)

, m_abe_consumer(m_face, m_keyChain, m_validator, *loadCert(consumerCertPath), *loadCert(aaCertPath))

, m_psync_consumer(m_syncPrefix, m_face,
                   std::bind(&Subscriber::receivedHelloData, this, _1),
                   std::bind(&Subscriber::receivedSyncUpdates, this, _1),
                   3, 0.001, 1_s, SYNC_INTEREST_LIFETIME) 
                   /* 3 = expected number of prefix to subscriber to, need to handle this differently later
                      1_s hello interset lifetime, SYNC_INTEREST_LIFETIME = 1600_ms sync interest life time */
, m_ApplicationDataCallback(callback)
, m_subCallback(subCallback)
{
  m_psync_consumer.sendHelloInterest();
  m_validator.load("certs/trust-schema.conf");
  // loadCert("certs/producer.cert"); // need this ?? 
  
  /*
    In this constructor (code below), first, we get the consumer's decryption key by calling
    obtainedDecryptionKey(). Calling this method from here (the application) has a few problems.
    First, this method should be called internally by NAC-ABE. I'm not sure why it was exposed
    to the consumer by the NAC-ABE library. Second, it doesn't provide a success/failure callback,
    so the caller won't have any idea if the key was fetched successfully or not. Because of these
    issues, we schedule readyForDecryption() to check if the public params and decryption key have
    been successfully fetched by NAC-ABE after 2 seconds, and then we fetch policy details from
    the controller after an additional 2 seconds.
  */

  NDN_LOG_DEBUG("Subscriber initialized, fetching decryption key");
  m_abe_consumer.obtainDecryptionKey();

  m_scheduler.schedule(2_s, [=] {
    NDN_LOG_DEBUG("Check to see if the key is fetched");
    if (!m_abe_consumer.readyForDecryption()){
      NDN_LOG_ERROR("error: Failed to fetch decryption, exiting consumer.....");
      exit(-1);
    }
  });

  // get policy details from controller
  try {
    ndn::Name interestName = m_controllerPrefix;
    interestName.append("POLICYDATA");
    interestName.append(m_consumerPrefix);
    // schedule policy interest after 2 second, cushion to obtain the decryption key
    m_scheduler.schedule(4_s, [=] { 
      NDN_LOG_DEBUG("Getting policy detail data, send interest: " << interestName);
      expressInterest(interestName, true);
    });
  }
  catch (const std::exception& e) {
    NDN_LOG_ERROR("error: " << e.what());
  }
}

void
Subscriber::run()
{
  try {
    NDN_LOG_INFO("Starting Face");
    m_face_thread = std::thread([this] { m_face.processEvents(); });
  }
  catch (const std::exception& ex)
  {
    NDN_LOG_ERROR("Face error: " << ex.what());
    NDN_THROW(Error(ex.what()));
  }
}

void
Subscriber::stop()
{
  NDN_LOG_DEBUG("Shutting down face: ");
  m_face.shutdown();
}

bool
Subscriber::checkConvergence()
{
  int counter = 0;
  while (counter < 3) // wait for 6 seconds max, else return false
  {
    std::this_thread::sleep_for (std::chrono::seconds(2));
    if(m_abe_consumer.readyForDecryption())
      return true;

    ++counter;
  }
  return false;
}

void
Subscriber::expressInterest(const ndn::Name& name, bool canBePrefix, bool mustBeFresh)
{
  NDN_LOG_INFO("Sending interest: "  << name);
  ndn::Interest interest(name);
  interest.setCanBePrefix(false);
  interest.setMustBeFresh(mustBeFresh);
  m_face.expressInterest(interest,
                         bind(&Subscriber::onData, this, _1, _2),
                         bind(&Subscriber::onTimeout, this, _1),
                         bind(&Subscriber::onTimeout, this, _1));
}

void
Subscriber::onData(const ndn::Interest& interest, const ndn::Data& data)
{
  NDN_LOG_INFO("Data received for: " << interest.getName());
  /* With validation */
  m_validator.validate(data,
    [=] (const ndn::Data& data) {
      wireDecode(data.getContent());
    },
    [] (const ndn::Data&, const ndn::security::ValidationError& error) {
      std::cerr << "Cannot validate retrieved data: " << error << std::endl;
  });
  // wireDecode(data.getContent());
}

void
Subscriber::onTimeout(const ndn::Interest& interest)
{
  // we will retransmit 3 times if an interest times out
  auto interestName = interest.getName();
  NDN_LOG_INFO("Interest: " << interestName << " timed out ");
  // one time re-transmission
  auto it = m_retransmissionCount.find(interest.getName());

  if (it == m_retransmissionCount.end()) {
    NDN_LOG_INFO("Re-transmitting interest: " << interest.getName() << " retransmission count: " << 1);
    m_retransmissionCount.emplace(interestName, 1); // will
    expressInterest(interestName);
    return;
  }
  if (it->second <= 3) {
    expressInterest(interestName);
    NDN_LOG_INFO("Re-transmitting interest: " << interest.getName() << " retransmission count: " << it->second);
    it->second = it->second + 1;
  }
  m_retransmissionCount.erase(it);
}

void
Subscriber::subscribe(ndn::Name& streamName)
{
  // convert the streamName into manifest, because that's what is published by the sync
  streamName.append("MANIFEST");
  auto it = m_availableStreams.find(streamName);
  if (it == m_availableStreams.end()) {
    NDN_LOG_INFO("Stream: " << streamName << " not available for subscription");
    // schedule a hello interest in next 200 milliseconds
    m_scheduler.schedule(200_ms, [=] { m_psync_consumer.sendHelloInterest();});
    return;
  }
  NDN_LOG_INFO("Sending subscription of " << streamName << " to sync");
  m_psync_consumer.addSubscription(streamName, it->second);
  // m_psync_consumer.sendSyncInterest(); // surprise why psync can't do this internally ??

  // add to subscription list if not added earlier
  addToSubscriptionList(streamName);
}

void
Subscriber::unsubscribe(ndn::Name& streamName)
{
  if (std::find(m_subscriptionList.begin(),
                m_subscriptionList.end(),
                streamName) == m_subscriptionList.end()){

    NDN_LOG_INFO("Stream: " << streamName << " not available for unsubscription");
  }
  
  m_subscriptionList.erase(std::remove(m_subscriptionList.begin(), 
                                       m_subscriptionList.end(), 
                                       streamName), m_subscriptionList.end());

  NDN_LOG_INFO("Unsubscribing to: " << streamName);
  streamName.append("MANIFEST"); // sync uses streamName + manifest
  m_psync_consumer.removeSubscription(streamName);
}

void
Subscriber::receivedHelloData(const std::map<ndn::Name, uint64_t>& availStreams)
{
  // store all the streams names and their latest seq number
  for (const auto& it: availStreams) {
    NDN_LOG_DEBUG (" stream name: " << it.first << " latest seqNum" << it.second);
    m_availableStreams[it.first] = it.second;

    // setHighSeqFetchedOfPrefix(it.first, it.second);
  }

  // subscribe to streams present in the subscription list
  for (auto stream : m_subscriptionList) { subscribe(stream); }

  m_psync_consumer.sendSyncInterest();
}

void
Subscriber::fetchABEData(const ndn::Name& name)
{
  NDN_LOG_DEBUG("Fetching data using NAC-ABE for name: " << name);
  m_abe_consumer.consume(name, bind(&Subscriber::abeOnData, this, _1, name),
                         bind(&Subscriber::abeOnError, this, _1, name));
}

void
Subscriber::receivedSyncUpdates(const std::vector<psync::MissingDataInfo>& updates)
{
  for (const auto& update : updates) {
    auto lSeq = getHighSeqFetchedOfPrefix(update.prefix);
    auto sc = (lSeq == NOT_AVAILABLE) ? STARTING_SEQ_NUM : lSeq; // sc = sequence counter

    for (; sc <= update.highSeq; sc++) {
      /* for each update (can be manifest or application prefix), we need to express 
      interest and fetch the respective content */
      NDN_LOG_INFO("Update: " << update.prefix << "/" << sc);
      auto interestName = update.prefix;
      
      interestName.appendNumber(sc);
      NDN_LOG_DEBUG("Request content for prefix: " << interestName);
      
      // check if this prefix is for MANIFEST or not
      if ((update.prefix).toUri().find("MANIFEST") != std::string::npos) {
        expressInterest(interestName, true);
      } else {
        fetchABEData(interestName);
      }
    }
    // update lowSequnece number, set it to current high
    setHighSeqFetchedOfPrefix(update.prefix, update.highSeq+1);
  }
}

void
Subscriber::wireDecode(const ndn::Block& wire)
{
  wire.parse();
  auto val = wire.elements_begin();
  if (val != wire.elements_end() && val->type() == mguard::tlv::mGuardController) {
    NDN_LOG_DEBUG ("Received data from controller");
    m_eligibleStreams.clear();
    val->parse();
    for (auto it = val->elements_begin(); it != val->elements_end(); ++it) {
      if (it->type() == ndn::tlv::Name) {
        m_eligibleStreams.emplace(*it);
      }
      else {
        NDN_THROW(ndn::tlv::Error("Expected Name element, but TLV has type " +
                                   ndn::to_string(it->type())));
      }
    }
    m_subCallback({m_eligibleStreams});
  }

  if (val != wire.elements_end() && val->type() == mguard::tlv::mGuardPublisher) {
    // If its matches mGuardPublisher tlv, it will be the manifest data because
    // publisher only creates manifest packets
    NDN_LOG_DEBUG ("Received data from publisher");
    val->parse();
    for (auto it = val->elements_begin(); it != val->elements_end(); ++it) {
      if (it->type() == ndn::tlv::Name) {
        ndn::Name dataName(*it);
        NDN_LOG_DEBUG("Fetch data: " << dataName);
        fetchABEData(dataName.getPrefix(-1));
      }
      else {
        NDN_THROW(ndn::tlv::Error("Expected Name element, but TLV has type " +
                                   ndn::to_string(it->type())));
      }
    }
  }
}

void
Subscriber::abeOnData(const ndn::Buffer& buffer, const ndn::Name& dataName)
{
  auto applicationData = std::string(buffer.begin(), buffer.end());
  NDN_LOG_DEBUG ("Received data for name: " << dataName);
  NDN_LOG_DEBUG ("Data: " << applicationData);
  std::map<std::string, std::string> temp;
  temp.insert({dataName.toUri(), applicationData});
  m_ApplicationDataCallback(temp);
}

void
Subscriber::abeOnError(const std::string& errorMessage, const ndn::Name& name)
{
  NDN_LOG_DEBUG ("ABE failled to fetch and encrypt data for name: " << name);
}

} // subscriber
} // mguard