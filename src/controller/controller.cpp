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

#include "controller.hpp"

using namespace ndn;

namespace mguard {
namespace controller {

NDN_LOG_INIT(mguard.Controller);

Controller::Controller(const ndn::Name& controllerPrefix,
                       const std::string& controllerCertPath,
                       const std::vector<std::string>& policyList,
                       const ndn::Name& aaPrefix, const std::string& aaCertPath,
                       const std::map<ndn::Name, std::string>& requestersCertPath,
                       const std::string& availableStreamsFilePath)
: m_controllerPrefix(controllerPrefix)
, m_controllerCert(*loadCert(controllerCertPath))
, m_aaPrefix(aaPrefix)
, m_requestersCertPath(requestersCertPath)
, m_policyParser(availableStreamsFilePath)
, m_attrAuthority(*loadCert(aaCertPath), m_face, m_keyChain)
{
  NDN_LOG_DEBUG("Controller certificate: " << m_controllerCert);
  
  for(auto& policy : policyList) {
    NDN_LOG_INFO("Policy path: " << policy);
    processPolicy(policy);
  }

  for(auto& it : m_policyMap)
    NDN_LOG_TRACE("Data consumer: " << it.first << " ABE policy: " << it.second.abePolicy);

  auto certName = ndn::security::extractIdentityFromCertName(m_controllerCert.getName());

  NDN_LOG_INFO("Setting interest filter on name: " << certName);
  m_face.setInterestFilter(ndn::InterestFilter(certName).allowLoopback(false),
                        [this] (auto&&...) {
                          m_face.put(this->m_controllerCert);
                        },
                        std::bind(&Controller::onRegistrationSuccess, this, _1),
                        std::bind(&Controller::onRegistrationFailed, this, _1));
  auto aaCert = *loadCert(aaCertPath);
  auto aaName = ndn::security::extractIdentityFromCertName(aaCert.getName());
  NDN_LOG_INFO("Setting interest filter on name: " << aaName);
  m_face.setInterestFilter(ndn::InterestFilter(aaName).allowLoopback(false),
                           [aaCert, this](auto&&...) {
      m_face.put(aaCert);
  },
    std::bind(&Controller::onRegistrationSuccess, this, _1),
     std::bind(&Controller::onRegistrationFailed, this, _1)
  );
  auto policyName = m_controllerPrefix;
  setInterestFilter(policyName.append("POLICYDATA"));
//
//    for (const auto &item: m_requestersCertPath) {
//      auto certPath = item.second;
//      auto cert = *loadCert(certPath);
//      auto id = m_keyChain.getPib().getIdentity(cert.getIdentity());
//      auto key = id.getKey(cert.getKeyName());
//      m_keyChain.addCertificate(key, cert);
//    }
}

void
Controller::run()
{
  try {
    m_face.processEvents();
  }
  catch (const std::exception& ex)
  {
    NDN_LOG_ERROR("Face error: " << ex.what());
    NDN_THROW(Error(ex.what()));
  }
}

void
Controller::processPolicy(const std::string& policyPath)
{
  auto policyDetail = m_policyParser.parsePolicy(policyPath);
  NDN_LOG_DEBUG("from policy info: " << policyDetail.abePolicy);

  // TODO: modify parser to store streams as ndn Name not the strings
  // in doing so we don't need the following conversion
  std::list <ndn::Name> tempStreams;
  for (const std::string& name : policyDetail.streams)
  {
    NDN_LOG_TRACE("Streams got from parser: " << name);
    tempStreams.push_back(name);
  }

  for (const std::string& requester : policyDetail.requesters) {
    NDN_LOG_DEBUG("Getting key and storing policy details for user: " << requester);

    try
    {
      auto path = getRequesterCertPath(requester);
      if (path.empty()) {
        NDN_LOG_DEBUG("Policy path does't exist: ");
        continue;

      }

      // auto requesterCert = m_keyChain.getPib().getIdentity(requester).getDefaultKey().getDefaultCertificate();
      NDN_LOG_DEBUG ("ABE policy for policy id: " << policyDetail.policyIdentifier << ": " << policyDetail.abePolicy);
      m_attrAuthority.addNewPolicy(*loadCert(path), policyDetail.abePolicy);
      policyDetails policyD = {policyDetail.policyIdentifier, tempStreams, policyDetail.abePolicy};
      m_policyMap.insert(std::pair <ndn::Name, policyDetails> (requester, policyD));
    }
    catch (std::exception& ex)
    {
      NDN_LOG_ERROR(ex.what());
      NDN_LOG_DEBUG("Error getting the cert, requester cert might be missing");
    }
  }
}

// /data/receive  ---- interest on this prefix from external application, data generator. 
void
Controller::setInterestFilter(const ndn::Name& name, const bool loopback)
{
  NDN_LOG_INFO("Setting interest filter on: " << name);
  m_face.setInterestFilter(ndn::InterestFilter(name).allowLoopback(false),
                           std::bind(&Controller::processInterest, this, _1, _2),
                           std::bind(&Controller::onRegistrationSuccess, this, _1),
                           std::bind(&Controller::onRegistrationFailed, this, _1));
}

void
Controller::processInterest(const ndn::Name& name, const ndn::Interest& interest)
{
  NDN_LOG_INFO("Interest received: " << interest.getName() << " name: " << name);
  // TODO: consumer will sent a signed interest, name will be extracted from identity 
  // extract subscriber name from the interest
  auto subscriberName = interest.getName().getSubName(5); // need to fix tis
  NDN_LOG_INFO("Consumer name: " << subscriberName);
  sendData(interest.getName());
}

void
Controller::sendData(const ndn::Name& name)
{
  auto subscriberName = name.getSubName(6);

  ndn::Data replyData(name);
  // replyData.setFreshnessPeriod(5_s);

  auto it = m_policyMap.find(subscriberName);
  if (it == m_policyMap.end()) {
    NDN_LOG_INFO("Key for subscriber: " << subscriberName << " not found " << "sending NACK");
    sendApplicationNack(name);
    return;
  }
  m_temp_policyDetail = it->second;
  replyData.setContent(wireEncode());
  m_keyChain.sign(replyData, signingByCertificate(m_controllerCert));
  m_face.put(replyData);
  NDN_LOG_DEBUG("Data sent for :" << name);
}

void
Controller::onRegistrationSuccess(const ndn::Name& name)
{
  NDN_LOG_INFO("Successfully registered prefix: " << name);
}

void
Controller::onRegistrationFailed(const ndn::Name& name)
{
  NDN_LOG_INFO("ERROR: Failed to register prefix " << name << " in local hub's daemon");
}

void
Controller::sendApplicationNack(const ndn::Name& name)
{
  NDN_LOG_INFO("Sending application nack");
  ndn::Name dataName(name);
  ndn::Data data(dataName);
  data.setContentType(ndn::tlv::ContentType_Nack);

  m_keyChain.sign(data, signingByCertificate(m_controllerCert));
  m_face.put(data);
}

const ndn::Block&
Controller::wireEncode()
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
Controller::wireEncode(ndn::EncodingImpl<TAG> &encoder)
{
  size_t totalLength = 0;
  auto& accessibleStreams = m_temp_policyDetail.streams;

  for (auto it = accessibleStreams.rbegin(); it != accessibleStreams.rend(); ++it) {
    NDN_LOG_DEBUG (" Encoding stream name: " << *it);
    totalLength += it->wireEncode(encoder);
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(mguard::tlv::mGuardController);

  return totalLength;
}

} // namespace controller
} // namespace mguard
