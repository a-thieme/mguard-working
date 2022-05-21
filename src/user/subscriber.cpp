#include "subscriber.hpp"
#include "common.hpp"

#include <nac-abe/attribute-authority.hpp>

#include <boost/algorithm/string.hpp>

#include <iostream>

NDN_LOG_INIT(mguard.subscriber);

namespace mguard {
namespace subscriber {

Subscriber::Subscriber(const ndn::Name& consumerPrefix, const ndn::Name& syncPrefix,
                       const ndn::Name& controllerPrefix, const std::string& consumerCertPath,
                       const std::string& aaCertPath, ndn::time::milliseconds syncInterestLifetime,
                       const DataCallback& callback, const SubscriptionCallback& subCallback)
: m_scheduler(m_face.getIoService())
, m_consumerPrefix(consumerPrefix)
, m_syncPrefix(syncPrefix)
, m_controllerPrefix(controllerPrefix)

, m_abe_consumer(m_face, m_keyChain, *loadCert(consumerCertPath), *loadCert(aaCertPath))

, m_psync_consumer(m_syncPrefix, m_face,
                   std::bind(&Subscriber::receivedHelloData, this, _1),
                   std::bind(&Subscriber::receivedSyncUpdates, this, _1),
                   2, 0.001, 10_s, 4_s) // 2 = expected number of prefix to subscriber to, need to handle this differently later
                  // 10_s hello interset lifetime, 4_s sync interest life time
                  // for us, the subscription happens at the begnning so we dont need to send hello interest that often 
, m_ApplicationDataCallback(callback)
, m_subCallback(subCallback)
{
  NDN_LOG_DEBUG("Subscriber initialized");
  m_abe_consumer.obtainDecryptionKey();

  // get policy details from controller
  try {
    ndn::Name interestName = m_controllerPrefix;
    interestName.append(m_consumerPrefix);
    NDN_LOG_DEBUG("Getting policy detail data, send interest: " << interestName);
    expressInterest(interestName, true);
  }
  catch (const std::exception& e)
  {
    NDN_LOG_ERROR("error: " << e.what());
  }
  std::this_thread::sleep_for (std::chrono::seconds(3));
  // This starts the consumer side by sending a hello interest to the producer
  // When the producer responds with hello data, receivedHelloData is called
  // m_psync_consumer.sendHelloInterest();
  // std::this_thread::sleep_for (std::chrono::seconds(1));
}

bool
Subscriber::checkConvergence()
{
  int counter = 0;
  while (counter < 3) // wait for 6 seconds max, else return false
  {
    if(m_abe_consumer.readyForDecryption())
      return true;
    ++counter;
    std::this_thread::sleep_for (std::chrono::seconds(3));
  }
  return false;
}

void
Subscriber::run(bool runSync)
{
  try {
    NDN_LOG_INFO("Starting Face");

    if (runSync) {
      m_psync_consumer.sendHelloInterest();
      // sleep some time for sync to kick in
      NDN_LOG_DEBUG("sleeping 5 seconds for sync to converge");
      std::this_thread::sleep_for (std::chrono::seconds(5));
    }
    m_face.processEvents();
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

void
Subscriber::expressInterest(const ndn::Name& name, bool canBePrefix, bool mustBeFresh)
{
  NDN_LOG_INFO("Sending interest: "  << name);
  ndn::Interest interest(name);
  interest.setCanBePrefix(false);
  interest.setMustBeFresh(mustBeFresh); //set true if want data explicit from producer.
  //  interest.setInterestLifetime(160_ms);

  m_face.expressInterest(interest,
                         bind(&Subscriber::onData, this, _1, _2),
                         bind(&Subscriber::onTimeout, this, _1),
                         bind(&Subscriber::onTimeout, this, _1));
}

void
Subscriber::onData(const ndn::Interest& interest, const ndn::Data& data)
{
  NDN_LOG_INFO("Data received for: " << interest.getName());
  wireDecode(data.getContent());

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
    ++it->second;
  }
}

void
Subscriber::subscribe(ndn::Name streamName)
{
  // convert the streamName into manifest, because that's what is published by the sync
  streamName.append("manifest");
  auto it = m_availableStreams.find(streamName);
  if (it == m_availableStreams.end()) {
    NDN_LOG_INFO("Stream: " << streamName << " not available for subscription");
    // schedule a hello interest in next 5 seconds
    m_scheduler.schedule(5_s, [=] { m_psync_consumer.sendHelloInterest();});
    return;
  }
  NDN_LOG_INFO("Subscribing to: " << streamName);
  m_psync_consumer.addSubscription(streamName, it->second);
  m_psync_consumer.sendSyncInterest();
}

void
Subscriber::receivedHelloData(const std::map<ndn::Name, uint64_t>& availStreams)
{
  // store all the streams names and their latest seq number
  for (const auto& it: availStreams) {
    NDN_LOG_DEBUG (" stream name: " << it.first << " latest seqNum" << it.second);
    m_availableStreams[it.first] = it.second;
  }

  // subscribe to streams present in the subscription list
  for (auto stream : m_subscriptionList) {
    subscribe(stream);
  }
}

void
Subscriber::receivedSyncUpdates(const std::vector<psync::MissingDataInfo>& updates)
{
  for (const auto& update : updates) {

    auto lSeq = getLowSeqOfPrefix(update.prefix);
    auto sc = (lSeq == NOT_AVAILABLE) ? STARTING_SEQ_NUM : lSeq; // sc = sequence counter

    for (; sc <= update.highSeq; sc++) {
      // for manifest update, we need to express interest and fetch the manifest content
      NDN_LOG_INFO("Update: " << update.prefix << "/" << sc);
      auto manifestInterestName = update.prefix;
      manifestInterestName.appendNumber(sc);
      NDN_LOG_DEBUG("Request content for manifest: " << manifestInterestName);
      expressInterest(manifestInterestName, true);
    }
  }
}

void
Subscriber::wireDecode(const ndn::Block& wire)
{
  wire.parse();
  auto val = wire.elements_begin();
  if (val != wire.elements_end() && val->type() == mguard::tlv::mGuardController)
  {
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
  if (val != wire.elements_end() && val->type() == mguard::tlv::mGuardPublisher)
  {
    std::vector<ndn::Name> tempNameBuffer;
    NDN_LOG_DEBUG ("Received data from publisher");
    val->parse();
    for (auto it = val->elements_begin(); it != val->elements_end(); ++it) {
      if (it->type() == ndn::tlv::Name) {
        tempNameBuffer.emplace_back(*it);
      }
      else {
        NDN_THROW(ndn::tlv::Error("Expected Name element, but TLV has type " +
                                   ndn::to_string(it->type())));
      }
    }
    // we got all the data names for this manifest, now lets fetch the actual data
    for (const auto& dataName : tempNameBuffer)
    {
      if(!checkConvergence())
        NDN_THROW(Error("Public params or private key is absent, can't decrypt the data"));

      m_abe_consumer.consume(dataName.getPrefix(-1), bind(&Subscriber::abeOnData, this, _1),
                             bind(&Subscriber::abeOnError, this, _1));
      NDN_LOG_DEBUG("data names: " << dataName);
    }
  }
}

void
Subscriber::abeOnData(const ndn::Buffer& buffer)
{
  auto applicationData = std::string(buffer.begin(), buffer.end());
  NDN_LOG_DEBUG ("Received Data " << applicationData);
  m_ApplicationDataCallback({applicationData});
}
void
Subscriber::abeOnError(const std::string& errorMessage)
{
  NDN_LOG_DEBUG ("ABE failled to fetch and encrypt data");
}

} // subscriber
} // mguard
