#ifndef MGUARD_SUBSCRIBER_HPP
#define MGUARD_SUBSCRIBER_HPP

#include <PSync/consumer.hpp>

#include <ndn-cxx/util/logger.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/util/time.hpp>

#include <string>

using namespace ndn::time_literals;

namespace mguard {

struct SyncDataInfo
{
  ndn::Name prefix;
  uint64_t highSeq;
  uint64_t lowSeq;
};

typedef std::function<void(const std::vector<SyncDataInfo>& updates)> SyncUpdateCallback;

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
  Subscriber(const ndn::Name& syncPrefix, ndn::time::milliseconds syncInterestLifetime,
             std::unordered_set<ndn::Name>& eligibleStreams, const SyncUpdateCallback& syncUpdateCallback);

  void
  run();

  void
  stop();

  void
  subscribe(ndn::Name& streamName);
  
  void
  unsubscribe(const ndn::Name& topic);

  void
  receivedHelloData(const std::map<ndn::Name, uint64_t>& availStreams);

  void
  receivedSyncUpdates(const std::vector<psync::MissingDataInfo>& updates);

  void
  sendInterest();

private:
  ndn::Face m_face;

  ndn::Name m_syncPrefix;
  // available streams are the ones received from psync
  // and eligible streams are determined from the policy
  std::unordered_map<ndn::Name, uint64_t> m_availableStreams;
  std::unordered_set<ndn::Name> m_eligibleStreams;

  psync::Consumer m_consumer;
  SyncUpdateCallback m_syncUpdateCallback;
};

} //namespace subscriber
} //namespace mguard

#endif // MGUARD_SUBSCRIBER_HPP