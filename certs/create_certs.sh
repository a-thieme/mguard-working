#!/bin/bash

server_certs() {
 echo "Installing server certs (producer, controller, and attribute authority)"
 ndnsec key-gen -t r /ndn/org/md2k
 ndnsec key-gen -t r /ndn/org/md2k/mguard/controller
 ndnsec key-gen -t r /ndn/org/md2k/mguard/aa

 ndnsec sign-req /ndn/org/md2k/mguard/controller > controller.ndncsr
 ndnsec sign-req /ndn/org/md2k/mguard/aa > aa.ndncsr

 ndnsec cert-gen -s /ndn/org/md2k -i /ndn/org/md2k aa.ndncsr > aa.cert
# ndnsec cert-install aa.cert
 ndnsec cert-gen -s /ndn/org/md2k -i /ndn/org/md2k controller.ndncsr > controller.cert
# ndnsec cert-install controller.cert

 ndnsec cert-dump -i /ndn/org/md2k > producer.cert
 ndnsec cert-dump -i /ndn/org/md2k > md2k-trust-anchor.ndncert
}

consumer_cert() {
  echo "Creating and installing consumer certificate"
  ndnsec key-gen -t r /ndn/org/md2k/local
  ndnsec sign-req /ndn/org/md2k/local > local.ndncsr
  ndnsec cert-gen -s /ndn/org/md2k -i /ndn/org/md2k local.ndncsr > local.cert
#  ndnsec cert-install local.cert
}

if [ "$1" == "-a" ]; then
  server_certs
  sleep 1
  consumer_cert
  exit
fi

server_certs


