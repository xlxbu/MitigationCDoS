
/* This is an ns-3 simulation to demonstrate the mitigation of cascading DoS attacks on Wi-Fi networks. 
 * This simulation shows that a cascading DoS attack can be prevented by reducing the packet length.
 *   
 * More simulation results can be found in paper
 * Liangxiao Xin, and David Starobinski, "Mitigation of Cascading Denial of Service Attacks on Wi-Fi Networks," 
 * IEEE CNS 2018, Beijing, China, June 2018
 *
 * Authors: Liangxiao Xin <xlx@bu.edu>
 *
 * This code is modified based on the example wifi-hidden-terminal.cc in ns-3.
*/

/* Office building model:
 *
 *  ^  -------------------------------------------------------------------
 *  |  |     |     |     |     |     |     |     |     |     |     |     |
 *  6m |node |<----|node |     |node |<----|node |     |node |<----|node |
 *  |  | 5   |     | 4   |     | 3   |     | 2   |     | 1   |     | 0   |
 *  v  -------------------------------------------------------------------
 *     <-4m->
 *
 * Results:
 * When nodes 0, 2, 4 transmit 1500 bytes UDP packets, the cascading DoS attack is feasible.
 * When nodes 0, 2, 4 transmit 200 bytes UDP packets, the attack is unfeasible and the network gains the highest saturation throughput.
 *
 * Note that we also need to set the short slot time in wifi-mac.cc
 * 
 */
#include "ns3/core-module.h"
#include "ns3/propagation-module.h"
#include "ns3/network-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/wifi-module.h"
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/buildings-helper.h"
#include "ns3/hybrid-buildings-propagation-loss-model.h"
#include "ns3/constant-position-mobility-model.h"

#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sys/stat.h>

using namespace ns3;


// start a single experiment 
void experiment (bool enableCtsRts, uint16_t NumofNode, uint16_t DurationofSimulation, double FirstNodeLoad, double RestNodeLoad, uint16_t PktLength){
  // 0. Enable or disable CTS/RTS
  UintegerValue ctsThr = (enableCtsRts ? UintegerValue (100) : UintegerValue (10000000));
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", ctsThr);
  Config::SetDefault ("ns3::WifiNetDevice::Mtu", UintegerValue(2296));
  /**Static ARP setup**/
  Config::SetDefault ("ns3::ArpCache::DeadTimeout", TimeValue (Seconds (0)));
  Config::SetDefault ("ns3::ArpCache::AliveTimeout", TimeValue (Seconds (120000)));

  // 1. Create nodes 
  NodeContainer nodes;
  nodes.Create (NumofNode);

  // 2. Create network topology using  building model
  // Create a one layer office building with 11 rooms.
  Ptr<Building> building1 = CreateObject<Building> ();
  building1->SetBoundaries (Box (0, 44, -3, 3, 0, 3));
  building1->SetBuildingType (Building::Office);
  building1->SetExtWallsType (Building::ConcreteWithWindows);
  building1->SetNRoomsX(11);
  building1->SetNRoomsY(1);
  building1->SetNFloors(1);

  // Place the nodes in the building
  Ptr<HybridBuildingsPropagationLossModel> propagationLossModel = CreateObject<HybridBuildingsPropagationLossModel> ();
  propagationLossModel->SetAttribute ("Frequency", DoubleValue (2.4e+09));
  propagationLossModel->SetAttribute ("InternalWallLoss", DoubleValue (12));
  for (size_t i = 0; i < NumofNode; ++i){
    Ptr<ConstantPositionMobilityModel> pos = CreateObject<ConstantPositionMobilityModel> ();
    nodes.Get (i)->AggregateObject (pos);
    pos->SetPosition(Vector (43.5-8*i, 0, 1));
    pos->AggregateObject (CreateObject<MobilityBuildingInfo> ());
    BuildingsHelper::MakeConsistent (pos);
  }

  // 3.Create & setup wifi channel
  Ptr<YansWifiChannel> wifiChannel = CreateObject <YansWifiChannel> ();
  wifiChannel->SetPropagationLossModel (propagationLossModel);
  wifiChannel->SetPropagationDelayModel (CreateObject <ConstantSpeedPropagationDelayModel> ());

  // 4. Install wireless devices
  /*constant rate wifi manager*/
  WifiHelper wifi;
  wifi.SetStandard (WIFI_PHY_STANDARD_80211g);
  wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager", 
                                "DataMode",StringValue ("ErpOfdmRate6Mbps"), 
                                "ControlMode", StringValue("DsssRate1Mbps"),
                                "FragmentationThreshold",UintegerValue(2300),
                                "MaxSlrc", UintegerValue(7));
  YansWifiPhyHelper wifiPhy =  YansWifiPhyHelper::Default ();
  wifiPhy.SetChannel (wifiChannel);
	
  NqosWifiMacHelper wifiMac = NqosWifiMacHelper::Default ();
  wifiMac.SetType ("ns3::AdhocWifiMac"); // use ad-hoc MAC
  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, nodes);	

  // 5. Install IP stack & assign IP addresses
  InternetStackHelper internet;
  internet.Install (nodes);
  Ipv4AddressHelper ipv4;
  ipv4.SetBase ("10.0.0.0", "255.0.0.0");
  ipv4.Assign (devices);

  // 6. Install applications: the UDP packets are generated by Poisson traffic
  ApplicationContainer cbrApps;
  uint16_t cbrPort = 12345;
  std::vector<OnOffHelper*> onoffhelpers;
  std::vector<PacketSinkHelper*> sinks;
  for (size_t i = 0; i < (NumofNode/2); ++i){
    //set nodes as senders
    std::stringstream ipv4address;
    std::stringstream offtime_first;
    std::stringstream offtime_rest;
    ipv4address << "10.0.0." << (i*2+2);
    OnOffHelper *onoffhelper = new OnOffHelper("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address (ipv4address.str().c_str()), cbrPort+i));
    onoffhelper->SetAttribute ("PacketSize", UintegerValue (PktLength));
    if ( i == (uint16_t)(NumofNode/2-1) ){
      if (FirstNodeLoad == 1){
        onoffhelper->SetAttribute ("OnTime",  StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
        onoffhelper->SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
      }else if (FirstNodeLoad == 0){
        onoffhelper->SetAttribute ("OnTime",  StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
        onoffhelper->SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));			
      }else {
        std::stringstream ontime_first;
        double pkt_time_first = (double)1/6000000 * PktLength*8;
        ontime_first << "ns3::ConstantRandomVariable[Constant=" << pkt_time_first << "]";
        onoffhelper->SetAttribute ("OnTime",  StringValue (ontime_first.str()));
        offtime_first << "ns3::ExponentialRandomVariable[Mean=" << 1/(FirstNodeLoad*(1/pkt_time_first))-pkt_time_first << "]";
        onoffhelper->SetAttribute ("OffTime", StringValue (offtime_first.str()));
      }
      onoffhelper->SetAttribute ("DataRate", StringValue ("6000000bps"));
      onoffhelper->SetAttribute ("StartTime", TimeValue (Seconds (53)));
      onoffhelper->SetAttribute ("StopTime", TimeValue (Seconds (153)));
    } else {
      std::stringstream ontime_rest;
      double pkt_time_rest = (double)1/6000000 * PktLength*8;
      ontime_rest << "ns3::ConstantRandomVariable[Constant=" << pkt_time_rest << "]";
      onoffhelper->SetAttribute ("OnTime",  StringValue (ontime_rest.str()));
      offtime_rest << "ns3::ExponentialRandomVariable[Mean=" << 1/(RestNodeLoad*(1/pkt_time_rest))-pkt_time_rest << "]";
      onoffhelper->SetAttribute ("OffTime", StringValue (offtime_rest.str()));
      onoffhelper->SetAttribute ("DataRate", StringValue ("6000000bps"));
      onoffhelper->SetAttribute ("StartTime", TimeValue (Seconds (3.100+i*0.01)));
    }
    cbrApps.Add (onoffhelper->Install (nodes.Get (i*2)));
    onoffhelpers.push_back(onoffhelper);

    //set nodes as receivers
    PacketSinkHelper *sink = new PacketSinkHelper("ns3::UdpSocketFactory",Address(InetSocketAddress (Ipv4Address::GetAny (), cbrPort+i)));
    cbrApps.Add (sink->Install (nodes.Get(i*2+1)));
  }
 
  /** \internal
    * We also use separate UDP applications that will send a single
    * packet before the CBR flows start.
    * This is a workaround for the lack of perfect ARP, see \bugid{187}
  */

  std::vector<UdpEchoClientHelper*> echoClientHelpers;
  uint16_t  echoPort = 9;
  ApplicationContainer pingApps;
  // again using different start times to workaround Bug 388 and Bug 912
  for (size_t i = 0; i < (NumofNode/2); ++i){
    std::stringstream ipv4address;
    ipv4address << "10.0.0." << (i*2+2);
    UdpEchoClientHelper *echoClientHelper = new UdpEchoClientHelper(Ipv4Address(ipv4address.str().c_str()), echoPort);
    echoClientHelper->SetAttribute ("MaxPackets", UintegerValue (1));
    echoClientHelper->SetAttribute ("Interval", TimeValue (Seconds (100000.0)));
    echoClientHelper->SetAttribute ("PacketSize", UintegerValue (10));		
    echoClientHelper->SetAttribute ("StartTime", TimeValue (Seconds (0.001+i/1000)));
    pingApps.Add (echoClientHelper->Install (nodes.Get (i*2)));
    echoClientHelpers.push_back(echoClientHelper);
  }

  // 7. Install AthstatsHelper to record the data.
  mkdir("CDoS-6Mbps-adhoc-UDP-building",S_IRWXU | S_IRWXG | S_IRWXO);
  char pathname [50];
  std::stringstream filename;
  std::stringstream foldername;
  sprintf (pathname, "./CDoS-6Mbps-adhoc-UDP-building/u_0=%1.2frho=%.2fT=%d",FirstNodeLoad, RestNodeLoad, PktLength);
  foldername << pathname;
  filename << pathname << "/nodes";
  mkdir(foldername.str().c_str(),S_IRWXU | S_IRWXG | S_IRWXO);
  AthstatsHelper athstats;
  athstats.EnableAthstats (filename.str().c_str(), devices);

  // 8. Run simulation for 10 seconds
  Simulator::Stop (Seconds (DurationofSimulation));
  Simulator::Run ();

  // 9. Cleanup
  Simulator::Destroy ();
}

int main (int argc, char **argv){
  RngSeedManager::SetSeed(1);
  uint16_t numofnode = 6;
  uint16_t durationofsimulation = 203;
  double firstnodeload = 1;
  double restnodeload = 0.14;
  experiment (false, numofnode, durationofsimulation, firstnodeload, restnodeload, 200);
  experiment (false, numofnode, durationofsimulation, firstnodeload, restnodeload, 1500);
  return 0;
}
