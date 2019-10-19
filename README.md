# Packet Manipulator

Some time ago I tried to search for a nice wireshark like app for android, and everything I could find either 
didn't work, or wasn't what I was looking for (for example there are some great packet capture applications that use the android vpn
feature to capture network activity of other apps, but I want something to view raw network traffic and promisc). So I set to create my own!

Right now this is pretty basic, there is a menu to choose what interface to capture on and when you press start it will sniff one packet and log it to
catlog (so not so useful). The majority of the work so far was to get pcap4j to work on android...

I hope that somewhen I will also able to upgrade this to be able to send packets

## How did I get pcap4j to work on android?

The main problem with root on android is that the app itself can't really run as root, the most you can do is to install the app as a system
one but that is not really a good solution, that means that when pcap4j tries to load the libpcap library, it might load it with no problem but doing
anything networking related will most probably give a permission denied :(

what I did is to reimplement the pcap interface that pcap4j uses so it will talk with a native binary which will act as a proxy. that will work
because what we can do is run native programs as root (using a root shell). so that program will run as root, and we will have it load libpcap
and call all the functions! 
