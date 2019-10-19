# Packet Manipulator

Some time ago I tried to search for a nice wireshark like app for android, and everything I could find either 
didn't work, or wasn't what I was looking for (for example there are some great packet capture applications that use the android vpn
feature to capture network activity of other apps, but I want something to view raw network traffic and promisc). So I set to create my own!

Right now this is pretty basic, there is a menu to choose what interface to capture on and when you press start it will start capturing
packets and add them to the list on the screen. I started adding some basic trasnfomers for the entries (so they can show fancy info or whatever) but right now only got ether, linux sll, ipv4 and arp.

I hope that somewhen I will also able to upgrade this to be able to send packets

<img width="200" src="https://i.imgur.com/VMYOimq.png">

## How did I get pcap4j to work on android?

The main problem with root on android is that the app itself can't really run as root, the most you can do is to install the app as a system
one but that is not really a good solution, that means that when pcap4j tries to load the libpcap library, it might load it with no problem but doing
anything networking related will most probably give a permission denied :(

what I did is to reimplement the pcap interface that pcap4j uses so it will talk with a native binary which will act as a proxy. that will work
because what we can do is run native programs as root (using a root shell). so that program will run as root, and we will have it load libpcap
and call all the functions! 
