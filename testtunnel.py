import os
import time
import multiprocessing
import binascii
from asyncio import ensure_future, get_event_loop, sleep, create_task
import logging
import psutil
import uvloop
import pprofile
import struct
import copy

from ipv8.messaging.anonymization.tunnel import EXIT_NODE, ORIGINATOR, IntroductionPoint
from ipv8.messaging.anonymization.tunnelcrypto import TunnelCrypto
from ipv8.messaging.anonymization.utils import run_speed_test
from ipv8.messaging.anonymization.hidden_services import HiddenTunnelCommunity
from ipv8.messaging.anonymization.community import TunnelSettings, PEER_FLAG_EXIT_BT, PEER_FLAG_EXIT_IPV8
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, Bootstrapper, BootstrapperDefinition
from ipv8_service import IPv8
from ipv8.taskmanager import task
from tracker_service import TrackerService

SWARMINFOHASH = binascii.unhexlify('e24d8e65a329a59b41a532ebd4eb4a3db7cb291b')

# results are printed to console and saved as texfiles in the CWD

TOTALMB = 25 # total MB to ping pong in between entry and exit
STARTPORT = 7090 # each peer is incrementing this ipv8 port
PROFILE = False # if enabled, enables linerprofiler on entry node, results save in profile.txt
UVLOOP = False # change the reactor to UVLOOP instead of asyncio
AEADPY = False # use faster symmetric encrytion library, the idea is implemented here, little bit ugly: https://github.com/shaktee/aeadpy
USEAFFINITY = True # each peer is running as a seperate proceess, when affinities enabled, each peer strictly runs on specified core in CPU_AFFINITIES. This is very usefull to compare performance of different pyipv8 implementations
HOPS = [1] # test for each node count 
E2E = [True] # test for each e2e criteria
SCALE = 1 # scale the transmitted packet size on test, bigger the faster, because it reduces the reactor overhead, however be carefull not to exceed UDP packet size
LOGLEVEL = 20
TRACKERPORT = 7089

TOTALMB = TOTALMB * SCALE
CPU_AFFINITIES = {"exit":[3],
                  "seed":[2],
                  "entry": [0],
                  "middle": [1, 4, 5, 6, 7]}
CORES = multiprocessing.cpu_count()
bootstrap_defs = [BootstrapperDefinition(Bootstrapper.DispersyBootstrapper, {'ip_addresses': [("192.168.2.226", TRACKERPORT)],
                                                                             'dns_addresses': [],
                                                                             'bootstrap_timeout': 0.0})]

processes = []
profiler = pprofile.Profile()

if AEADPY:
    import aeadpy
    

def getcpucore(role, affinities):
    if not USEAFFINITY:
        return None
    try:
        core = affinities[role].pop(0)
    except IndexError:
        core = None
    if core and core >= CORES:
        core = None
    return core


class AeadCrypto(TunnelCrypto):
    def initialize(self, key):
        TunnelCrypto.initialize(self, key)
        self.logger = logging.getLogger(self.__class__.__name__)
        print("Using AEADpy")
        
    def encrypt_str(self, content, key, salt, salt_explicit):
        saltex = struct.pack('!q', salt_explicit)
        ciphertext = aeadpy.encrypt(b"CHACHA20_POLY1305", key, content, salt + saltex, b"")
        return saltex + ciphertext["ciphertext"] + ciphertext["tag"]

    def decrypt_str(self, content, key, salt):
        content = salt + content
        return aeadpy.decrypt(b"CHACHA20_POLY1305", key, content[12:], content[:12], b"", b"")["plaintext"]



class FakeDhtProvider:
    def __init__(self, pipe):
        self.peers = []
        self.pipe = pipe
        self._pk = None
        
    @property
    def pk(self):
        if not self._pk:
            self._pk = self.pipe.recv()
        return self._pk
    
    def add(self, peer):
        self.peers.append(peer)
    
    async def peer_lookup(self, mid, peer=None):
        logging.info("peer lookup")
    
    async def announce(self, info_hash, intro_point):
        logging.info("peer announce")

    async def lookup(self, infohash):
        logging.info("lookup")
        return infohash, [IntroductionPoint(x, self.pk, source=1) for x in self.peers]

seed_lpipe, seed_rpipe = multiprocessing.Pipe()
entry_lpipe, entry_rpipe = multiprocessing.Pipe()
fakeprovider = FakeDhtProvider(seed_lpipe)


class SpeedTest(HiddenTunnelCommunity):
    community_id = os.urandom(20)

    def __init__(self, *args, **kwargs):
        self.targethops = kwargs.pop("hops")
        self.pipe = kwargs.pop("pipe")
        self.isexit = kwargs.pop("isexit", False)
        self.isentry = kwargs.pop("isentry", False)
        self.ise2e = kwargs.pop("ise2e", False)
        self.isseed = kwargs.pop("isseed", False)
        self.results = []
        self.testid = "%shop_%s" % (self.targethops, self.ise2e)
        super(SpeedTest, self).__init__(*args, **kwargs)
        if self.ise2e:
            self.dht_provider = fakeprovider

    def started(self):
        if self.ise2e:
            fakeprovider.add(self.my_peer)
            if self.isentry:
                self.join_swarm(SWARMINFOHASH, self.targethops, seeding=False, callback=self.on_community_started)
            elif self.isseed:
                self.join_swarm(SWARMINFOHASH, self.targethops, seeding=True)
                self.pipe.send(self.swarms[SWARMINFOHASH].seeder_sk.pub().key_to_bin())
                self.register_task("introduction_point", self.create_introduction_point, SWARMINFOHASH, delay=10)
            self.register_task("doping", self.do_ping)
            self.register_task("docirc", self.do_circuits, delay=1)
        else:
            self.register_task("started", self.on_community_started)
    
    @task
    async def on_community_started(self, address=None):
        if self.isentry:
            if self.ise2e:
                circuit = self.circuits[self.ip_to_circuit_id(address[0])]
            else:
                while True:
                    circuit = self.create_circuit(self.targethops)
                    if circuit and await circuit.ready:
                        break
                    await sleep(2)
            logging.info("I am: %s, using circuit: %s, E2E: %s" % (self.my_peer, 
                                                                   " <-> ".join([str(x.peer) for x in circuit.hops]), 
                                                                   circuit.e2e))
            self.results += await self.run_speed_test(ORIGINATOR, circuit, TOTALMB)
            self.results += await self.run_speed_test(EXIT_NODE, circuit, TOTALMB)
            self.remove_circuit(circuit.circuit_id)
            for i in range(2):
                results = "\n".join([";".join([str(y) for y in x if x[1] == i]) for x in self.results])
                logging.info("\n" + results)
                with open("result_%s_%s.csv" % (self.testid, i), "w+") as f:
                    f.write(results)
            loop = get_event_loop()
            loop.call_later(0, loop.stop)
            self.pipe.send(True)

    async def run_speed_test(self, direction, circuit, size):
        packetsize = 1024 * SCALE
        request_size = 0 if direction == ORIGINATOR else packetsize
        response_size = packetsize if direction == ORIGINATOR else 0
        num_requests = size * 1024 * 1024 / packetsize
        task = create_task(run_speed_test(self, circuit, request_size, response_size, num_requests, window=50))
        results = []
        prev_transferred = ts = 0
        while not task.done():
            cur_transferred = circuit.bytes_down if direction == ORIGINATOR else circuit.bytes_up
            results.append((ts, direction, (cur_transferred - prev_transferred) / 1024))
            prev_transferred = cur_transferred
            ts += 1
            await sleep(1)
        return results


async def start_community(i, hops, isexit=False, isentry=False, ise2e=False, isseed=False):
    builder = ConfigBuilder().clear_keys().clear_overlays()
    port = STARTPORT + i
    builder.set_port(port)
    role = "entry " if isentry else "exit  " if isexit else "seed  " if isseed else "middle"
    builder.config['logger'] = {"format": f"{port}->{role}: %(asctime)s - %(name)s - %(levelname)s - %(message)s", "level": LOGLEVEL}
    builder.add_key("my peer", "curve25519", f"ec{i}.pem")
    settings = TunnelSettings()
    settings.next_hop_timeout = 30
    if isexit:
        settings.peer_flags.add(PEER_FLAG_EXIT_IPV8)
        settings.peer_flags.add(PEER_FLAG_EXIT_BT)
    if AEADPY:
        settings.crypto = AeadCrypto()
    extra_communities = {}
    builder.add_overlay("SpeedTest",
                        "my peer",
                        [WalkerDefinition(Strategy.RandomWalk, 10, {'timeout': 3.0})],
                        # [BootstrapperDefinition(Bootstrapper.UDPBroadcastBootstrapper, {})],
                        bootstrap_defs,
                        {"settings": settings,
                         "pipe": seed_rpipe if isseed else entry_rpipe if isentry else None,
                         "isentry": isentry,
                         "isexit": isexit,
                         "ise2e": ise2e,
                         "isseed": isseed,
                         "hops": hops},
                        [('started',)])
    extra_communities["SpeedTest"] = SpeedTest
    await IPv8(builder.finalize(), extra_communities=extra_communities).start()


def runcommunity(i, hops, isexit, isentry, ise2e, isseed):
    if UVLOOP:
        uvloop.install()
    
    if PROFILE and isentry:
        print("profiling entry node")
        profiler.enable()
    ensure_future(start_community(i, hops, isexit, isentry, ise2e, isseed))
    get_event_loop().run_forever()
    if PROFILE and isentry:
        profiler.disable()
        profiler.dump_stats("profile.txt")
    
   
def runprocess(i, hops, isexit, isentry, ise2e, isseed, affinities):
    role = "entry" if isentry else "exit" if isexit else "seed" if isseed else "middle"
    core = getcpucore(role, affinities)
    if core is not None:
        p = psutil.Process()
        print("Spawning %s on cpu %s" % (role, core + 1))
        p.cpu_affinity([core])
    else:
        print("Spawning %s on with no affinity" % role)
    p = multiprocessing.Process(target=runcommunity, args=(i, hops, isexit, isentry, ise2e, isseed))
    p.start()
    processes.append(p)
    

def runtracker(port):
    def trackerloop(port):
        tracker = TrackerService()
        ensure_future(tracker.start_tracker(port))
        get_event_loop().run_forever()
    p = multiprocessing.Process(target=trackerloop, args=(port,))
    p.start()
    processes.append(p)



def runtest(hops, ise2e):
    print("Starting test for HOPS: %s, E2E: %s" % (hops, ise2e))
    affinities = copy.deepcopy(CPU_AFFINITIES)
    
    runtracker(TRACKERPORT)

    # start hops
    for i in range(hops):
        runprocess(i, hops, False, i == 0, ise2e, False, affinities)
        
    # start exit
    runprocess(i + 1, hops, True, False, ise2e, False, affinities)
    
    # 1 more peer when E2E
    if ise2e:
        runprocess(i + 2, hops, False, False, ise2e, True, affinities)
    
    # wait for finish signal, and kill everything like a faschist
    if entry_lpipe.recv():
        time.sleep(1)
        for p in processes:
            pass
            p.kill()
    time.sleep(5)
    print("Ended test for HOPS: %s, E2E: %s" % (hops, ise2e))


for i in HOPS:
    for ise2e in E2E:
        runtest(i, ise2e)
        time.sleep(3)
