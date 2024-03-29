# wg-turn

wg-turn is just a [turn](https://en.wikipedia.org/wiki/Traversal_Using_Relays_around_NAT) daemon for wireguard.If you need more functionality, you can look at [cunīcu](https://cunicu.li/), [netbird](https://netbird.io/), [TailScale](https://tailscale.com/) or other 

wg-turn use the mainline DHT to discover the peers endpoint

:warning: someone in possession of private keys would be able to carry out a man-in-the-middle attack.

## usage
configure a wireguard interface with the name: "wg-turn0" or "wg_turn0" on device
with [wg-quick](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8), or with [Command-line Interface](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8).

- You can omit the endpoint.
- it is advisable to set persistent-keepalive to 25.

once the interface is configured and mounted, all you have to do is run the wg-turn daemon. Wait a few seconds (this can take up to 5 minutes).

## functionality

- wireguard
    - [x] IPv4 inteface
    - [ ] IPv6 inteface (note tested)
- endpoint
  - [x] IPv4 endpoint
  - [x] IPv6 endpoint
- DHT
    - [X] IPv4 dht
    - [x] IPv6 dht

wg-turn has only been tested on linux-based operating systems.

