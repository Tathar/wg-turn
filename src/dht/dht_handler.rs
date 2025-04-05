/*
Copyright (C) 2024 Pierre-Emmanuel DOUET

This file is part of wg-turn.
wg-turn is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

wg-turn is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with wg-turn. If not, see <https://www.gnu.org/licenses/>.
*/


// use crate::dht::DhtCommand;

use crate::utils;
use crate::utils::Abort;
use crate::utils::PublicKey;
use btdht::{router, InfoHash, MainlineDht, NodeId};
use futures::stream::StreamExt;
use rand;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::sync;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::select;

pub enum DhtCommand {
    Register(PublicKey, oneshot::Sender<mpsc::Receiver<SocketAddr>>),
}

pub struct DhtHandler {
    rcv: mpsc::UnboundedReceiver<DhtCommand>,
    running: bool,
    dht4: MainlineDht,
    dht6: MainlineDht,
    pub_key: Option<PublicKey>,
    tasks: Vec<Abort<()>>,
}

impl DhtHandler {
    pub async fn new(port: u16, pub_key: PublicKey, rcv: mpsc::UnboundedReceiver<DhtCommand>) -> DhtHandler {
        let id = NodeId::from(rand::random::<[u8; 20]>());

        let socket4 = utils::new_reuse_udp_socket(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port).unwrap();

        let dht4 = 
            MainlineDht::builder()
                .add_routers([router::BITTORRENT_DHT, router::TRANSMISSION_DHT])
                .set_read_only(true)
                .set_node_id(id.clone())
                .start(socket4)
                .unwrap();

        let socket6 = utils::new_reuse_udp_socket(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).unwrap();

        let dht6 = 
            MainlineDht::builder()
                .add_routers([router::BITTORRENT_DHT, router::TRANSMISSION_DHT])
                .set_read_only(true)
                .set_node_id(id)
                .set_announce_port(port)
                .start(socket6)
                .unwrap();

        let dht4s = dht4.clone();
        let dht6s = dht6.clone();

        let mut tasks = Vec::new();

        tasks.push(Abort::spawn(async move {
            println!("bootstrap ipv4");
            dht4s.bootstrapped().await;
            println!("bootstraped ipv4");
        }));

        tasks.push(Abort::spawn(async move {
            println!("bootstrap ipv6");
            dht6s.bootstrapped().await;
            println!("bootstraped ipv6");
        }));

        // let (snd, rcv) = mpsc::unbounded_channel();

        DhtHandler {
            rcv,
            running: true,
            dht4,
            dht6,
            pub_key: Some(pub_key),
            tasks,
        }
    }

    pub async fn run(mut self) {
        while self.running {
            self.run_once().await
        }
    }

    pub async fn run_once(&mut self) {
        select! {
            command = self.rcv.recv() => {
                if let Some(command) = command {
                    self.handle_command(command).await
                } else {
                    self.shutdown()
                }
            }
        }
    }

    async fn handle_command(&mut self, task: DhtCommand) {
        match task {
            DhtCommand::Register(pub_key,ret) => {
                self.register(pub_key,ret).await;
            }
        }
    }

    fn shutdown(&mut self) {
        self.running = false;
    }

    pub async fn register(&mut self, pub_key: PublicKey, ret : sync::oneshot::Sender<mpsc::Receiver<SocketAddr>>)  {
        let key_array = utils::calc_id(&pub_key.array(), &self.pub_key.clone().unwrap().array());
        let id = InfoHash::sha1(&key_array);

        let (snd1, rcv) = mpsc::channel(1);
        let snd2 = snd1.clone();

        let dht4 = self.dht4.clone();
        // let mut tasks = self.tasks.write().await;
        self.tasks.push(Abort::spawn(async move {
            let mut peers = HashSet::new();
            loop {
                // let start = Instant::now();
                if dht4.bootstrapped().await == false {
                    continue;
                };
                // println!("search ipv4");
                let mut search = dht4.search(id, true);
                while let Some(addr) = search.next().await {
                    if peers.insert(addr) {
                        // println!("peer found: {addr}");
                    }
                }

                if peers.len() != 0 {
                    for peer in peers.drain() {
                        if let Err(_) = snd1.send(peer).await {
                            println!("dht v4 receiver dropped");
                            return;
                        };
                    }
                }
            }
        }));

        let dht6 = self.dht6.clone();
        self.tasks.push(Abort::spawn(async move {
            loop {
                let mut peers = HashSet::new();
                // let start = Instant::now();
                if dht6.bootstrapped().await == false {
                    continue;
                };
                // println!("search ipv6");
                let mut search = dht6.search(id, true);
                while let Some(addr) = search.next().await {
                    if peers.insert(addr) {
                        // println!("peer found: {addr}");
                    }
                }

                if peers.len() != 0 {
                    for peer in peers.drain() {
                        if let Err(_) = snd2.send(peer).await {
                            println!("dht v6 receiver dropped");
                            return;
                        };
                    }
                }
            }
        }));

        ret.send(rcv).unwrap();
    }
}

impl Drop for DhtHandler {
    fn drop(&mut self) {
        println! {"drop DHT handler"};
    }
}
