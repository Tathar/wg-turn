/*
Copyright (C) 2024 Pierre-Emmanuel DOUET

This file is part of wg-turn.
wg-turn is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

wg-turn is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with wg-turn. If not, see <https://www.gnu.org/licenses/>.
*/

use crate::dht;
use crate::wg;
use crate::wg::WgPeer;

use anyhow::anyhow;
use anyhow::Result;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::select;
use tokio::task::JoinSet;
use tokio::time;
use tokio::{sync::mpsc, sync::RwLock};

pub async fn peer_task(mut peer: wg::WgPeer, dht: Arc<RwLock<dht::DHT>>) -> Result<WgPeer> {
    peer.gateway(None).await;

    let mut rx_dht: mpsc::Receiver<SocketAddr>;

    let mut w_dht = dht.write().await;
    rx_dht = w_dht
        .register(&peer.public_key(), &peer.preshared_key())
        .await;
    drop(w_dht);

    let rx_wg = peer.check_input();
    let mut w_rx_wg = rx_wg.write().await;

    let _ = peer.ping().await;

    let interval = time::interval(wg::SLEEP);
    let mut first_interval = true;

    tokio::pin!(interval);
    loop {
        tokio::select! {
            Some(endpoint) = rx_dht.recv() => {
                // println!("2 receve {}", endpoint);
                let _reuslt = peer.new_check(endpoint).await.unwrap();
                // time::sleep(Duration::from_secs(10)).await;
                },
            Some(endpoint) = w_rx_wg.recv() => {
                // println!("2 set {}", endpoint);
                peer.gateway(Some(endpoint)).await;
                // tokio::time::sleep(Duration::from_secs(30)).await;
                match peer.check_connection().await {
                    Ok(ret) => if ret {
                        // let ret = peer.public_key().clone();
                        // peer.clean().await;
                        return Ok(peer);
                    }
                    Err(err) => {
                        println!("peer_task error: {}: return",err);
                        // peer.clean().await;
                        return Err(anyhow!("peer_task error is_connected(): {}",err))
                    }
                }
            },
            _ = interval.tick() => {
                if first_interval {
                    first_interval = false;
                } else {
                    match peer.is_connected().await {
                        Ok(ret) => if ret {
                            // peer.clean().await;
                            return Ok(peer);
                        },
                        Err(err) => {
                            println!("peer_task error: {}: return",err);
                            // peer.clean().await;
                            return Err(anyhow!("peer_task() error: {}" ,err));
                            },
                    }
                    let _ = peer.ping().await;
                }
            },
            else => {
                // peer.clean().await;
                return Err(anyhow!("peer_task oups"))
            },
        };
    }
}

pub async fn interface_task(iface_name: String) -> Result<()> {
    loop {
        let device: Arc<wg::WgDevice>;
        match wg::WgDevice::new(&iface_name) {
            Ok(wg_device) => device = Arc::new(wg_device),
            Err(err) => {
                println!("Error {}: wait 3Os end retry", err);
                time::sleep(Duration::from_secs(30)).await;
                // wg_peers.clear();
                continue;
            }
        }

        if let Ok(result) = device.check_all_peers(device.clone()).await {
            if result == true {
                continue;
            }
        } else {
            // println!("wait 30s");
            time::sleep(Duration::from_secs(30)).await;
            continue;
        }

        device.gateway().await;
        let dht = Arc::new(RwLock::new(
            dht::DHT::new(device.org_listen_port(), device.public_key().await).await,
        ));

        let mut peer_tasks = JoinSet::new();
        let mut peers = device.get_all_peers().await;
        // let mut actual_peer : Vec<PublicKey> = Vec::new();
        while let Some(peer) = peers.pop() {
            let wg_peer = wg::WgPeer::new(device.clone(), peer).await;
            peer_tasks.spawn(peer_task(wg_peer, dht.clone()));

            // time::sleep(Duration::from_secs(10)).await;
        }
        let mut check_task = JoinSet::new();
        loop {
            select! {
                 result = peer_tasks.join_next() => {
                    if let Some(result) = result{
                        match result {
                            Ok(result) => {
                                match result {
                                    Ok(mut wg_peer) => {
                                        println!("peer {} is connected",wg_peer.public_key());
                                        // let peer = device.get_peer(&public_key).await.unwrap();
                                        // let mut wg_peer = WgPeer::new(device.clone(), peer).await;
                                        check_task.spawn(async move {
                                            loop {
                                                match wg_peer.check_connection().await {
                                                    Ok(connected) => {
                                                        if !connected {
                                                            // wg_peer.clean().await;
                                                            return wg_peer;
                                                        }
                                                    },
                                                    Err(err) => println!("interface_task check connection error {} for {}", err, wg_peer.public_key())
                                               }

                                            }
                                        });
                                    }
                                    Err(err) => return Err(anyhow!("interface_task error {}", err)),
                                }
                            }
                            Err(err) => return Err(anyhow!("interface_task join error {}", err)),
                        }
                    } else {
                        println!("all peer is connected");
                        break
                    }
                }
                result = check_task.join_next(),if check_task.len() > 0 => {
                    if let Some(result) = result{
                        match result {
                            Ok(wg_peer) => {
                                // let peer = device.get_peer(&public_key).await.unwrap();
                                // let wg_peer = wg::WgPeer::new(device.clone(), peer).await;
                                peer_tasks.spawn(peer_task(wg_peer, dht.clone()));
                            }
                            Err(err) => return Err(anyhow!("interface_task error {}", err)),
                        }
                    }
                },
            }
        }

        check_task.abort_all();
        while let Some(_) = check_task.join_next().await {}
        drop(dht);
    }
}
