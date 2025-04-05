/*
Copyright (C) 2024 Pierre-Emmanuel DOUET

This file is part of wg-turn.
wg-turn is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

wg-turn is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with wg-turn. If not, see <https://www.gnu.org/licenses/>.
*/

use crate::utils::Abort;
use crate::utils::PublicKey;
use crate::utils::{self, Handcheck, Msg, MsgType};

use anyhow::{anyhow, Result};
use crypto_box::SecretKey;
use rand::prelude::*;
use std::collections::HashMap;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr,
    SocketAddr::{V4, V6},
};
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;
use tokio::net::UdpSocket;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, RwLock, RwLockWriteGuard};
use tokio::task::JoinSet;
use tokio::time;
use tokio::{select, time::sleep};
use wireguard_uapi::linux::err::SetDeviceError;
use wireguard_uapi::linux::set::{Device, Peer};
use wireguard_uapi::{err, DeviceInterface, WgSocket};

#[cfg(debug_assertions)]
use base64::prelude::*;

const SHORT_SLEEP: std::time::Duration = std::time::Duration::from_secs(10);
pub const SLEEP: std::time::Duration = std::time::Duration::from_secs(25);
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

struct WgIface {
    socket: WgSocket,
    device: wireguard_uapi::get::Device,
}

impl WgIface {
    pub fn new(name: &str) -> Result<WgIface> {
        let mut socket = WgSocket::connect()?;
        let device = socket.get_device(DeviceInterface::from_name(name))?;

        Ok(WgIface { socket, device })
    }

    pub fn update(&mut self) -> Result<(), err::GetDeviceError> {
        self.device = self
            .socket
            .get_device(DeviceInterface::from_name(&self.device.ifname[..]))?;
        return Ok(());
    }

    pub fn set_device(&mut self, device: Device) -> Result<(), SetDeviceError> {
        self.socket.set_device(device)
    }
}

impl Deref for WgIface {
    type Target = wireguard_uapi::get::Device;
    fn deref(&self) -> &Self::Target {
        &self.device
    }
}

pub struct WgDevice {
    device: Arc<RwLock<WgIface>>,
    org_listen_port: u16,
    tmp_listen_port: RwLock<Option<u16>>,
    configs: RwLock<HashMap<PublicKey, (SocketAddr, Option<Abort<()>>)>>,
}

static WG_COUNTER: AtomicUsize = AtomicUsize::new(0);

impl WgDevice {
    pub fn new(name: &str) -> Result<WgDevice> {
        let device = WgIface::new(name)?;
        let org_listen_port = device.listen_port;

        #[cfg(debug_assertions)]
        println!("WgDevice::new() listen_port = {}", org_listen_port);

        WG_COUNTER.fetch_add(1, Ordering::Relaxed);

        Ok(WgDevice {
            device: Arc::new(RwLock::new(device)),
            org_listen_port,
            tmp_listen_port: RwLock::new(None),
            // aborts: RwLock::new(Vec::new()),
            configs: RwLock::new(HashMap::new()),
        })
    }

    pub fn all_close() -> bool {
        if WG_COUNTER.load(Ordering::Relaxed) == 0 {
            true
        } else {
            false
        }
    }

    pub async fn gateway(&self) {
        //        println!("tmp_listen_port lock");
        let mut w_tmp_listen_port = self.tmp_listen_port.write().await;
        let mut tmp_listen_port = w_tmp_listen_port.take();

        if tmp_listen_port == None {
            //            println!("WgIface lock");
            let mut w_device = self.device.write().await;
            let ifname = w_device.device.ifname.clone();
            if let Some(port) = self.set_wg_port(&mut w_device.socket, &ifname) {
                #[cfg(debug_assertions)]
                {
                    println!("WgDevice::gateway() listen_port = {}", self.org_listen_port);
                    println!("tmp_listen_port = {}", port);
                }

                tmp_listen_port = Some(port.clone());
            } else {
                panic!("cannot create socket for wireguard")
            }
        }
        *w_tmp_listen_port = tmp_listen_port;
    }

    pub async fn update(&self) -> Result<(), err::GetDeviceError> {
        // println!("WgDevice::update()");
        // println!("Wgiface lock");
        let mut w_device = self.device.write().await;
        let ret = w_device.update();
        drop(w_device);
        //        println!("Wgiface unlock");
        ret
    }

    pub async fn set_peer(&self, public_key: &PublicKey, endpoint: &SocketAddr) -> bool {
        // println!("WgDevice::set_peer(): Wgiface lock");
        let mut peer = Peer::from_public_key(public_key.as_bytes());
        peer = peer.endpoint(endpoint);

        // println!("Wgiface lock");
        let mut w_device: RwLockWriteGuard<'_, WgIface> = self.device.write().await;
        let name = w_device.ifname.clone();

        let mut n_device = Device::from_ifname(&name);
        n_device.peers.push(peer);

        if let Err(_) = w_device.set_device(n_device) {
            false
        } else {
            true
        }
    }

    async fn set_peer_with_lock(
        &self,
        w_device: &mut RwLockWriteGuard<'_, WgIface>,
        public_key: &PublicKey,
        endpoint: &SocketAddr,
    ) -> bool {
        // println!("WgDevice::set_peer(): Wgiface lock");
        let mut peer = Peer::from_public_key(public_key.as_bytes());
        peer = peer.endpoint(endpoint);

        // println!("Wgiface lock");
        // let mut w_device: RwLockWriteGuard<'_, WgIface> = self.device.write().await;
        let name = w_device.ifname.clone();
        let mut n_device = Device::from_ifname(&name);
        n_device.peers.push(peer);

        if let Err(_) = w_device.set_device(n_device) {
            false
        } else {
            true
        }
    }

    pub fn org_listen_port(&self) -> u16 {
        self.org_listen_port
    }

    pub async fn tmp_listen_port(&self) -> u16 {
        self.gateway().await;
        let r_tmp_listen_port = self.tmp_listen_port.read().await;
        *r_tmp_listen_port.as_ref().unwrap()
    }

    pub async fn tmp_v4_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            self.tmp_listen_port().await,
        )
    }

    pub async fn tmp_v6_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            self.tmp_listen_port().await,
        )
    }

    pub fn local_v4_socket(&self) -> Result<UdpSocket> {
        utils::new_reuse_udp_socket(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    pub fn local_v6_socket(&self) -> Result<UdpSocket> {
        utils::new_reuse_udp_socket(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)
    }

    pub fn inet_v4_socket(&self) -> Result<UdpSocket> {
        utils::new_reuse_udp_socket(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.org_listen_port)
    }

    pub fn inet_v6_socket(&self) -> Result<UdpSocket> {
        utils::new_reuse_udp_socket(IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.org_listen_port)
    }

    pub async fn public_key(&self) -> PublicKey {
        //        println!("WgDevice::public_key() Wgiface Rlock");
        let r_device = self.device.read().await;
        PublicKey::new(r_device.public_key.unwrap())
    }

    pub async fn private_key(&self) -> SecretKey {
        //        println!("WgDevice::public_key() Wgiface Rlock");
        let r_device = self.device.read().await;
        SecretKey::from_bytes(r_device.private_key.unwrap())
    }

    pub async fn get_peer(&self, public_key: &PublicKey) -> Result<wireguard_uapi::get::Peer> {
        // println!("WgDevice::get_peer()");
        self.update().await?;

        // println!("WgDevice::get_peer() update");
        // println!("WgDevice::get_peer() Wgiface Rlock");
        let r_device = self.device.read().await;
        for peer in r_device.peers.iter() {
            if public_key == &peer.public_key {
                return Ok(peer.clone());
            }
        }
        return Err(anyhow!("WgDevice::get_peer() peer not found"));
    }

    pub async fn get_all_peers(&self) -> Vec<wireguard_uapi::get::Peer> {
        // println!("WgDevice::get_all_peers() Wgiface Rlock");
        let r_device = self.device.read().await;
        return r_device.peers.clone();
    }

    pub async fn check_all_peers(&self, device: Arc<WgDevice>) -> Result<bool> {
        // println!("WgDevice::check_all_peers()");
        self.update().await?;
        let mut tasks: JoinSet<Result<bool>> = JoinSet::new();
        // println!("WgDevice::check_all_peers() Wgiface Rlock");
        let r_device = self.device.read().await;
        for peer in r_device.peers.iter() {
            let mut wg_peer = WgPeer::new(device.clone(), peer.clone()).await;
            // wg_peers.push(wg_peer);
            tasks.spawn(async move { wg_peer.check_connection().await });
        }
        drop(r_device);

        let mut ok = true;
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(result) => match result {
                    Ok(result) => {
                        if !result {
                            #[cfg(debug_assertions)]
                            println!("WgDevice::check_all_peers() : false");
                            ok = false;
                            break;
                        }
                    }
                    Err(err) => {
                        println!("WgDevice::check_all_peers() Error {}", err);
                        return Err(anyhow!("WgDevice::check_all_peers(): Error {}", err));
                    }
                },
                Err(err) => {
                    println!("WgDevice::check_all_peers() JoinError {}", err);
                    return Err(anyhow!("WgDevice::check_all_peers(): JoinError {}", err));
                }
            }
        }

        if ok {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn push_config(
        &self,
        pub_key: PublicKey,
        endpoint: SocketAddr,
        abort: Option<Abort<()>>,
    ) {
        let mut w_configs = self.configs.write().await;
        w_configs.insert(pub_key, (endpoint, abort));
    }

    pub async fn get_config(&self, pub_key: &PublicKey) -> Option<(SocketAddr, Option<Abort<()>>)> {
        let mut w_configs = self.configs.write().await;
        w_configs.remove(pub_key)
    }

    //set wireguarde listen port
    fn set_wg_port(&self, wgsocket: &mut WgSocket, name: &str) -> Option<u16> {
        let mut port: u16 = random();

        while port < 1024 && port >= 65535 && port == self.org_listen_port {
            port = random();
        }

        let mut wg_device_set = Device::from_ifname(name);
        wg_device_set = wg_device_set.listen_port(port);
        let result = wgsocket.set_device(wg_device_set);
        match result {
            Err(_) => {
                if port < 65535 {
                    self.set_wg_port(wgsocket, name)
                } else {
                    None
                }
            }
            Ok(_) => Some(port),
        }
    }

    async fn clean(&mut self) {
        // println!("WgDevice::clean()");

        let mut w_device = self.device.write().await;
        let mut w_tmp_listen_port = self.tmp_listen_port.write().await;
        if let Some(_) = w_tmp_listen_port.take() {
            let mut w_configs = self.configs.write().await;

            for (public_key, (endpoint, task)) in w_configs.drain() {
                // println!("WgDevice::clean set peer");
                drop(task);
                tokio::time::sleep(Duration::ZERO).await;
                let _result = self
                    .set_peer_with_lock(&mut w_device, &public_key, &endpoint)
                    .await;
                // if result {
                //     println!("peer {} set at {}", public_key,endpoint);
                // }
            }
            tokio::time::sleep(Duration::ZERO).await;

            // println!("clean Wgiface Wlock");
            let name = w_device.ifname.clone();

            loop {
                let mut wg_device_set = Device::from_ifname(&name);
                wg_device_set = wg_device_set.listen_port(self.org_listen_port);
                // println!("WgDevice::clean set_device");
                match w_device.set_device(wg_device_set) {
                    Err(err) => {
                        println!("WgDevice::clean() {}", err);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    Ok(_) => {
                        break;
                    }
                }
            }
        }

        // println!("WgDevice::clean() end");
    }
}

impl Drop for WgDevice {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        println!("WgDevice::drop() listen_port = {}", self.org_listen_port);

        tokio::task::block_in_place(move || {
            Handle::current().block_on(async move {
                self.clean().await;
                WG_COUNTER.fetch_sub(1, Ordering::Relaxed);
            });
        });
    }
}

pub struct WgPeer {
    iface: Arc<WgDevice>,
    inet_endpoint: Option<SocketAddr>,
    check_data: u64,
    check_time: std::time::Instant,
    gateway: Option<Abort<()>>,
    wg_peer: wireguard_uapi::get::Peer,
    // rx: Arc<RwLock<mpsc::Receiver<SocketAddr>>>,
    rx: Option<mpsc::Receiver<SocketAddr>>,
    tx: mpsc::Sender<SocketAddr>,
    tests: Arc<RwLock<HashMap<SocketAddr, Abort<Result<()>>>>>,
}

impl WgPeer {
    pub async fn new(iface: Arc<WgDevice>, wg_peer: wireguard_uapi::get::Peer) -> WgPeer {
        let inet_endpoint: Option<SocketAddr>;
        let gateway: Option<Abort<()>>;
        if let Some((endpoint, task)) = iface.get_config(&PublicKey::new(wg_peer.public_key)).await
        {
            #[cfg(debug_assertions)]
            println!(
                "new WgPeer for {} with {}",
                BASE64_STANDARD.encode(wg_peer.public_key),
                endpoint
            );

            inet_endpoint = Some(endpoint);
            gateway = task;
        } else {
            #[cfg(debug_assertions)]
            println!(
                "new WgPeer for {}",
                BASE64_STANDARD.encode(wg_peer.public_key)
            );

            inet_endpoint = None;
            gateway = None;
        }
        let (tx, rx) = mpsc::channel(1);

        let check_data = wg_peer.rx_bytes;

        let ret = WgPeer {
            iface,
            wg_peer,
            inet_endpoint,
            check_data,
            check_time: std::time::Instant::now(),
            gateway,
            // rx: Arc::new(RwLock::new(rx)),
            rx: Some(rx),
            tx,
            tests: Arc::new(RwLock::new(HashMap::new())),
        };

        ret
    }

    // attache new localhost socket to public reuse_socket
    pub async fn gateway(&mut self, endpoint: Option<SocketAddr>) -> bool {
        #[cfg(debug_assertions)]
        if let Some(endpoint) = endpoint {
            println!("WgPeer::gateway() with {}", endpoint);
        } else {
            println!("WgPeer::gateway() with None");
        }

        let inet_endpoint: SocketAddr;

        if let Some(l_endpoint) = endpoint {
            inet_endpoint = l_endpoint;
            self.inet_endpoint = Some(l_endpoint);
        } else if let Some(l_endpoint) = self.inet_endpoint {
            inet_endpoint = l_endpoint;
        } else if let Some(l_endpoint) = self.wg_peer.endpoint {
            inet_endpoint = l_endpoint;
            self.inet_endpoint = Some(l_endpoint);
        } else {
            return false;
        }

        self.gateway = None;
        let local_socket: UdpSocket;
        let inet_socket: UdpSocket;

        self.iface.gateway().await;

        if let V6(_) = inet_endpoint {
            local_socket = self.iface.local_v6_socket().unwrap();
            local_socket
                .connect(self.iface.tmp_v6_socket_addr().await)
                .await
                .unwrap();
            inet_socket = self.iface.inet_v6_socket().unwrap();
        } else {
            local_socket = self.iface.local_v4_socket().unwrap();
            local_socket
                .connect(self.iface.tmp_v4_socket_addr().await)
                .await
                .unwrap();
            inet_socket = self.iface.inet_v4_socket().unwrap();
        }

        let local_endpoint: SocketAddr;
        match local_socket.local_addr() {
            Ok(endpoint) => local_endpoint = endpoint,
            Err(err) => {
                println!("WgPeer::gateway() for {} error: {}", self.public_key(), err);
                return false;
            }
        }

        if let Err(err) = inet_socket.connect(inet_endpoint).await {
            println!("WgPeer::gateway() for {} error: {}", self.public_key(), err);
            return false;
        }

        let public_key = self.public_key().clone();

        self.gateway = Some(Abort::spawn(async move {
            let mut inet_buf = vec![0u8; 64 * 1024];
            let mut local_buf = vec![0u8; 64 * 1024];
            loop {
                select! {
                    result = inet_socket.recv(&mut inet_buf) => {
                        if let Ok(n1)  = result {
                            if let Err(err) = local_socket.send(&inet_buf[0..n1]).await {
                                println!("WgPeer::Gateway for {} to {} error: {}",public_key,local_endpoint,err);
                                break;
                            }
                        }
                    }
                    result = local_socket.recv(&mut local_buf) => {
                        if let Ok(n1)  = result {
                            if let Err(err) = inet_socket.send(&local_buf[0..n1]).await {
                                println!("WgPeer::Gateway for {} to {} error: {}",public_key,inet_endpoint,err);
                                break;
                            }
                        }
                    }
                }
            }
        }));

        let ret = self
            .iface
            .set_peer(&PublicKey::new(self.wg_peer.public_key), &local_endpoint)
            .await;

        // println!("end WgPeer::gateway");
        ret
    }

    pub fn relese_gateway(&mut self) {
        self.gateway = None;
    }

    //create new public reuse socket and check peer identity
    pub async fn new_check(&mut self, endpoint: SocketAddr) -> Result<()> {
        // println!("new_check for {}", endpoint);
        if let V6(v6_endpoint) = endpoint {
            if v6_endpoint.port() <= 1 {
                return Ok(());
            }
        } else if let V4(v4_endpoint) = endpoint {
            if v4_endpoint.port() <= 1 {
                return Ok(());
            }
        }

        let org_listen_port = self.iface.org_listen_port();

        let question: [u8; 32] = random();

        let public_key = self.public_key();
        let private_key = self.iface.private_key().await;

        let msg = Msg::new(Some(question), None);
        let snd_question = serde_bencode::to_bytes(&Handcheck::new(
            MsgType::Syn,
            msg,
            &public_key,
            &private_key,
        )?)?;

        //send task
        let r_test = self.tests.read().await;
        if r_test.contains_key(&endpoint) {
            return Ok(());
        }
        drop(r_test);

        if let Some(connected_endoint) = self.inet_endpoint {
            if connected_endoint == endpoint {
                let _ = self.ping().await;
                time::sleep(SLEEP).await;
                if self.is_connected().await? {
                    println!("new_check return for {}", endpoint);
                    return Ok(());
                } else {
                    println!("new_check relese_gateway for {}", endpoint);
                    self.relese_gateway();
                    time::sleep(Duration::ZERO).await;
                }
            }
        }

        let mut w_tests = self.tests.write().await;

        //new test
        if !w_tests.contains_key(&endpoint) {
            let inet_socket: UdpSocket;
            if let V6(_) = endpoint {
                #[cfg(debug_assertions)]
                println!("new IPV6 socket");
                inet_socket =
                    utils::new_reuse_udp_socket(IpAddr::V6(Ipv6Addr::UNSPECIFIED), org_listen_port)
                        .unwrap();
            } else if let V4(_) = endpoint {
                #[cfg(debug_assertions)]
                println!("new IPV4 socket");
                inet_socket =
                    utils::new_reuse_udp_socket(IpAddr::V4(Ipv4Addr::UNSPECIFIED), org_listen_port)
                        .unwrap();
            } else {
                return Err(anyhow!("WgPeer::new_check() addres is no V4 or V6"));
            }

            let tx = self.tx.clone();

            let test = self.tests.clone();

            w_tests.insert(endpoint, Abort::spawn(async move {
                    // println!("check new peer for {} with {} ",public_key, endpoint);
                    match inet_socket.connect(endpoint).await {
                        Ok(_) => {}
                        Err(err) => {
                            println!("new_check for {} to {} with {}",public_key, endpoint,err);
                            let mut w_tests = test.write().await;
                            let _task = w_tests.remove(&endpoint);
                            return Err(anyhow!(err));
                        }
                    }


                    #[cfg(debug_assertions)]
                    match inet_socket.local_addr().unwrap() {
                        V6(data) => println!("socket {} is IPV6", data),
                        V4(data) =>  println!("socket {} is IPV4", data),
                    }

                    #[cfg(debug_assertions)]
                    match endpoint {
                        V6(data) => println!("endpoint {} is IPV6", data),
                        V4(data) =>  println!("endpoint {} is IPV4", data),
                    }

                    let start = time::Instant::now();

                    let interval  = time::interval(SHORT_SLEEP);
                    tokio::pin!(interval);
                    let mut buf = vec![0u8; 2048];
                    let mut count_syn_replay = 0u8;
                    let mut count_syn_act_replay = 0u8;
                    loop {
                        select! {
                            Ok(n) = inet_socket.recv(&mut buf) => {
                                // println!("data receve from {} with len {}", endpoint, n);

                                if n == snd_question.len() && buf[..snd_question.len()] == snd_question {
                                    println!("Receve Self Syn message");
                                    return Ok(());
                                } else {
                                    let handshake : Handcheck;
                                    match  serde_bencode::from_bytes(&buf) {
                                        Ok(ok) => handshake = ok,
                                        Err(err) => {
                                            println!("serde error in new_check for {} to {} with {}",public_key, endpoint,err);
                                            let mut w_tests = test.write().await;
                                            let _task = w_tests.remove(&endpoint);
                                            return Err(anyhow!("serde error in new_check for {} to {} with {}",public_key, endpoint,err));
                                        }
                                    }

                                    match handshake.decrypt(&public_key,&private_key) {
                                        Ok(msg) => {
                                            if handshake.msg_type == MsgType::Syn {
                                                if count_syn_replay < 5 {
                                                    count_syn_replay += 1;
                                                    println!("Receve Syn for {} from {}",public_key,endpoint);
                                                    // let msg = handshake.decrypt(&public_key,&private_key)?;
                                                    let res = Msg::new(Some(question),Some(msg.question));

                                                    match Handcheck::new(MsgType::SynAck, res, &public_key,&private_key) {
                                                        Ok(handcheck) => {
                                                            
                                                                match serde_bencode::to_bytes(&handcheck) {
                                                                    Ok(snd_responce) => {
                                                                        let result = inet_socket.send(&snd_responce).await;
                                                                        match result {
                                                                            Ok(_) => {
                                                                                println!("Send Syn/Ack for {} to {}",public_key, endpoint);
                                                                            },
                                                                            Err(err) => {
                                                                                println!("send Syn/Ack error in new_check for {} to {} with {}",public_key, endpoint,err);
                                                                                let mut w_tests = test.write().await;
                                                                                let _task = w_tests.remove(&endpoint);
                                                                                return Err(anyhow!("send Syn/Ack error in new_check for {} to {} with {}",public_key, endpoint,err));
                                                                            },
                                                                        };
                                                                    },
                                                                    Err(err) => {
                                                                        println!("send Syn/Ack error in new_check for {} to {} with {}",public_key, endpoint,err);
                                                                        let mut w_tests = test.write().await;
                                                                        let _task = w_tests.remove(&endpoint);
                                                                        return Err(anyhow!("send Syn/Ack error in new_check for {} to {} with {}",public_key, endpoint,err));
                                                                    },
                                                                };
                                                        },
                                                        Err(err) => {
                                                            println!("send Syn/Ack error in new_check for {} to {} with {}",public_key, endpoint,err);
                                                            let mut w_tests = test.write().await;
                                                            let _task = w_tests.remove(&endpoint);
                                                            return Err(anyhow!("send Syn/Ack error in new_check for {} to {} with {}",public_key, endpoint,err));
                                                        },
                                                    };
                                                }else {
                                                    println!("receve Syn replay for {} from {}",public_key, endpoint);
                                                    let mut w_tests = test.write().await;
                                                    let _task = w_tests.remove(&endpoint);
                                                    return Err(anyhow!("receve Syn replay for {} from {}",public_key, endpoint));
                                                }
                                            } else if handshake.msg_type == MsgType::SynAck {
                                                if msg == question {
                                                    println!("Receve SynAck for {} from {}",public_key,endpoint);
                                                    if count_syn_act_replay < 5 {
                                                        count_syn_act_replay += 5;
                                                        let res = Msg::new(None,Some(msg.question));
                                                        match Handcheck::new(MsgType::Ack, res, &public_key, &private_key) {
                                                            Ok(ok) => {
                                                                match serde_bencode::to_bytes(&ok) {
                                                                    Ok(snd_responce) => {
                                                                        let result = inet_socket.send(&snd_responce).await;
                                                                        match result {
                                                                            Ok(_) => {
                                                                                println!("Send Ack for {} to {}",public_key, endpoint);
                                                                                match tx.send(endpoint).await {
                                                                                    Ok(_) => {
                                                                                        let mut w_tests = test.write().await;
                                                                                        let _task = w_tests.remove(&endpoint);
                                                                                        return Ok(());
                                                                                    }
                                                                                    Err(err) => {
                                                                                        println!("send error in new_check for {} to {} with {}",public_key, endpoint,err);
                                                                                        let mut w_tests = test.write().await;
                                                                                        let _task = w_tests.remove(&endpoint);
                                                                                        return Err(anyhow!(err));
                                                                                    }
                                                                                }
                                                                            },
                                                                            Err(err) => {
                                                                                println!("send Ack error in new_check for {} to {} with {}",public_key, endpoint,err);
                                                                                let mut w_tests = test.write().await;
                                                                                let _task = w_tests.remove(&endpoint);
                                                                                return Err(anyhow!("send Ack error in new_check for {} to {} with {}",public_key, endpoint,err));
                                                                            }
                                                                        }
                                                                    }
                                                                    Err(err) => {
                                                                        println!("serde_bencode error {}",err);
                                                                        continue
                                                                        // return Err(anyhow!(err));
                                                                    }

                                                                }
                                                            },
                                                            Err(err) => {
                                                                println!("Handcheck::new() error {}",err);
                                                                continue
                                                                // return Err(anyhow!(err));
                                                            },
                                                        }
                                                    } else {
                                                        println!("receve Syn/Act replay for {} from {}",public_key, endpoint);
                                                        let mut w_tests = test.write().await;
                                                        let _task = w_tests.remove(&endpoint);
                                                        return Err(anyhow!("receve Syn/Act replay for {} from {}",public_key, endpoint));
                                                    }
                                                }else {
                                                    println!("Receve Invalid SynAck in new_check for {} to {}",public_key, endpoint);
                                                    let mut w_tests = test.write().await;
                                                    let _task = w_tests.remove(&endpoint);
                                                    return Err(anyhow!("Receve Invalid SynAck in new_check for {} to {}",public_key, endpoint));
                                                }
                                            } else if handshake.msg_type == MsgType::Ack {
                                                if msg == question {
                                                    println!("Receve Ack for {} from {}",public_key,endpoint);
                                                    match tx.send(endpoint).await {
                                                        Ok(_) => {
                                                            let mut w_tests = test.write().await;
                                                            let _task = w_tests.remove(&endpoint);
                                                            return Ok(());
                                                        }
                                                        Err(err) => {
                                                            println!("send error in new_check for {} to {} with {}",public_key, endpoint,err);
                                                            let mut w_tests = test.write().await;
                                                            let _task = w_tests.remove(&endpoint);
                                                            return Err(anyhow!(err));
                                                        }
                                                    }
                                                }else {
                                                    println!("Receve Invalid Ack in new_check for {} to {}",public_key, endpoint);
                                                    let mut w_tests = test.write().await;
                                                    let _task = w_tests.remove(&endpoint);
                                                    return Err(anyhow!("Receve Invalid Ack in new_check for {} to {}",public_key, endpoint));
                                                }
                                            }else {
                                                println!("Receve Invalid message type in new_check for {} to {}",public_key, endpoint);
                                                let mut w_tests = test.write().await;
                                                let _task = w_tests.remove(&endpoint);
                                                return Err(anyhow!("Receve Invalid message type in new_check for {} to {}",public_key, endpoint));
                                            }

                                        }
                                        Err(err) => {
                                            println!("receve error in new_check for {} to {} with {}",public_key, endpoint,err);
                                            let mut w_tests = test.write().await;
                                            let _task = w_tests.remove(&endpoint);
                                            return Err(anyhow!("receve error in new_check for {} to {} with {}",public_key, endpoint,err));
                                        }

                                    }
                                }
                            },
                            _ = interval.tick() => {

                                    let result = inet_socket.send(&snd_question).await;
                                    match result {
                                        Ok(_) => {
                                            // println!("send check for {} to {}",public_key, endpoint);
                                        },
                                        Err(err) => {
                                            println!("send error in new_check for {} to {} with {}",public_key, endpoint,err);
                                            let mut w_tests = test.write().await;
                                            let _task = w_tests.remove(&endpoint);
                                            return Err(anyhow!("send error in new_check for {} to {} with {}",public_key, endpoint,err));
                                        }
                                    }


                                    if start.elapsed() > TIMEOUT {
                                            println!("check timeout for {}", endpoint);
                                            let mut w_tests = test.write().await;
                                            let _task = w_tests.remove(&endpoint);
                                            return Err(anyhow!("WgPeer::new_check() Timeout"));
                                        }
                                    }

                        }
                    }
                }));
        }
        Ok(())
    }

    //Get cheked endpoint recever
    // pub fn check_input(&self) -> Arc<RwLock<mpsc::Receiver<SocketAddr>>> {
    //     self.rx.clone()
    // }

    //Get cheked endpoint recever
    pub fn get_check_input_recever(&mut self) -> mpsc::Receiver<SocketAddr> {
        self.rx.take().unwrap()
    }
    //Set cheked endpoint recever
    pub fn set_check_input_recever(&mut self, recever : mpsc::Receiver<SocketAddr>){
        self.rx = Some(recever);
    }

    //update peer_info
    pub async fn update(&mut self) -> Result<()> {
        // println!("WgPeer::update()");
        match self
            .iface
            .get_peer(&PublicKey::new(self.wg_peer.public_key))
            .await
        {
            Ok(wg_peer) => {
                self.wg_peer = wg_peer;
                // println!(
                //     "WgPeer::update last handshake = {:?}",
                //     self.wg_peer.last_handshake_time
                // );
                return Ok(());
            }
            Err(e) => {
                // println!("WgPeer::update() error {}", e);
                Err(anyhow!("WgPeer::update() {}", e))
            }
        }
    }

    pub async fn is_connected(&mut self) -> Result<bool> {
        // println!("is_connected()");
        self.update().await?;

        let _endpoint: SocketAddr;

        if let Some(l_endpoint) = self.inet_endpoint {
            _endpoint = l_endpoint;
        } else if let Some(l_endpoint) = self.wg_peer.endpoint {
            _endpoint = l_endpoint;
        } else {
            #[cfg(debug_assertions)]
            println!(
                "WgPeer::is_connected() for {} no endpoint",
                self.public_key()
            );
            return Ok(false);
        }

        // println!("is_connected() 1");
        let now = std::time::Instant::now();
        if self.wg_peer.last_handshake_time == Duration::ZERO {
            #[cfg(debug_assertions)]
            println!(
                "WgPeer::is_connected() for {} with {} = false (ZERO)",
                self.public_key(),
                _endpoint
            );
            self.check_data = self.wg_peer.rx_bytes;
            self.check_time = now;
            Ok(false)
        } else {
            let last = SystemTime::UNIX_EPOCH + self.wg_peer.last_handshake_time;
            if self.wg_peer.rx_bytes > self.check_data {
                #[cfg(debug_assertions)]
                println!(
                    "WgPeer::is_connected() for {} with {}  = true ({} > {})",
                    self.public_key(),
                    _endpoint,
                    self.wg_peer.rx_bytes,
                    self.check_data
                );
                self.check_data = self.wg_peer.rx_bytes;
                self.check_time = now;
                Ok(true)
            } else if self.wg_peer.rx_bytes == self.check_data
                && now.duration_since(self.check_time) >= SLEEP
            {
                #[cfg(debug_assertions)]
                println!(
                    "WgPeer::is_connected() for {} with {}  = false ({} == {})",
                    self.public_key(),
                    _endpoint,
                    self.wg_peer.rx_bytes,
                    self.check_data
                );

                self.check_data = self.wg_peer.rx_bytes;
                self.check_time = now;
                Ok(false)
            } else if let Err(_e) = last.elapsed() {
                self.check_data = self.wg_peer.rx_bytes;
                self.check_time = now;
                #[cfg(debug_assertions)]
                    println!(
                        "WgPeer::is_connected() for {} with {}  = false (-{:?})",
                        self.public_key(),
                        _endpoint,
                        _e.duration()
                    );
                Ok(false)
            } else if last.elapsed().is_ok() && last.elapsed().unwrap() > Duration::from_secs(3 * 60) {
                self.check_data = self.wg_peer.rx_bytes;
                self.check_time = now;
                #[cfg(debug_assertions)]
                println!(
                    "WgPeer::is_connected() for {} with {}  = false ({:?})",
                    self.public_key(),
                    _endpoint,
                    last.elapsed().unwrap()
                );
                Ok(false)
            } else {
                #[cfg(debug_assertions)]
                println!(
                    "WgPeer::is_connected() for {} with {}  = true ({:?})",
                    self.public_key(),
                    _endpoint,
                    last.elapsed().unwrap()
                );
                self.check_data = self.wg_peer.rx_bytes;
                self.check_time = now;
                Ok(true)
            }
        }
    }

    pub async fn check_connection(&mut self) -> Result<bool> {
        self.ping().await?;
        let now = std::time::Instant::now();
        let wait = SLEEP;

        sleep(wait.saturating_sub(now.duration_since(self.check_time))).await;
        self.is_connected().await
        
    }

    pub async fn ping(&self) -> Result<()> {
        let mut o_endpoint: Option<SocketAddr> = None;
        for peer in self.wg_peer.allowed_ips.iter() { //if ip address is specified
            if peer.cidr_mask == 32 && peer.ipaddr.is_ipv4() {
                //todo: need solution if only network is specified
                // println!("peer.ipaddr = {}", peer.ipaddr);
                // println!("peer.family = {}", peer.family); //family 2 = IPV4
                o_endpoint = Some(SocketAddr::new(peer.ipaddr, 0));
                break;
            }else if peer.cidr_mask == 128 && peer.ipaddr.is_ipv6() {
                o_endpoint = Some(SocketAddr::new(peer.ipaddr, 0));
                break;
            }
        }
        
        if o_endpoint == None {
            for peer in self.wg_peer.allowed_ips.iter() { //if only netwok is specified
                if peer.ipaddr.is_ipv4() && peer.cidr_mask < 32 && !peer.ipaddr.is_unspecified() {
                    if let IpAddr::V4(address) = peer.ipaddr {
                        if address.is_link_local() {
                            continue;
                        }else {
                            let octets = address.octets();
                            let ipaddr = IpAddr::V4(Ipv4Addr::new(octets[0],octets[1],octets[2],254));
                            o_endpoint = Some(SocketAddr::new(ipaddr, 0));
                            break;
                        }
                    }
                }else if peer.ipaddr.is_ipv6() && peer.cidr_mask < 128 && !peer.ipaddr.is_unspecified() {
                    if let IpAddr::V6(address) = peer.ipaddr {
                        let mut word = [0u16;8];
                        for (i,bytes) in address.octets().chunks(2).enumerate() {
                                word[i] = ((bytes[0] as u16) << 8) | bytes[1] as u16;
                        }

                        let ipaddr = IpAddr::V6(Ipv6Addr::new(word[0],word[1],word[2],word[3],word[4],word[5],word[6],0xFFFF));
                        o_endpoint = Some(SocketAddr::new(ipaddr, 0));
                        break;
                    }
                }
            }
        }

        if o_endpoint == None {
            for peer in self.wg_peer.allowed_ips.iter() { //if only unspecified address is specified
                if peer.ipaddr.is_ipv4() && peer.cidr_mask < 32 && peer.ipaddr.is_unspecified() {
                    o_endpoint = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1,1,1,1)), 0));
                    break;
                } else if peer.ipaddr.is_ipv4() && peer.cidr_mask < 128 && peer.ipaddr.is_unspecified() {
                    o_endpoint = Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2606,0x4700,0x4700,0,0,0,0,0x1111)), 0));
                    break;
                }
            }
        }

        if let Some(endpoint) = o_endpoint {
            let wg_socket: UdpSocket;
            if let V6(_) = endpoint {
                wg_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
                    .await
                    .unwrap();
            } else {
                wg_socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
                    .await
                    .unwrap();
            }

            match wg_socket.connect(endpoint).await {
                Ok(_) => {
                    // println!("WgPeer::ping() for {}", endpoint);
                    match wg_socket.send(&[]).await {
                        Ok(_) => Ok(()),
                        Err(_err) => {
                            // println!("WgPeer::ping() socket.send() err {}", _err);
                            // Err(anyhow!("WgPeer::ping() socket.send() err {}" , _err))
                            Ok(())
                        }
                    }
                }
                Err(err) => {
                    println!("WgPeer::ping() socket.connect() err {}", err);
                    Err(anyhow!("WgPeer::ping() socket.connect() err {}", err))
                }
            }
        } else {
            println!("WgPeer::ping() endpoint not found");
            Err(anyhow!("WgPeer::ping() endpoint not found"))
        }
    }

    pub fn public_key(&self) -> PublicKey {
        return PublicKey::new(self.wg_peer.public_key);
    }

    pub async fn clean(&mut self) {
        // println!("WgPeer::clean() for {} with {:?}",self.public_key(), self.inet_endpoint);
        let mut w_test = self.tests.write().await;
        w_test.clear();
        if let Some(mut endpoint) = self.inet_endpoint.take() {
            if let V6(socket_v6) = endpoint {
                if let Some(ip_v4) = socket_v6.ip().to_ipv4() {
                    endpoint = SocketAddr::new(IpAddr::V4(ip_v4), endpoint.port());
                }
            }

            // println!("WgPeer::clean() send with {}",endpoint);
            self.iface
                .push_config(
                    PublicKey::new(self.wg_peer.public_key),
                    endpoint,
                    self.gateway.take(),
                )
                .await;
        }
        sleep(Duration::ZERO).await;
        // println!("WgPeer::clean() end");
    }
}

impl PartialEq for WgPeer {
    fn eq(&self, other: &Self) -> bool {
        self.wg_peer.public_key == other.wg_peer.public_key
    }

    fn ne(&self, other: &Self) -> bool {
        self.wg_peer.public_key != other.wg_peer.public_key
    }
}

impl Drop for WgPeer {
    fn drop(&mut self) {
        tokio::task::block_in_place(move || {
            Handle::current().block_on(async move {
                self.clean().await;
            });
        });
    }
}
