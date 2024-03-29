/*
Copyright (C) 2024 Pierre-Emmanuel DOUET

This file is part of wg-turn.
wg-turn is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

wg-turn is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with wg-turn. If not, see <https://www.gnu.org/licenses/>.
*/

use anyhow::anyhow;
use anyhow::Result;
use base64::prelude::*;
use blake3::Hash;
use concat_arrays::concat_arrays;
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{ChaChaBox, Nonce, SecretKey};
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use socket2;
use std::convert::From;
use std::convert::Into;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use tokio::net;
use tokio::net::UdpSocket;
use tokio::task;
use tokio::task::JoinError;

#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn new_reuse_udp_socket(address: IpAddr, port: u16) -> Result<UdpSocket> {
    let socket: socket2::Socket;

    match address {
        IpAddr::V4(_) => {
            socket =
                socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap()
        }
        IpAddr::V6(_) => {
            socket =
                socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None).unwrap()
        }
    }
    let _ = socket.set_reuse_address(true);
    socket.set_nonblocking(true).unwrap();
    let socket_address: SocketAddr = SocketAddr::new(address, port);
    let socket_address = socket_address.into();
    socket.bind(&socket_address)?;

    let sync_socket = std::net::UdpSocket::from(
        <std::net::UdpSocket as Into<socket2::Socket>>::into(socket.into()),
    );
    Ok(net::UdpSocket::from_std(sync_socket)?)
}

pub struct Abort<T> {
    task: task::JoinHandle<T>,
}

#[cfg(debug_assertions)]
static COUNTER: AtomicUsize = AtomicUsize::new(0);

impl<T: Send + 'static> Abort<T> {
    pub fn spawn<F>(future: F) -> Abort<T>
    where
        F: tokio::macros::support::Future<Output = T> + Send + 'static,
    {
        #[cfg(debug_assertions)]
        {
            COUNTER.fetch_add(1, Ordering::Relaxed);
            println! {"Abort::spawn() counter = {}", COUNTER.load(Ordering::Relaxed)}
        }

        Abort {
            task: task::spawn(future),
        }
    }
}

impl<T> Drop for Abort<T> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            COUNTER.fetch_sub(1, Ordering::Relaxed);
            println! {"Abort::drop() counter = {}", COUNTER.load(Ordering::Relaxed)}
        }
        self.task.abort()
    }
}

use std::ops::Deref;

impl<T> Deref for Abort<T> {
    type Target = task::JoinHandle<T>;

    fn deref(&self) -> &Self::Target {
        &self.task
    }
}

use futures::task::Context;
use tokio::macros::support::Pin;
use tokio::macros::support::Poll;

impl<T> Future for Abort<T> {
    type Output = Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let task = Pin::new(&mut self.task);
        Future::poll(task, cx)
    }
}

#[derive(Serialize, Deserialize, PartialEq)]
pub enum MsgType {
    Syn,
    SynAck,
    Ack,
}

//send crypted data structure
#[derive(Serialize, Deserialize)]
pub struct Handcheck {
    pub msg_type: MsgType,
    nonce: Nonce,
    ciphertext: Vec<u8>,
}

impl Handcheck {
    pub fn new(
        msg_type: MsgType,
        msg: Msg,
        public_key: &PublicKey,
        private_key: &SecretKey,
    ) -> Result<Handcheck> {
        match msg.encrypt(public_key, private_key) {
            Ok((nonce, ciphertext)) => Ok(Handcheck {
                msg_type,
                nonce,
                ciphertext,
            }),
            Err(err) => Err(err),
        }
    }

    pub fn decrypt(&self, public_key: &PublicKey, private_key: &SecretKey) -> Result<Msg> {
        match Msg::decrypt(public_key, private_key, &self) {
            Ok(msg) => Ok(msg),
            Err(err) => Err(err),
        }
    }
}

//send data structure
#[derive(Serialize, Deserialize, PartialEq)]
pub struct Msg {
    pub question: [u8; 32],
    pub response: Hash,
}

impl Msg {
    pub fn new(question: Option<[u8; 32]>, response: Option<[u8; 32]>) -> Self {
        let msg_q: [u8; 32];
        if let Some(s) = question {
            msg_q = s;
        } else {
            msg_q = random();
        }

        let msg_r: Hash;
        if let Some(s) = response {
            msg_r = blake3::hash(&s);
        } else {
            let r: [u8; 32] = random();
            msg_r = blake3::hash(&r);
        }

        Msg {
            question: msg_q,
            response: msg_r,
        }
    }

    pub fn decrypt(
        public_key: &PublicKey,
        private_key: &SecretKey,
        msg: &Handcheck,
    ) -> Result<Self> {
        let chacha_box = ChaChaBox::new(public_key, private_key);
        match chacha_box.decrypt(&msg.nonce, &msg.ciphertext[..]) {
            Ok(data) => Ok(serde_bencode::from_bytes(&data[..])?),
            Err(err) => Err(anyhow!(err)),
        }
    }

    pub fn encrypt(
        &self,
        public_key: &PublicKey,
        private_key: &SecretKey,
    ) -> Result<(Nonce, Vec<u8>)> {
        let chacha_box = ChaChaBox::new(public_key, private_key);
        let nonce = ChaChaBox::generate_nonce(&mut OsRng);
        let message = serde_bencode::to_bytes(self)?;
        match chacha_box.encrypt(&nonce, &message[..]) {
            Ok(ciphertext) => Ok((nonce, ciphertext)),
            Err(err) => Err(anyhow!(err)),
        }
    }
}

impl PartialEq<[u8; 32]> for Msg {
    fn eq(&self, other: &[u8; 32]) -> bool {
        self.response == blake3::hash(other)
    }
}

#[derive(Eq, Hash, PartialEq, Clone)]
pub struct PublicKey(crypto_box::PublicKey);

impl PublicKey {
    pub fn new(data: [u8; 32]) -> PublicKey {
        PublicKey(crypto_box::PublicKey::from_bytes(data))
    }

    pub fn array(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(item: [u8; 32]) -> Self {
        PublicKey(crypto_box::PublicKey::from_bytes(item))
    }
}

impl From<&[u8; 32]> for PublicKey {
    fn from(item: &[u8; 32]) -> Self {
        PublicKey(crypto_box::PublicKey::from_bytes(*item))
    }
}

impl From<crypto_box::PublicKey> for PublicKey {
    fn from(item: crypto_box::PublicKey) -> Self {
        PublicKey(item)
    }
}

impl Deref for PublicKey {
    type Target = crypto_box::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<[u8]> for PublicKey
where
    <PublicKey as Deref>::Target: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.deref().as_ref()
    }
}

impl PartialEq<[u8; 32]> for PublicKey {
    fn eq(&self, other: &[u8; 32]) -> bool {
        self.0.to_bytes() == *other
    }

    fn ne(&self, other: &[u8; 32]) -> bool {
        self.0.to_bytes() != *other
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0.as_bytes()))
    }
}

pub fn calc_id(pub_key1: &[u8; 32], pub_key2: &[u8; 32], psk: &[u8; 32]) -> [u8; 64] {
    // let psk_sha: [u8; 20] = Sha1::digest(psk).into();
    // let mut add_array = [0u8; 32];
    // for ((add_val, l_val), r_val) in add_array.iter_mut().zip(pub_key1).zip(pub_key2) {
    //     *add_val = u8::wrapping_add(*l_val, *r_val);
    // }
    // concat_arrays!(add_array, psk_sha)

    let psk_hash = *blake3::hash(psk).as_bytes();
    let pub_key1_hash = *blake3::hash(pub_key1).as_bytes();
    let pub_key2_hash = *blake3::hash(pub_key2).as_bytes();
    let mut add_array = [0u8; 32];
    for ((add_val, l_val), r_val) in add_array.iter_mut().zip(pub_key1_hash).zip(pub_key2_hash) {
        *add_val = u8::wrapping_add(l_val, r_val);
    }

    concat_arrays!(add_array, psk_hash)
}
