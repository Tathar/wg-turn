/*
Copyright (C) 2024 Pierre-Emmanuel DOUET

This file is part of wg-turn.
wg-turn is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

wg-turn is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with wg-turn. If not, see <https://www.gnu.org/licenses/>.
*/


// use dht_handler;
use crate::utils::PublicKey;

use crate::dht::dht_handler;
use crate::dht::dht_handler::DhtCommand;
use std::net::SocketAddr;
use tokio::{sync::mpsc,task};
use tokio::sync;

#[derive(Clone)]
pub struct DHT {
    send: mpsc::UnboundedSender<DhtCommand>,
}

// pub struct DHT {
//     dht4: Arc<MainlineDht>,
//     dht6: Arc<MainlineDht>,
//     pub_key: Option<PublicKey>,
//     tasks: RwLock<Vec<Abort<()>>>,
// }

impl DHT {
    pub async fn new(port: u16, pub_key: PublicKey) -> DHT {
        
        let (send, rcv) = mpsc::unbounded_channel();

        let handler = dht_handler::DhtHandler::new(port, pub_key, rcv).await;

        task::spawn(handler.run());

        DHT {
            send
        }
    }

    pub async fn register(&self, pub_key: &PublicKey) -> mpsc::Receiver<SocketAddr> {
        let (snd, rcv) = sync::oneshot::channel();

        self.send.send(DhtCommand::Register(pub_key.clone(), snd)).unwrap();

        match rcv.await {
            Ok(ret) => ret,
            Err(_) => panic!(),
        }
    }
}

impl Drop for DHT {
    fn drop(&mut self) {
        println! {"drop DHT"};
    }
}
