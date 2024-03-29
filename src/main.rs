/*
Copyright (C) 2024 Pierre-Emmanuel DOUET

This file is part of wg-turn.
wg-turn is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

wg-turn is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with wg-turn. If not, see <https://www.gnu.org/licenses/>.
*/

mod dht;
mod task;
mod utils;
mod wg;

use std::time::Duration;
use tokio::signal::unix::{signal, SignalKind};
use tokio::task::JoinSet;
use wg::WgDevice;

// #[async_std::main]
#[tokio::main]
async fn main() {
    println!("wg-turn v1.0.0");
    let mut tasks = JoinSet::new();

    let mut route = wireguard_uapi::linux::RouteSocket::connect().unwrap();
    if let Ok(devices) = route.list_device_names() {
        for device in devices {
            if device.contains("wg-turn") {
                tasks.spawn(task::interface_task(device.clone()));
            }
            if device.contains("wg_turn") {
                tasks.spawn(task::interface_task(device.clone()));
            }
        }
    }

    if tasks.len() == 0 {
        println!("interface not fond");
        return;
    }

    let mut sig_int = signal(SignalKind::interrupt()).unwrap();
    let mut sig_hangup = signal(SignalKind::hangup()).unwrap();
    let mut sig_quit = signal(SignalKind::quit()).unwrap();
    let mut sig_term = signal(SignalKind::terminate()).unwrap();

    tokio::select! {
        _ = sig_int.recv() => println!("ctrl-c pressed"),
        _ = sig_hangup.recv() =>println!("HANGUP receve"),
        _ = sig_quit.recv() =>println!("QUIT receve"),
        _ = sig_term.recv() =>println!("TERM receve"),
    }

    tasks.abort_all();
    while let Some(_) = tasks.join_next().await {
        tokio::time::sleep(Duration::ZERO).await;
    }

    while !WgDevice::all_close() {
        tokio::time::sleep(Duration::ZERO).await;
    }
}
