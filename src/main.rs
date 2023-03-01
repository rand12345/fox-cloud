use crc16::*;
use futures::FutureExt;
use getopts::Options;
use log::warn;
use std::env;
use std::io::{Cursor, Error, ErrorKind};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use crate::decoder::Middleware;
mod decoder;

type BoxedError = Box<dyn std::error::Error + Sync + Send + 'static>;
static DEBUG: AtomicBool = AtomicBool::new(false);
const BUF_SIZE: usize = 1024;

fn print_usage(program: &str, opts: Options) {
    let program_path = std::path::PathBuf::from(program);
    let program_name = program_path.file_stem().unwrap().to_string_lossy();
    let brief = format!(
        "Usage: {} REMOTE_HOST:PORT [-b BIND_ADDR] [-l LOCAL_PORT]",
        program_name
    );
    print!("{}", opts.usage(&brief));
}

#[tokio::main]
async fn main() -> Result<(), BoxedError> {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt(
        "b",
        "bind",
        "The address on which to listen for incoming requests, defaulting to 0.0.0.0",
        "BIND_ADDR",
    );
    opts.optopt(
        "l",
        "local-port",
        "The local port to which tcpproxy should bind to, randomly chosen otherwise",
        "LOCAL_PORT",
    );
    opts.optflag("d", "debug", "Enable debug mode");

    let matches = match opts.parse(&args[1..]) {
        Ok(opts) => opts,
        Err(e) => {
            eprintln!("{}", e);
            print_usage(&program, opts);
            std::process::exit(-1);
        }
    };
    let remote = match matches.free.len() {
        1 => matches.free[0].as_str(),
        _ => {
            print_usage(&program, opts);
            std::process::exit(-1);
        }
    };

    if !remote.contains(':') {
        eprintln!("A remote port is required (REMOTE_ADDR:PORT)");
        std::process::exit(-1);
    }

    DEBUG.store(matches.opt_present("d"), Ordering::Relaxed);
    // let local_port: i32 = matches.opt_str("l").unwrap_or("0".to_string()).parse()?;
    let local_port: i32 = matches.opt_str("l").map(|s| s.parse()).unwrap_or(Ok(0))?;
    let bind_addr = match matches.opt_str("b") {
        Some(addr) => addr,
        None => "0.0.0.0".to_owned(),
    };

    forward(&bind_addr, local_port, remote).await
}

async fn forward(bind_ip: &str, local_port: i32, remote: &str) -> Result<(), BoxedError> {
    // Listen on the specified IP and port
    let bind_addr = if !bind_ip.starts_with('[') && bind_ip.contains(':') {
        // Correctly format for IPv6 usage
        format!("[{}]:{}", bind_ip, local_port)
    } else {
        format!("{}:{}", bind_ip, local_port)
    };
    println!("Remote TCP: {bind_addr}");
    let bind_sock = match bind_addr.parse::<std::net::SocketAddr>() {
        Ok(b) => b,
        Err(e) => panic!("Failed to connect to bind address. {e:?}"),
    };
    let listener = TcpListener::bind(&bind_sock).await?;
    println!(
        "Listening on {}, Bound to {:?}",
        listener.local_addr().unwrap(),
        bind_sock
    );

    // We have either been provided an IP address or a host name.
    let remote = std::sync::Arc::new(remote.to_string());
    async fn read_cloud_send_and_forward<R, W>(
        read: &mut R,
        write: &mut W,
        mut abort: broadcast::Receiver<()>,
    ) -> tokio::io::Result<usize>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut copied = 0;
        let mut buf = [0u8; BUF_SIZE];
        loop {
            let bytes_read;
            tokio::select! {
                biased;

                result = read.read(&mut buf) => {
                    bytes_read = result?;
                },
                _ = abort.recv() => {
                    eprintln!("Abort");
                    break;
                }
            }

            if bytes_read == 0 {
                break;
            }

            match Middleware::new(&buf[0..bytes_read]) {
                Ok(decoded) => {
                    println!("Inv << Fox {:02x?}", decoded.raw);
                    println!("Inv << Fox {:02x?}", decoded.modbus);
                }
                Err(e) => eprintln!("{e:?}"),
            }
            write.write_all(&buf[0..bytes_read]).await?;
            copied += bytes_read;
        }
        Ok(copied)
    }

    async fn read_inv_send_and_forward<R, W>(
        read: &mut R,
        write: &mut W,
        mut abort: broadcast::Receiver<()>,
    ) -> tokio::io::Result<usize>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut copied = 0;
        let mut buf = [0u8; BUF_SIZE];
        loop {
            let bytes_read;
            tokio::select! {
                biased;

                result = read.read(&mut buf) => {
                    bytes_read = result?;
                },
                _ = abort.recv() => {
                    eprintln!("Abort");
                    break;
                }
            }

            if bytes_read == 0 {
                break;
            }

            match Middleware::new(&buf[0..bytes_read]) {
                Ok(decoded) => {
                    println!("Inv >> Fox {:02x?}", decoded.modbus);
                }
                Err(e) => eprintln!("{e:?}"),
            }
            write.write_all(&buf[0..bytes_read]).await?;
            copied += bytes_read;
        }
        Ok(copied)
    }

    loop {
        let remote = remote.clone();
        let (mut client, client_addr) = listener.accept().await?;

        tokio::spawn(async move {
            let mut remote = match TcpStream::connect(remote.as_str()).await {
                Ok(s) => s,
                Err(e) => panic!("{e:?}"),
            };
            println!("New connection from {}", client_addr);
            // Establish connection to upstream for each incoming client connection

            println!("Connected to {remote:?}");
            let (mut client_read, mut client_write) = client.split();
            let (mut remote_read, mut remote_write) = remote.split();

            let (cancel, _) = broadcast::channel::<()>(1);
            loop {
                let (remote_copied, client_copied) = tokio::join! {


                    read_cloud_send_and_forward(&mut remote_read, &mut client_write, cancel.subscribe())
                        .then(|r| { let _ = cancel.send(()); async { r } }),
                    read_inv_send_and_forward(&mut client_read, &mut remote_write, cancel.subscribe())
                        .then(|r| { let _ = cancel.send(()); async { r } }),
                };

                match client_copied {
                    Ok(count) => {
                        if DEBUG.load(Ordering::Relaxed) {
                            eprintln!(
                                "Transferred {} bytes from remote client {} to upstream server",
                                count, client_addr
                            );
                        }
                    }
                    Err(err) => {
                        eprintln!(
                            "Error writing bytes from remote client {} to upstream server",
                            client_addr
                        );
                        eprintln!("{}", err);
                    }
                };

                match remote_copied {
                    Ok(count) => {
                        if DEBUG.load(Ordering::Relaxed) {
                            eprintln!(
                                "Transferred {} bytes from upstream server to remote client {}",
                                count, client_addr
                            );
                        }
                    }
                    Err(err) => {
                        eprintln!(
                            "Error writing from upstream server to remote client {}!",
                            client_addr
                        );
                        eprintln!("{}", err);
                    }
                };
            }
            let r: Result<(), BoxedError> = Ok(());
            r
        });
    }
}
