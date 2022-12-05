use std::{
    io::{BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    time::SystemTime,
};

use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::Result;
use bytes::BytesMut;
use grammers_mtproto::transport::{Abridged, Transport};
use grammers_tl_types::{Cursor, Deserializable, Serializable};
use log::{debug, error};

type Aes256Ctr64Be = ctr::Ctr64BE<aes::Aes256>;
const SERVER_NONCE: [u8; 16] = 0x1337u128.to_le_bytes();

fn main() {
    pretty_env_logger::init();

    let listener = TcpListener::bind("127.0.0.1:11337").unwrap();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        if let Err(e) = handle_connection(stream) {
            for e in e.chain() {
                error!("{}", e);
            }
        }
    }
}

#[allow(clippy::unused_io_amount)]
fn handle_connection(mut stream: TcpStream) -> Result<()> {
    // Init connection
    let mut buf_reader = BufReader::new(&mut stream);
    let mut init = [0; 64];
    let mut encrypted_init = [0; 8];
    let mut packet_len = [0; 1];
    buf_reader.by_ref().take(56).read(&mut init)?;
    buf_reader.read_exact(&mut encrypted_init)?;
    buf_reader.read_exact(&mut packet_len)?;
    debug!("init: {:02x?}", init);
    debug!("encrypted_init: {:02x?}", encrypted_init);
    debug!("packet_len: {:02x?}", packet_len);

    let encrypt_key: Vec<u8> = init.into_iter().skip(8).take(32).collect();
    let encrypt_iv: Vec<u8> = init.into_iter().skip(40).take(16).collect();
    debug!("encrypt_key: {:02x?}", encrypt_key);
    debug!("encrypt_iv: {:02x?}", encrypt_iv);

    let decrypt_key: Vec<u8> = init.into_iter().rev().skip(8).take(32).collect();
    let decrypt_iv: Vec<u8> = init.into_iter().rev().skip(40).take(16).collect();
    debug!("decrypt_key: {:02x?}", decrypt_key);
    debug!("decrypt_iv: {:02x?}", decrypt_iv);

    let mut cipher =
        Aes256Ctr64Be::new(encrypt_key.as_slice().into(), encrypt_iv.as_slice().into());
    cipher.apply_keystream(&mut init);
    debug!("init: {:02x?}", init);

    // ReqPqMulti
    cipher.apply_keystream(&mut packet_len);
    debug!("packet_len: {:02x?}", packet_len);
    let packet_len = packet_len[0] as usize * 4;

    let mut packet = vec![0; packet_len];
    buf_reader.read(&mut packet)?;
    cipher.apply_keystream(&mut packet);
    debug!("packet: {:02x?}", packet);

    let mut cur = Cursor::from_slice(&packet);
    let req_pq_multi = ReqPqMulti::parse(&mut cur)?;
    debug!("req_pq_multi: {:02x?}", req_pq_multi);

    // ResPq
    let res_pq = ResPq::generate(
        req_pq_multi.nonce,
        0x17ED48941A08F981u64.to_le_bytes().into_iter().collect(),
        // 0x0u64.to_le_bytes().into_iter().collect(), // SIGFPE
    );
    let mut res_pq_mtproto = BytesMut::new();
    Abridged::new().pack(&res_pq.ser(), &mut res_pq_mtproto);
    let _ = res_pq_mtproto.split_to(1);
    debug!("res_pq: {:02x?}", res_pq);
    debug!("res_pq_mtproto: {:02x?}", res_pq_mtproto.to_vec());

    let mut encryptor =
        Aes256Ctr64Be::new(decrypt_key.as_slice().into(), decrypt_iv.as_slice().into());
    encryptor.apply_keystream(&mut res_pq_mtproto);
    stream.write_all(&res_pq_mtproto)?;

    // ReqDHParams

    // debug!("answer: {:02x?}", {
    //     let mut buf = Vec::new();
    //     stream.read_to_end(&mut buf)?;
    //     buf
    // });

    Ok(())
}

#[allow(dead_code)]
#[derive(Debug)]
struct ReqPqMulti {
    auth_key_id: i64,
    message_id: i64,
    message_length: u32,
    magic: u32,
    nonce: [u8; 16],
}

impl ReqPqMulti {
    fn parse(cur: &mut Cursor) -> Result<Self> {
        Ok(ReqPqMulti {
            auth_key_id: i64::deserialize(cur)?,
            message_id: i64::deserialize(cur)?,
            message_length: u32::deserialize(cur)?,
            magic: u32::deserialize(cur)?,
            nonce: <[u8; 16]>::deserialize(cur)?,
        })
    }
}

#[derive(Debug)]
struct ResPq {
    auth_key_id: i64,
    message_id: i64,
    message_length: u32,
    magic: u32,
    nonce: [u8; 16],
    server_nonce: [u8; 16],
    pq: Vec<u8>,
    server_public_key_fingerprints: Vec<i64>,
}

impl ResPq {
    #[allow(overflowing_literals)]
    fn generate(nonce: [u8; 16], pq: Vec<u8>) -> Self {
        ResPq {
            auth_key_id: 0,
            message_id: (SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()) as i64,
            message_length: 0,
            magic: 0x05162463,
            nonce,
            server_nonce: SERVER_NONCE,
            pq,
            server_public_key_fingerprints: vec![0xd09d1d85de64fd85],
        }
    }

    fn ser(&self) -> Vec<u8> {
        let mut res = Vec::new();
        self.auth_key_id.serialize(&mut res);
        self.message_id.serialize(&mut res);
        self.message_length.serialize(&mut res);
        self.magic.serialize(&mut res);
        self.nonce.serialize(&mut res);
        self.server_nonce.serialize(&mut res);
        self.pq.serialize(&mut res);
        self.server_public_key_fingerprints.serialize(&mut res);
        res
    }
}
