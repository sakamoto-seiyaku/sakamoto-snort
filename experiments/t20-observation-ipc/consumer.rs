use std::ffi::{c_char,c_void,CString};
use std::time::Duration;
extern "C" {
    fn ipc_open(p:*const c_char,fd:i32,g:u64,create:i32)->*mut c_void;
    fn ipc_read(h:*mut c_void,c:u32,limit:usize,f:extern "C" fn(*const u8,usize,*mut c_void),arg:*mut c_void)->usize;
    fn ipc_wait(h:*mut c_void)->i32;
    fn ipc_wait_race(h:*mut c_void)->i32;
    fn ipc_done(h:*mut c_void)->i32;
    fn ipc_report(h:*mut c_void,role:*const c_char);
    fn ipc_close(h:*mut c_void);
    fn ipc_now()->u64;
    fn ipc_cpu()->u64;
}
#[derive(Default)]
struct Channel {count:u64,sum:u64,xor:u64,bytes:u64,last:u64}
struct State {generation:u64,channel:usize,channels:[Channel;2],bad:u64,latency:Vec<u64>,crash:bool,boundary:bool}
fn u32_at(b:&[u8],n:usize)->u32 {u32::from_le_bytes(b[n..n+4].try_into().unwrap())}
fn u64_at(b:&[u8],n:usize)->u64 {u64::from_le_bytes(b[n..n+8].try_into().unwrap())}
extern "C" fn receive(p:*const u8,n:usize,arg:*mut c_void) {
    let s=unsafe{&mut *(arg as *mut State)};
    if !(128..=2048).contains(&n) {s.bad+=1;return;}
    let b=unsafe{std::slice::from_raw_parts(p,n)};
    let seq=u64_at(b,16);let shape=if seq%10<7{0}else if seq%10<9{1}else{2};
    if s.crash {
        // Exit inside the borrow, before the C queue releases this record.
        println!("{{\"role\":\"consumer_crash\",\"generation\":{},\"seen_sequence\":{}}}",s.generation,seq);
        std::process::exit(42);
    }
    let expected=if s.boundary {[128,129,255,256,511,512,513,1023,1024,2047,2048][(seq as usize-1)%11]}else{[128,512,2048][shape]};
    let c=&mut s.channels[s.channel];
    if u32_at(b,0)!=1 || u32_at(b,4) as usize!=n || expected!=n ||
       u64_at(b,8)!=s.generation || seq<=c.last || u64_at(b,32)!=seq/10+1 ||
       u64_at(b,40)!=seq*1500 || u64_at(b,48)!=seq*2 ||
       u32_at(b,56) as usize!=shape || u32_at(b,60) as usize!=s.channel ||
       b[64..].iter().enumerate().any(|(i,x)|*x!=(seq*17+(i as u64+64)*13+s.generation) as u8) {
        s.bad+=1;
    }
    c.last=seq;c.count+=1;c.sum=c.sum.wrapping_add(seq);c.xor^=seq;c.bytes+=n as u64;
    s.latency.push(unsafe{ipc_now()}.saturating_sub(u64_at(b,24)));
}
fn main() {
    let a:Vec<String>=std::env::args().collect(); if a.len()!=6 {std::process::exit(2);}
    let generation=a[3].parse::<u64>().unwrap();let batch=a[4].parse::<usize>().unwrap();
    let path=CString::new(a[1].as_str()).unwrap();
    let fd=a[2].parse().unwrap();
    // An independent attachment with wrong generation must fail before reading.
    let stale=unsafe{ipc_open(path.as_ptr(),fd,generation+1,0)};
    if !stale.is_null(){std::process::exit(7);}
    let h=unsafe{ipc_open(path.as_ptr(),fd,generation,0)};
    if h.is_null(){std::process::exit(3);}
    let mut s=State{generation,channel:0,channels:Default::default(),bad:0,latency:Vec::new(),crash:a[5]=="crash",boundary:a[5]=="boundary"};
    let wall=unsafe{ipc_now()};let cpu=unsafe{ipc_cpu()};let mut wait_error=0;
    if a[5]=="pause" {std::thread::sleep(Duration::from_millis(700));}
    if a[5]=="stopped" {std::process::exit(0);}
    let mut finished=false;
    loop {
        let mut n=0;
        for c in 0..2 {
            if a[5]=="isolation" && c==1 {continue;}
            s.channel=c;
            n+=unsafe{ipc_read(h,c as u32,batch,receive,&mut s as *mut _ as *mut c_void)};
        }
        if n>0 {continue;}
        if finished {break;}
        if unsafe{ipc_done(h)}!=0 {finished=true;continue;}
        let rc=unsafe{if a[5]=="wake_race"{ipc_wait_race(h)}else{ipc_wait(h)}};
        if rc!=0 {wait_error+=1;break;}
    }
    let used=unsafe{ipc_cpu()}-cpu;let elapsed=unsafe{ipc_now()}-wall;
    s.latency.sort_unstable();
    let quantile=|p:usize|s.latency.get(s.latency.len().saturating_sub(1)*p/100).copied().unwrap_or(0);
    println!("{{\"role\":\"consumer_result\",\"wall_ns\":{},\"cpu_ns\":{},\"bad\":{},\"wait_error\":{},\"stale_rejected\":true,\"latency_p50_ns\":{},\"latency_p95_ns\":{},\"latency_p99_ns\":{},\"latency_max_ns\":{},\"channels\":[{}]}}",elapsed,used,s.bad,wait_error,quantile(50),quantile(95),quantile(99),quantile(100),s.channels.iter().map(|c|format!("{{\"count\":{},\"sum\":{},\"xor\":{},\"bytes\":{}}}",c.count,c.sum,c.xor,c.bytes)).collect::<Vec<_>>().join(","));
    unsafe{ipc_report(h,c"consumer".as_ptr());ipc_close(h);}
    if s.bad>0 || wait_error>0{std::process::exit(6);}
}
