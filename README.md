# [bpf-helpers(7)](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html) tracer


## Build

1. Install `libbfd`:

```
sudo apt-get install binutils-dev
```

2. Build/install [bpftool](https://github.com/libbpf/bpftool) with `libbfd` enabled:

```
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool
cd src
make
sudo make install
```
3. Build/install [libpcap](https://github.com/the-tcpdump-group/libpcap):

```
sudo apt-get install -y curl unzip gcc flex bison make
curl https://github.com/the-tcpdump-group/libpcap/archive/refs/tags/libpcap-1.10.4.zip -OL
unzip libpcap-1.10.4.zip
cd libpcap-libpcap-1.10.4/
./configure --enable-dbus=no
make
sudo make install
```

4. Build `bpf-helpers-tracer`:

```
go build
```

## Usage

```
Usage of ./bpf-helpers-tracer:
      --deref-pointer   (optional) dereference pointer arguments
      --prog-id int     (required) only support tc-bpf program for now (default -1)
```

Some examples:

```
$ sudo bpftool prog
...
649: sched_cls  name handle_ingress  tag c0c258a151d66206  gpl
	loaded_at 2023-10-28T02:28:19+0000  uid 0
	xlated 664B  jited 411B  memlock 4096B  map_ids 279,281
	btf_id 403

$ sudo ./bpf-helpers-tracer --prog-id 649
Start tracing
ffff961d003ffae0 bpf_prog_c0c258a151d66206_handle_ingress+0 (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv6=::1>::1 TCP=16443>40840[.F])
ffff961d003ffae0 bpf_prog_c0c258a151d66206_handle_ingress+r (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv6=::1>::1 TCP=16443>40840[.F])
ffff961d03a1cb00 bpf_prog_c0c258a151d66206_handle_ingress+0 (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv6=::1>::1 TCP=40840>16443[.R])
ffff961d03a1cb00 bpf_prog_c0c258a151d66206_handle_ingress+r (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv6=::1>::1 TCP=40840>16443[.R])
ffff961d003ffae0 bpf_prog_c0c258a151d66206_handle_ingress+0 (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv4=127.0.0.1>127.0.0.1 TCP=16443>60972[.F])
ffff961d003ffae0 bpf_prog_c0c258a151d66206_handle_ingress+r (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv4=127.0.0.1>127.0.0.1 TCP=16443>60972[.F])
ffff961d03a1cb00 bpf_prog_c0c258a151d66206_handle_ingress+0 (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv4=127.0.0.1>127.0.0.1 TCP=60972>16443[.R])
ffff961d03a1cb00 bpf_prog_c0c258a151d66206_handle_ingress+r (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv4=127.0.0.1>127.0.0.1 TCP=60972>16443[.R])
...
^C
```

```
$ sudo ./bpf-helpers-tracer --prog-id 649 'host 127.0.0.1 and tcp[tcpflags] = tcp-syn'
Start tracing
ffff961c01397ee0 bpf_prog_c0c258a151d66206_handle_ingress+0 (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv4=127.0.0.1>127.0.0.1 TCP=42750>9099[S])
ffff961c01397ee0 bpf_prog_c0c258a151d66206_handle_ingress+r (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv4=127.0.0.1>127.0.0.1 TCP=42750>9099[S])
ffff961c013a58e0 bpf_prog_c0c258a151d66206_handle_ingress+0 (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv4=127.0.0.1>127.0.0.1 TCP=42762>9099[S])
ffff961c013a58e0 bpf_prog_c0c258a151d66206_handle_ingress+r (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv4=127.0.0.1>127.0.0.1 TCP=42762>9099[S])
ffff961d07f37ee0 bpf_prog_c0c258a151d66206_handle_ingress+0 (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv4=127.0.0.1>127.0.0.1 TCP=48360>9099[S])
ffff961d07f37ee0 bpf_prog_c0c258a151d66206_handle_ingress+r (Mark=0 | Ethernet=00:00:00:00:00:00>00:00:00:00:00:00 IPv4=127.0.0.1>127.0.0.1 TCP=48360>9099[S])
```
