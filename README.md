# 配置环境
使用Cloudlab。需要创建两个节点，Node0为c6525-25g，Node1可以根据Resource availability选择。

# 编译Kernel
下载[这个repo](https://github.com/ONCache-VM/linux/tree/6.15) (分支6.15)，使用[这个.config文件](https://github.com/ONCache-VM/xskgen/blob/main/.config)编译。
```
make -j16
make deb-pkg
scp -i <your-priv-key> ../*<build-number>*.deb <node0>:~
```

上传xskgen
```
scp -i <your-priv-key> xskgen <node0>:~
```

Node0上
```
sudo apt install -y libxdp-dev
sudo dpkg -i *<build-number>*.deb
sudo reboot
```

等重启后，进入`xskgen`并`make`。

# 启动
Usage of xskgen:
```
xskgen [OPTS] <ifname> <src mac> <dst mac> <src ip> <dst ip> <src port> <dst port>
    OPTS:
    -b    run in busy polling mode
    -B    number of packets to submit at the same time
    -c    run in copy mode
    -C    do _not_ request checksum offload
    -d    debug mode: single packet, sleep between them
    -q    rx-tx queue number
    -r    don't install dummy xdp (rx) program
    -R    number of entries in fill/comp/rx/tx rings (per ring)
    -m    request tx offloads
    -M    fill tx offloads but don't set XDP_TX_METADATA
    -l    stop after sending given number of packets
    -s    packet payload size (1400 is default)
    -T    do _not_ request tx timestamp
    -U    number of entries in umem
    -g    disable GSO offload
```

先获取Node0和Node1的mac地址。

## 发包
**batch_size=1，发送10个包，每个包大小为1800**
Node0 window 1:
```
sudo ethtool -L enp65s0f0np0 combined 1
sudo ethtool --set-priv-flags enp65s0f0np0 xdp_tx_mpwqe off
cd xskgen
sudo ./xskgen -d -l 10 -B 1 -m -s 1800 enp65s0f0np0 <mac0> <mac1> 10.10.1.1 10.10.1.2 6000 6000
```

Node0 window 2:
```
sudo dmesg -w
```

Node1:
```
sudo tcpdump -i <eth> udp -XX -vvv -nn
```

Ctrl+C可以看到tcpdump收到包的数量。

**batch_size=1，发送2000个包，每个包大小为1800。此时观察kernel output，出现报错。从cloudlab上的console log可以看到全部错误信息。**
Node0:
```
sudo ./xskgen -d -l 2000 -B 1 -m -s 1800 enp65s0f0np0 <mac0> <mac1> 10.10.1.1 10.10.1.2 6000 6000
```
