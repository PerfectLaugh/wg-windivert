# WG-WinDivert
Go VPN partially by only proxying specified process name in WireGuard, in Windows.

# How to install
Install Golang, then execute following command to build wg-windivert.

```
go get https://github.com/PerfectLaugh/wg-windivert
```

The following is the usage:

```
Usage of wg-windivert.exe:
  -endpoint string
        Server Endpoint
  -ipv4 string
        Internal IPv4 in WireGuard (default "0.0.0.0")
  -ipv6 string
        Internal IPv6 in WireGuard (default "::")
  -name string
        Target Process Name(s)
  -privkey string
        Client Private Key
  -pubkey string
        Server Public Key
```

Please notice that you need to put [WinDivert](https://reqrypt.org/windivert.html) binaries (including driver) in executable directory, then execute with administrator privilieges.
