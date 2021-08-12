# packet-sniffer

Reads all packets sent to a given network interface (NIC) and dumps them on the console.

## Usage

```bash
mvn clean package
sudo java -jar target/app.jar lo0
```

The first argument is the interface name, default value is `en0`.