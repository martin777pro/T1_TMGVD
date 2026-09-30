# T1_TMGVD

## Compilar

```bash
g++ -O2 -std=c++17 -o sketch_ventana codigo/sketch_ventana.cpp
```

## Uso

```bash
./sketch_ventana traza.bin --key dst -d 5 -w 1024 --query <IP> --out est.csv
```

## Experimentos

```bash
./codigo/experimentos.sh traza.bin salida
```

- Traza: https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz
- Semilla de los ataques: 42
