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
python3 codigo/analisis.py salida resultados
```

- `experimentos.sh` deja en `salida/` las trazas con ataque, los JSON de los ataques y los CSV exactos y estimados.
- `analisis.py` lee `salida/` y deja en `resultados/` las figuras y las tablas. Requiere pandas y matplotlib.
- Traza: https://mawi.wide.ad.jp/mawi/samplepoint-F/2018/201812031400.pcap.gz
- Semilla de los ataques: 42
