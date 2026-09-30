# T1_TMGVD

Count-Min Sketch y CountSketch sobre una ventana deslizante de 60 s formada por 6 subventanas de 10 s.

## Compilar

```bash
g++ -O2 -std=c++17 -o sketch_ventana codigo/sketch_ventana.cpp
```

## Uso

```bash
./sketch_ventana traza.bin --key dst -d 5 -w 1024 --query <IP> --out est.csv
```
