#!/bin/bash
set -e

TRAZA=$1
OUT=$2
ENT=codigo_entregado
ANCHOS="256 1024 4096"
SEMILLA=42

mkdir -p "$OUT"
make -C $ENT
g++ -O2 -std=c++17 -o "$OUT/sketch_ventana" codigo/sketch_ventana.cpp

sketches() {  # traza clave nombre consultas...
    local traza=$1 clave=$2 nombre=$3
    shift 3
    for w in $ANCHOS; do
        "$OUT/sketch_ventana" "$traza" --key $clave -d 5 -w $w "$@" --out "$OUT/${nombre}_w$w.csv"
    done
}

# Actividad 1: validación con las 20 claves más frecuentes de la primera ventana
for clave in src dst; do
    $ENT/exact_hh "$TRAZA" --key $clave --topk 20 --max-windows 1 --out-topk "$OUT/base_${clave}_top20.csv"
    CONSULTAS=$(awk -F, 'NR > 1 {printf "--query %s ", $4}' "$OUT/base_${clave}_top20.csv")
    $ENT/exact_hh "$TRAZA" --key $clave $CONSULTAS --out-query "$OUT/base_${clave}_exacto.csv"
    sketches "$TRAZA" $clave base_$clave $CONSULTAS
done

# Actividad 2: ataques
python3 $ENT/inject_attack.py ddos --base "$TRAZA" --out "$OUT/traza_ddos.bin" --gt "$OUT/gt_ddos.json" \
    --start 300 --duration 30 --pps 10000 --sources 4000 --seed $SEMILLA
python3 $ENT/inject_attack.py scan --base "$TRAZA" --out "$OUT/traza_scan.bin" --gt "$OUT/gt_scan.json" \
    --start 300 --duration 30 --pps 8000 --dst-count 60000 --seed $SEMILLA

VICTIMA=$(python3 -c "import json; print(json.load(open('$OUT/gt_ddos.json'))['ataque']['victima'])")
ATACANTE=$(python3 -c "import json; print(json.load(open('$OUT/gt_scan.json'))['ataque']['atacante'])")

$ENT/exact_hh "$OUT/traza_ddos.bin" --key dst --query $VICTIMA --out-query "$OUT/ddos_exacto.csv"
sketches "$OUT/traza_ddos.bin" dst ddos --query $VICTIMA

$ENT/exact_hh "$OUT/traza_scan.bin" --key src --query $ATACANTE --out-query "$OUT/scan_exacto.csv"
sketches "$OUT/traza_scan.bin" src scan --query $ATACANTE
