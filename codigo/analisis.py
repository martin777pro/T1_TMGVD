import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import pandas as pd

ENTRADA, SALIDA = sys.argv[1], sys.argv[2]
ANCHOS = [256, 1024, 4096]
D = 5
W_US = 60_000_000

NOMBRE = {"cms": "CMS", "cs": "CS"}
TITULO = {"ddos": "DDoS", "scan": "Scan"}
COLOR = {  # más oscuro a mayor w
    "cms": {256: "#f29a70", 1024: "#eb6834", 4096: "#a8431a"},
    "cs": {256: "#86b6ef", 1024: "#2a78d6", 4096: "#104281"},
}
LINEA = {"cms": "-", "cs": "--"}
NEGRO, GRIS, FONDO_ATAQUE = "#0b0b0b", "#898781", "#f0efec"

plt.rcParams.update({
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.edgecolor": "#c3c2b7",
    "axes.grid": True,
    "grid.color": "#e1e0d9",
    "grid.linewidth": 0.6,
    "font.size": 9,
})
miles = FuncFormatter(lambda v, _: f"{v / 1000:.0f}k" if v else "0")


def memoria(w):
    return 7 * D * w * 4  # 6 sub-sketches + agregado, contadores int32


def validacion():
    resultado = {}
    for w in ANCHOS:
        m = pd.concat([
            pd.read_csv(f"{ENTRADA}/base_{clave}_exacto.csv")
              .merge(pd.read_csv(f"{ENTRADA}/base_{clave}_w{w}.csv"), on=["win", "key"])
            for clave in ("src", "dst")
        ])
        m = m[m.exact_f > 0]
        for sk in NOMBRE:
            error = (m[f"{sk}_f"] - m.exact_f).abs()
            resultado[sk, w] = (error.mean(), (error / m.exact_f).median())
    return resultado


def cargar_ataque(nombre):
    datos = pd.read_csv(f"{ENTRADA}/{nombre}_exacto.csv")
    for w in ANCHOS:
        est = pd.read_csv(f"{ENTRADA}/{nombre}_w{w}.csv")
        assert (est.N.values == datos.N.values).all(), "N_j no coincide con exact_hh"
        for col in ("cms_f", "cs_f", "cms_hh", "cs_hh", "cms_med_delta", "cs_delta"):
            datos[f"{col}_{w}"] = est[col].values
    gt = json.load(open(f"{ENTRADA}/gt_{nombre}.json"))
    return datos, gt


def ventanas_J(datos, gt):
    # Después del inicio y antes de que el último paquete del ataque salga de la ventana
    inicio, fin = gt["ventana_ataque_us"]
    return datos[(datos.tau_us > inicio) & (datos.tau_us - W_US < fin) & (datos.exact_f > 0)]


def latencia(datos, gt, columna_hh):
    inicio = gt["ventana_ataque_us"][0]
    detectadas = datos[(datos.tau_us >= inicio) & (datos[columna_hh] == 1)]
    if len(detectadas) == 0:
        return "no detecta"
    return f"{(detectadas.tau_us.iloc[0] - inicio) / 1e6:.0f}"


def zona_grafico(datos, gt):
    inicio, fin = gt["ventana_ataque_rel_s"]
    return datos[datos.t_rel_s.between(inicio - 60, fin + 60)]


def graficar(arriba, abajo, t, exacto, estimados):
    """Arriba las curvas superpuestas; abajo el error de cada ventana (estimado - exacto)."""
    arriba.plot(t, exacto, color=NEGRO, lw=2, zorder=5, label="exacto")
    abajo.axhline(0, color=NEGRO, lw=1)
    for sk, w, etiqueta, valores in estimados:
        estilo = dict(ls=LINEA[sk], color=COLOR[sk][w], lw=1.5, marker="o", ms=3, label=etiqueta)
        arriba.plot(t, valores, **estilo)
        abajo.plot(t, valores - exacto, **estilo)
    arriba.yaxis.set_major_formatter(miles)
    abajo.set_xlabel("τ (s desde el inicio de la traza)")


def figura_frecuencia(nombre, datos, gt):
    zona = zona_grafico(datos, gt)
    fig, (arriba, abajo) = plt.subplots(2, 1, figsize=(8, 6), sharex=True,
                                        gridspec_kw={"height_ratios": [2, 1]})
    arriba.axvspan(*gt["ventana_ataque_rel_s"], color=FONDO_ATAQUE, label="ataque")
    abajo.axvspan(*gt["ventana_ataque_rel_s"], color=FONDO_ATAQUE)
    arriba.plot(zona.t_rel_s, zona.threshold, ":", color=GRIS, lw=1.5, label="umbral ⌈φN⌉")
    graficar(arriba, abajo, zona.t_rel_s, zona.exact_f,
             [(sk, w, f"{NOMBRE[sk]} w={w}", zona[f"{sk}_f_{w}"]) for sk in NOMBRE for w in ANCHOS])
    clave = "destino" if nombre == "ddos" else "origen"
    arriba.set_title(f"{TITULO[nombre]}: frecuencia de {datos.key[0]} (IP {clave})")
    arriba.set_ylabel("paquetes en la ventana")
    abajo.set_ylabel("estimado − exacto")
    arriba.legend(ncol=3, fontsize=8, frameon=False, loc="upper left")
    fig.tight_layout()
    fig.savefig(f"{SALIDA}/frecuencia_{nombre}.png", dpi=150)
    plt.close(fig)


def figura_delta(ataques):
    fig, ejes = plt.subplots(2, 2, figsize=(11, 6), sharex="col", sharey="row",
                             gridspec_kw={"height_ratios": [2, 1]})
    for col, (nombre, (datos, gt)) in enumerate(ataques.items()):
        arriba, abajo = ejes[0, col], ejes[1, col]
        zona = zona_grafico(datos, gt)
        arriba.axvspan(*gt["ventana_ataque_rel_s"], color=FONDO_ATAQUE)
        abajo.axvspan(*gt["ventana_ataque_rel_s"], color=FONDO_ATAQUE)
        graficar(arriba, abajo, zona.t_rel_s, zona.exact_delta,
                 [("cms", w, f"CMS-mediana w={w}", zona[f"cms_med_delta_{w}"]) for w in ANCHOS] +
                 [("cs", w, f"CS w={w}", zona[f"cs_delta_{w}"]) for w in ANCHOS])
        arriba.set_title(f"{TITULO[nombre]}: Δf de {datos.key[0]}")
    ejes[0, 0].set_ylabel(r"$\Delta f_j = f_j - f_{j-1}$ (paquetes)")
    ejes[1, 0].set_ylabel("estimado − exacto")
    manejadores, etiquetas = ejes[0, 0].get_legend_handles_labels()
    fig.legend(manejadores, etiquetas, ncol=7, fontsize=8, frameon=False, loc="lower center")
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(f"{SALIDA}/delta.png", dpi=150)
    plt.close(fig)


def tabla_md(encabezado, filas):
    lineas = ["| " + " | ".join(encabezado) + " |", "|" + "---|" * len(encabezado)]
    lineas += ["| " + " | ".join(str(v) for v in fila) + " |" for fila in filas]
    return "\n".join(lineas) + "\n"


os.makedirs(SALIDA, exist_ok=True)
errores_validacion = validacion()
ataques = {nombre: cargar_ataque(nombre) for nombre in ("ddos", "scan")}

for nombre, (datos, gt) in ataques.items():
    figura_frecuencia(nombre, datos, gt)
figura_delta(ataques)

md = ["# Resultados\n"]

filas = []
for w in ANCHOS:
    for sk in NOMBRE:
        error_abs, error_rel = errores_validacion[sk, w]
        fila = [NOMBRE[sk], w, memoria(w), f"{error_abs:.0f}", f"{error_rel:.4f}"]
        for datos, gt in ataques.values():
            J = ventanas_J(datos, gt)
            fila.append(f"{((J[f'{sk}_f_{w}'] - J.exact_f).abs() / J.exact_f).mean():.4f}")
        for datos, gt in ataques.values():
            fila.append(latencia(datos, gt, f"{sk}_hh_{w}"))
        filas.append(fila)
filas.append(["Exacto", "", "", "", "", "", ""] +
             [latencia(datos, gt, "exact_hh") for datos, gt in ataques.values()])
md.append("## Resumen CMS vs CS (d = 5)\n")
md.append(tabla_md(["Sketch", "w", "Memoria (B)", "Validación: error abs. medio",
                    "Validación: error rel. mediano", "MRE DDoS", "MRE Scan",
                    "Latencia DDoS (s)", "Latencia Scan (s)"], filas))

for nombre, (datos, gt) in ataques.items():
    J = ventanas_J(datos, gt)
    columnas = [(sk, w) for w in ANCHOS for sk in NOMBRE]
    filas = [[f"{r.t_rel_s:.0f}", r.exact_f, r.threshold] +
             [f"{abs(r[f'{sk}_f_{w}'] - r.exact_f) / r.exact_f:.4f}" for sk, w in columnas]
             for _, r in J.iterrows()]
    md.append(f"\n## {TITULO[nombre]}: error relativo por ventana en J ({len(J)} ventanas)\n")
    md.append(tabla_md(["τ (s)", "f exacta", "umbral"] + [f"{NOMBRE[sk]} {w}" for sk, w in columnas], filas))

for nombre, (datos, gt) in ataques.items():
    con_delta = datos.dropna(subset=["exact_delta"])
    extremos = pd.concat([con_delta.nlargest(3, "exact_delta"), con_delta.nsmallest(3, "exact_delta")])
    columnas = [(col, w) for w in ANCHOS for col in ("cs_delta", "cms_med_delta")]
    filas = [[f"{r.t_rel_s:.0f}", f"{r.exact_delta:.0f}"] +
             [f"{r[f'{col}_{w}'] - r.exact_delta:+.0f}" for col, w in columnas]
             for _, r in extremos.iterrows()]
    filas.append(["todas", "error abs. medio"] +
                 [f"{(con_delta[f'{col}_{w}'] - con_delta.exact_delta).abs().mean():.0f}" for col, w in columnas])
    md.append(f"\n## {TITULO[nombre]}: mayores incrementos y decrementos de Δf (error = estimado − exacto)\n")
    md.append(tabla_md(["τ (s)", "Δf exacto"] +
                       [f"{'CS' if col == 'cs_delta' else 'CMS-med'} {w}" for col, w in columnas], filas))

with open(f"{SALIDA}/tablas.md", "w", encoding="utf-8") as f:
    f.write("\n".join(md))
print(f"figuras y tablas en {SALIDA}/")
