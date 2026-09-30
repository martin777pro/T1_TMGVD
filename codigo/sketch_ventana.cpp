#include <algorithm>
#include <cinttypes>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#pragma pack(push, 1)
struct Record {
    uint64_t ts_us;
    uint32_t src, dst;
    uint16_t sport, dport, len;
    uint8_t proto, flags;
};
#pragma pack(pop)

const uint64_t W = 60000000;  // 60 s en microsegundos
const uint64_t P = 10000000;  // 10 s
const int M = 6;

const uint64_t PRIMO = (1ull << 61) - 1;

uint64_t hash_ab(uint64_t a, uint64_t b, uint32_t x) {
    unsigned __int128 v = (unsigned __int128)a * x + b;
    return (uint64_t)(v % PRIMO);
}

struct Hashes {
    int d;
    uint32_t w;
    std::vector<uint64_t> a, b, c, e;

    Hashes(int d, uint32_t w, uint64_t semilla) : d(d), w(w) {
        std::mt19937_64 gen(semilla);
        std::uniform_int_distribution<uint64_t> dist(1, PRIMO - 1);
        for (int r = 0; r < d; r++) {
            a.push_back(dist(gen));
            b.push_back(dist(gen));
            c.push_back(dist(gen));
            e.push_back(dist(gen));
        }
    }
    uint32_t columna(int r, uint32_t x) const { return hash_ab(a[r], b[r], x) % w; }
    int signo(int r, uint32_t x) const { return (hash_ab(c[r], e[r], x) & 1) ? 1 : -1; }
};

struct Ventana {
    int d;
    uint32_t w;
    std::vector<std::vector<int32_t>> sub;
    std::vector<int32_t> A;

    Ventana(int d, uint32_t w)
        : d(d), w(w), sub(M, std::vector<int32_t>(d * w, 0)), A(d * w, 0) {}

    void sumar(int ranura, int r, uint32_t col, int valor) {
        sub[ranura][r * w + col] += valor;
        A[r * w + col] += valor;
    }

    void expirar(int ranura) {
        for (size_t k = 0; k < A.size(); k++) {
            A[k] -= sub[ranura][k];
            sub[ranura][k] = 0;
        }
    }

    size_t bytes() const { return (M + 1) * A.size() * sizeof(int32_t); }
};

double mediana(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    size_t n = v.size();
    if (n % 2 == 1) return v[n / 2];
    return (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

bool leer_ip(const char *s, uint32_t *ip) {
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    *ip = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

std::string ip_texto(uint32_t ip) {
    char buf[16];
    sprintf(buf, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "uso: %s traza.bin --key src|dst -d D -w W [--seed S] [--phi F] "
                        "--query IP [--query IP ...] --out archivo.csv\n", argv[0]);
        return 1;
    }
    const char *ruta = argv[1];
    bool por_origen = false;
    int d = 5;
    uint32_t w = 1024;
    uint64_t semilla = 1;
    double phi = 0.01;
    const char *salida = nullptr;
    std::vector<uint32_t> consultas;

    for (int i = 2; i < argc; i++) {
        std::string op = argv[i];
        if (i + 1 >= argc) { fprintf(stderr, "falta valor para %s\n", op.c_str()); return 1; }
        const char *valor = argv[++i];

        if (op == "--key") por_origen = (std::string(valor) == "src");
        else if (op == "-d") d = atoi(valor);
        else if (op == "-w") w = atoi(valor);
        else if (op == "--seed") semilla = strtoull(valor, nullptr, 10);
        else if (op == "--phi") phi = atof(valor);
        else if (op == "--out") salida = valor;
        else if (op == "--query") {
            uint32_t ip;
            if (!leer_ip(valor, &ip)) { fprintf(stderr, "IP inválida: %s\n", valor); return 1; }
            consultas.push_back(ip);
        }
        else { fprintf(stderr, "opción desconocida: %s\n", op.c_str()); return 1; }
    }
    if (consultas.empty() || !salida) {
        fprintf(stderr, "faltan --query o --out\n");
        return 1;
    }

    int fd = open(ruta, O_RDONLY);
    if (fd < 0) { perror(ruta); return 1; }
    struct stat st;
    fstat(fd, &st);
    const Record *pkt = (const Record *)mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (pkt == MAP_FAILED) { perror("mmap"); return 1; }
    const size_t n = st.st_size / sizeof(Record);

    FILE *csv = fopen(salida, "w");
    if (!csv) { perror(salida); return 1; }
    fprintf(csv, "win,tau_us,t_rel_s,key,N,threshold,cms_f,cs_f,cms_hh,cs_hh,"
                 "cms_med_delta,cs_delta\n");

    Hashes h(d, w, semilla);
    Ventana cms(d, w), cs(d, w);
    uint64_t n_sub[M] = {0};
    uint64_t N = 0;

    // Celdas de la subventana que sale, para Delta A = S_entra - S_sale
    std::vector<std::vector<int32_t>> sale_cms(consultas.size(), std::vector<int32_t>(d));
    std::vector<std::vector<int32_t>> sale_cs(consultas.size(), std::vector<int32_t>(d));

    size_t i = 0;
    auto cargar_hasta = [&](uint64_t t_fin, int ranura) {
        while (i < n && pkt[i].ts_us <= t_fin) {
            uint32_t x = por_origen ? pkt[i].src : pkt[i].dst;
            for (int r = 0; r < d; r++) {
                uint32_t col = h.columna(r, x);
                cms.sumar(ranura, r, col, 1);
                cs.sumar(ranura, r, col, h.signo(r, x));
            }
            n_sub[ranura]++;
            N++;
            i++;
        }
    };

    // La subventana q cubre (t0 + (q-1)P, t0 + qP] y va en la ranura (q-1) % M.
    // Los paquetes con ts == t0 no caen en ninguna ventana (igual que exact_hh).
    const uint64_t t0 = pkt[0].ts_us;
    const uint64_t t_ultimo = pkt[n - 1].ts_us;
    while (i < n && pkt[i].ts_us <= t0) i++;

    for (int q = 1; q <= M; q++) cargar_hasta(t0 + q * P, q - 1);

    int win = 0;
    for (uint64_t tau = t0 + W; tau <= t_ultimo; tau += P, win++) {
        int ranura = ((tau - t0) / P - 1) % M;

        if (win > 0) {
            for (size_t z = 0; z < consultas.size(); z++)
                for (int r = 0; r < d; r++) {
                    uint32_t col = h.columna(r, consultas[z]);
                    sale_cms[z][r] = cms.sub[ranura][r * w + col];
                    sale_cs[z][r] = cs.sub[ranura][r * w + col];
                }
            cms.expirar(ranura);
            cs.expirar(ranura);
            N -= n_sub[ranura];
            n_sub[ranura] = 0;
            cargar_hasta(tau, ranura);
        }

        uint64_t umbral = std::max<uint64_t>(1, std::ceil(phi * N));

        for (size_t z = 0; z < consultas.size(); z++) {
            uint32_t x = consultas[z];
            int64_t f_cms = INT64_MAX;
            std::vector<double> filas_cs, delta_cms, delta_cs;

            for (int r = 0; r < d; r++) {
                uint32_t col = h.columna(r, x);
                int s = h.signo(r, x);
                f_cms = std::min<int64_t>(f_cms, cms.A[r * w + col]);
                filas_cs.push_back(s * cs.A[r * w + col]);
                delta_cms.push_back(cms.sub[ranura][r * w + col] - sale_cms[z][r]);
                delta_cs.push_back(s * (cs.sub[ranura][r * w + col] - sale_cs[z][r]));
            }
            double f_cs = std::max(0.0, mediana(filas_cs));

            fprintf(csv, "%d,%" PRIu64 ",%.6f,%s,%" PRIu64 ",%" PRIu64 ",%" PRId64 ",%.1f,%d,%d,",
                    win, tau, (tau - t0) / 1e6, ip_texto(x).c_str(), N, umbral,
                    f_cms, f_cs, f_cms >= (int64_t)umbral, f_cs >= umbral);
            if (win > 0)
                fprintf(csv, "%.1f,%.1f\n", mediana(delta_cms), mediana(delta_cs));
            else
                fprintf(csv, ",\n");
        }
    }
    fclose(csv);

    printf("ventanas: %d\n", win);
    printf("memoria contadores CMS: %zu bytes (7 matrices de %d x %u)\n", cms.bytes(), d, w);
    printf("memoria contadores CS:  %zu bytes (7 matrices de %d x %u)\n", cs.bytes(), d, w);
    return 0;
}
