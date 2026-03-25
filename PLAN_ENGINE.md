# Plan: Attack Path Engine — Long-Term Enterprise Performance Architecture

## Context

El motor local DFS actual está implementado en Python puro (`attack_graph_core.py`). Para entornos grandes (20K+ nodos, 500K+ aristas) los tiempos de ejecución alcanzan 2-7 minutos. Los cuellos de botella identificados son:

1. **DFS traversal Python puro** — O(S × (N+V)) por fuente, 10-120s para grafos grandes
2. **Virtual edge expansion (LocalAdminPassReuse)** — O(C × M²) por visita de nodo, multiplicador crítico en entornos con muchas reutilizaciones de credenciales
3. **Containment filter O(P² × L²)** — ya documentado en el código como "expensive O(n²) operation", puede superar 5 minutos para P alto
4. **Serialización JSON** — carga lenta para grafos de 100MB+

El usuario necesita una arquitectura enterprise que escale a entornos con 100K+ aristas y cientos de usuarios owned/principals, manteniendo distribución como binario único (PyInstaller).

**Descartadas por incompatibilidad o coste:**
- PostgreSQL: CTEs recursivos son más lentos que DFS nativo para multi-hop paths con semántica de grafo; requiere proceso externo
- Neo4j embebido: requiere JVM (~500MB+), incompatible con PyInstaller single-binary
- Go subprocess: overhead de serialización por llamada hace inviable el shared-memory para grafos grandes
- BH CE exclusivamente: requiere servicio externo, no funciona offline

---

## Arquitectura recomendada: migración Rust por fases

### Principio guía
La clave no es reemplazar la arquitectura, sino **reemplazar únicamente el kernel del DFS** con código nativo mientras Python mantiene la lógica de negocio, post-procesado y UX. Esto minimiza el riesgo y permite despliegue incremental.

---

## Fase 1 — Quick wins en Python (1-2 semanas, ~3-5x speedup)

**Objetivo**: Resultados inmediatos sin cambios arquitectónicos.

### 1a. MessagePack en lugar de JSON para el grafo
- Sustituir `json.load()` / `json.dump()` por `msgpack` para `attack_graph.json`
- **Ganancia**: 5-10x en serialización, reducción de tamaño en disco ~60%
- Implementar backward-compat: detectar formato por magic bytes

### 1b. Reemplazar O(P²) containment filter
- Sustituir el doble bucle de sub-secuencias por un índice invertido de firmas (dict de frozensets)
- Para keep_shortest: indexar por terminal → set de sigs ya vistas; lookup O(1) en vez de O(P×L)
- **Ganancia estimada**: 10-50x en la fase de post-procesado para P grande
- Fichero: `attack_graph_core.py`, función `filter_contained_paths_for_domain_listing()`

### 1c. Multiprocessing para multi-principal
- Para `scope=owned/principals` con múltiples fuentes: cada principal es independiente → `multiprocessing.Pool`
- El grafo (read-only) se pasa como shared memory via `multiprocessing.shared_memory` o se precarga en cada worker
- **Ganancia**: ~N_cores × speedup (4-8x en hardware típico)
- Fichero: `attack_graph_service.py`, sección `compute_display_paths_for_principals()`

### 1d. Pre-filtrado de aristas por tipo relevante
- Al construir el grafo, separar aristas MemberOf del resto → evitar propagarlas en rutas ya expandidas
- Pre-calcular membresías transitivas una sola vez al cargar el grafo en vez de expandirlas en cada DFS

---

## Fase 2 — rustworkx: Rust sin código Rust propio (2-4 semanas, ~10-50x DFS)

**Objetivo**: Sustituir el DFS Python puro por una librería con backend Rust, sin escribir ni un fichero `.rs`.

### Por qué rustworkx
- Es la librería de grafos de IBM Quantum, escrita en Rust con bindings PyO3
- Pip-installable, sin dependencias de sistema, funciona dentro de PyInstaller
- Provee `rustworkx.digraph_dfs_search()` y primitivas BFS/DFS con callbacks Python
- Tiene soporte nativo para directed multigraphs (esencial para nuestro modelo de aristas)
- Ya es la base de `qiskit` → producción-battle-tested

### Implementación
1. Al cargar el grafo, construir un `rustworkx.PyDiGraph` en paralelo al dict actual
2. Implementar `DFSVisitor` con la lógica de:
   - Visited set (acyclicity)
   - Signature deduplication
   - Depth limit
   - Terminal node detection
   - max_paths cap
3. Virtual edge expansion (LocalAdminPassReuse): pre-materializar como aristas reales en el rustworkx graph en vez de generarlas on-the-fly en cada visita → elimina el O(C×M²) por visita
4. Path collection: acumular en lista Python desde el visitor

### Ficheros afectados
- `adscan_internal/services/attack_graph_core.py` — nueva clase `RustworkxDFSEngine`
- `adscan_internal/services/attack_graph_service.py` — selección de engine (rustworkx vs fallback Python)
- `requirements.txt` — añadir `rustworkx>=0.15`

### Fallback
Mantener el DFS Python actual como fallback si rustworkx no está disponible (entornos de CI legacy).

---

## Fase 3 — Almacenamiento binario del grafo con DuckDB (1-2 meses)

**Objetivo**: Eliminar el cuello de botella de carga/guardado del grafo, habilitar consultas analíticas rápidas sobre el grafo (ej: "todos los nodos con >50 ACLs salientes").

### Por qué DuckDB y no PostgreSQL
- In-process: sin servidor externo, embeddable en PyInstaller
- Lee/escribe Parquet nativo → formato columnar comprimido, 10-100x más rápido que JSON
- Permite queries SQL sobre el grafo para reducción de ruido de ACLs
- API Python nativa, sin ORM necesario

### Implementación
1. Persistir nodos y aristas en dos tablas DuckDB (`nodes.parquet`, `edges.parquet`)
2. Índices en columnas `from_id`, `to_id`, `relation` → lookup O(log N) para construcción de adjacency
3. Pre-filtrado SQL de aristas ruidosas antes de cargar al DFS
4. El `rustworkx.PyDiGraph` se construye directamente desde DuckDB sin pasar por JSON

---

## Fase 4 — Extensión Rust propia via PyO3 (3-6 meses, 50-200x total)

**Objetivo**: Engine DFS completamente nativo con semántica exacta de ADscan (virtual edges, signature dedup, path pruning, containment filter) en Rust.

### Arquitectura
```
Python (UX, lógica de negocio, post-procesado)
    ↓ PyO3 bindings (zero-copy)
Rust DFS Engine (petgraph + custom traversal)
    ↓ shared memory / Arrow IPC
DuckDB (graph storage, Parquet)
```

### Componentes del engine Rust
- `adgraph_core` crate con `AdGraph`, `DfsEngine`, `VirtualEdgeExpander`, `ContainmentFilter`, `PathMinimizer`
- Paralelismo interno via Rayon para multi-principal
- Build via `maturin` + Docker manylinux (ya existe `dockerfile`)

---

## Resumen de ganancias por fase

| Fase | Effort | DFS speedup | Filter speedup | Total |
|------|--------|-------------|----------------|-------|
| 1a-d (Python optimizations) | 1-2 sem | 2-3x | 10-50x | ~3-5x end-to-end |
| 2 (rustworkx) | 2-4 sem | 10-50x | — | ~10-50x DFS |
| 3 (DuckDB) | 4-8 sem | — | — | ~5-10x load time |
| 4 (PyO3 Rust engine) | 3-6 meses | 50-200x | 50x | ~100x end-to-end |

**Objetivo final**: grafos de 500K aristas y 200 principals en <5 segundos.

---

## Ficheros críticos

- `adscan_internal/services/attack_graph_core.py` — DFS engine, containment filter
- `adscan_internal/services/attack_graph_service.py` — orquestación, multi-principal
- `adscan_internal/services/attack_paths_core.py` — path minimization, display conversion
- `requirements.txt`, `dockerfile`, `build_adscan.sh`
