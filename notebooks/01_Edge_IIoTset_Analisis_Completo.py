# %% [markdown]
# # 🔒 Análisis Completo del Dataset Edge-IIoTset
# ## TFM: IDS/IPS con IA para Raspberry Pi — UCLM 2025-2026
# **Alumno:** Luis Ignacio de Luna Gómez
#
# **Dataset:** Edge-IIoTset (Ferrag et al., 2022) — IEEE Access
#
# **Referencia:** "Edge-IIoTset: A New Comprehensive Realistic Cyber Security
# Dataset of IoT and IIoT Applications for Centralized and Federated Learning"

# %% [markdown]
# ---
# ## FASE 0 — Validación del Entorno
# ---

# %%
import sys
import importlib
import warnings
warnings.filterwarnings('ignore')

print(f"Python: {sys.version}")

REQUIRED = [
    'numpy', 'pandas', 'matplotlib', 'seaborn', 'sklearn', 'xgboost',
    'lightgbm', 'imblearn', 'shap', 'scipy', 'pyarrow', 'psutil', 'tqdm'
]
missing = []
for pkg in REQUIRED:
    try:
        importlib.import_module(pkg)
    except ImportError:
        missing.append(pkg)

if missing:
    print(f"❌ Paquetes faltantes: {missing}")
    print("Ejecutar: pip install -r notebooks/requirements_notebook.txt")
else:
    print("✅ Todas las dependencias instaladas")

import psutil
ram_gb = psutil.virtual_memory().total / 1e9
print(f"RAM total: {ram_gb:.1f} GB")
if ram_gb < 8:
    print("⚠️ Menos de 8 GB de RAM — se usará carga por chunks")
else:
    print("✅ RAM suficiente para carga completa")

# %%

# %% [markdown]
# ---
# ## FASE 1 — Contexto y Documentación
# ---
#
# ### 1.1 Arquitectura del Testbed Edge-IIoTset
#
# El testbed se organiza en **7 capas**:
#
# | Capa | Tecnología | Función |
# |------|-----------|---------|
# | Cloud Computing | ThingsBoard IoT Platform | Gestión centralizada de dispositivos |
# | NFV | OPNFV Platform | Virtualización de funciones de red |
# | Blockchain | Hyperledger Sawtooth | Integridad y trazabilidad |
# | Fog Computing | Digital Twin | Procesamiento intermedio |
# | SDN | ONOS Controller | Control de red programable |
# | Edge Computing | Mosquitto MQTT, Modbus TCP/IP | Procesamiento en el borde |
# | IoT/IIoT Perception | 10+ tipos de sensores | Generación de datos |
#
# ### 1.2 Sensores IoT del testbed
# - Temperatura y humedad (DHT11/DHT22)
# - Ultrasónico (HC-SR04)
# - Nivel de agua
# - pH
# - Humedad del suelo
# - Ritmo cardíaco
# - Sensor de llama
# - Sensor infrarrojo
#
# ### 1.3 Protocolos de conectividad
# - **MQTT** (Message Queuing Telemetry Transport) — IoT ligero
# - **Modbus TCP/IP** — Protocolo industrial IIoT
# - **CoAP** (Constrained Application Protocol) — IoT restringido
# - **HTTP/HTTPS** — Comunicación web estándar
#
# ### 1.4 Taxonomía de Amenazas y Mapeo MITRE ATT&CK

# %%
# Verificar que la celda de imports se ejecutó
if 'PROJECT_ROOT' not in dir():
    raise RuntimeError("⚠️ Ejecuta primero la celda de imports (línea 49) que define PROJECT_ROOT y las librerías.")

# Documentación estructurada de ataques
ATTACK_TAXONOMY = {
    "DoS/DDoS": {
        "ataques": ["DDoS_UDP", "DDoS_ICMP", "DDoS_TCP", "DDoS_HTTP"],
        "descripcion": "Inundación de tráfico para denegar servicio a dispositivos IoT/IIoT edge",
        "mitre_ids": ["T1498", "T1499"],
        "mitre_names": ["Network Denial of Service", "Endpoint Denial of Service"],
        "protocolos_afectados": ["UDP", "ICMP", "TCP", "HTTP"],
        "impacto": "Indisponibilidad de servicios IoT críticos"
    },
    "Information Gathering": {
        "ataques": ["Port_Scanning", "OS_Fingerprinting", "Vulnerability_Scanner"],
        "descripcion": "Reconocimiento activo: escaneo de puertos, detección de SO y vulnerabilidades",
        "mitre_ids": ["T1046", "T1592", "T1595"],
        "mitre_names": ["Network Service Scanning", "Gather Victim Host Info", "Active Scanning"],
        "protocolos_afectados": ["TCP", "UDP", "ICMP"],
        "impacto": "Obtención de información para ataques posteriores"
    },
    "Man-in-the-Middle": {
        "ataques": ["MITM", "DNS_Spoofing"],
        "descripcion": "Interceptación y manipulación de comunicaciones entre dispositivos",
        "mitre_ids": ["T1557", "T1557.002"],
        "mitre_names": ["Adversary-in-the-Middle", "ARP Cache Poisoning"],
        "protocolos_afectados": ["ARP", "DNS"],
        "impacto": "Interceptación de datos sensibles, redirección de tráfico"
    },
    "Injection": {
        "ataques": ["SQL_Injection", "XSS", "Uploading_Attack"],
        "descripcion": "Inyección de código/comandos maliciosos en aplicaciones IoT",
        "mitre_ids": ["T1190", "T1059"],
        "mitre_names": ["Exploit Public-Facing Application", "Command and Scripting Interpreter"],
        "protocolos_afectados": ["HTTP", "HTTPS"],
        "impacto": "Ejecución remota de código, robo de datos"
    },
    "Malware": {
        "ataques": ["Backdoor", "Ransomware", "Password"],
        "descripcion": "Software malicioso: puertas traseras, cifrado de datos, fuerza bruta",
        "mitre_ids": ["T1059.004", "T1486", "T1110"],
        "mitre_names": ["Unix Shell (Backdoor)", "Data Encrypted for Impact", "Brute Force"],
        "protocolos_afectados": ["TCP", "HTTP", "SSH"],
        "impacto": "Control remoto, extorsión, acceso no autorizado"
    }
}

# Mostrar tabla resumen
print("=" * 100)
print("TAXONOMÍA DE AMENAZAS — Edge-IIoTset → MITRE ATT&CK for IoT")
print("=" * 100)
for cat, info in ATTACK_TAXONOMY.items():
    print(f"\n🔴 {cat}")
    print(f"   Descripción: {info['descripcion']}")
    print(f"   Ataques: {', '.join(info['ataques'])}")
    print(f"   MITRE: {', '.join(f'{mid} ({mn})' for mid, mn in zip(info['mitre_ids'], info['mitre_names']))}")
    print(f"   Protocolos: {', '.join(info['protocolos_afectados'])}")
    print(f"   Impacto: {info['impacto']}")

total_attacks = sum(len(v["ataques"]) for v in ATTACK_TAXONOMY.values())
print(f"\nTotal: {total_attacks} tipos de ataque + Normal = {total_attacks + 1} clases")

# Guardar taxonomía como JSON para la memoria
taxonomy_path = PROJECT_ROOT / "docs" / "attack_taxonomy.json"
with open(taxonomy_path, 'w', encoding='utf-8') as f:
    json.dump(ATTACK_TAXONOMY, f, indent=2, ensure_ascii=False)
print(f"\n📄 Taxonomía guardada en: {taxonomy_path}")

# %% [markdown]
# ---
# ## FASE 2 — Extracción y Carga de Datos
# ---

# %%
# === 2.1 Descarga del dataset ===
# Opción A: Kaggle API (requiere ~/.kaggle/kaggle.json)
# Opción B: Descarga manual desde https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot

DATASET_KAGGLE = "mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot"

def download_kaggle_dataset(dataset_slug, dest_dir):
    """Descarga dataset de Kaggle si no existe localmente."""
    try:
        from kaggle.api.kaggle_api_extended import KaggleApi
        api = KaggleApi()
        api.authenticate()
        print(f"⬇️  Descargando {dataset_slug}...")
        api.dataset_download_files(dataset_slug, path=str(dest_dir), unzip=True)
        print(f"✅ Dataset descargado y descomprimido en {dest_dir}")
        return True
    except Exception as e:
        print(f"⚠️ Error con Kaggle API: {e}")
        print("📥 Descarga manual:")
        print(f"   1. Ve a https://www.kaggle.com/datasets/{dataset_slug}")
        print(f"   2. Descarga y descomprime en: {dest_dir}")
        return False

# Buscar el CSV principal
def find_dataset_file(base_dir, filename="DNN-EdgeIIoT-dataset.csv"):
    """Busca el archivo CSV recursivamente."""
    for path in Path(base_dir).rglob(filename):
        return path
    # Buscar variantes
    for path in Path(base_dir).rglob("*.csv"):
        if "edgeiiot" in path.name.lower() or "dnn" in path.name.lower():
            return path
    return None

csv_path = find_dataset_file(DATA_RAW)
if csv_path is None:
    print("Dataset no encontrado localmente. Intentando descarga...")
    download_kaggle_dataset(DATASET_KAGGLE, DATA_RAW)
    csv_path = find_dataset_file(DATA_RAW)

if csv_path:
    print(f"✅ Dataset encontrado: {csv_path}")
    print(f"   Tamaño: {csv_path.stat().st_size / 1e6:.1f} MB")
else:
    print("❌ No se encontró el dataset. Descárgalo manualmente.")
    print(f"   Destino: {DATA_RAW}")

# %%
# === 2.2 Carga con validación de integridad ===

PARQUET_PATH = DATA_PROCESSED / "edge_iiot_dataset.parquet"

def load_and_validate_dataset(csv_path, parquet_path):
    """Carga CSV con validación de integridad y convierte a Parquet."""
    # Si existe Parquet previo, cargar directamente
    if parquet_path.exists():
        print(f"📂 Cargando desde Parquet: {parquet_path}")
        df = pd.read_parquet(parquet_path)
        print(f"   Shape: {df.shape}")
        return df

    if csv_path is None:
        raise FileNotFoundError("No se encontró el CSV del dataset.")

    print(f"📂 Cargando CSV: {csv_path}")
    # Carga con manejo de errores (saltos de línea en strings, encoding)
    try:
        df = pd.read_csv(csv_path, low_memory=False, on_bad_lines='warn')
    except TypeError:
        # Versiones antiguas de pandas
        df = pd.read_csv(csv_path, low_memory=False, error_bad_lines=False)

    print(f"   Shape: {df.shape}")

    # --- Validación de integridad ---
    print("\n🔍 Validación de integridad:")

    # Verificar columna de etiqueta
    label_candidates = ['Attack_type', 'attack_type', 'Attack_label',
                        'attack_label', 'label', 'Label', 'type']
    label_col = None
    for col in label_candidates:
        if col in df.columns:
            label_col = col
            break

    if label_col is None:
        print("   ⚠️ No se encontró columna de etiqueta estándar.")
        print(f"   Columnas disponibles: {list(df.columns[-5:])}")
        # Intentar última columna como etiqueta
        label_col = df.columns[-1]
        print(f"   Usando última columna como etiqueta: '{label_col}'")
    else:
        print(f"   ✅ Columna de etiqueta: '{label_col}'")

    # Renombrar a nombre estándar si es necesario
    if label_col != 'Attack_type':
        df.rename(columns={label_col: 'Attack_type'}, inplace=True)
        print(f"   Renombrada '{label_col}' → 'Attack_type'")

    # Distribución inmediata de clases
    print(f"\n   📊 Distribución de clases:")
    class_dist = df['Attack_type'].value_counts()
    for cls, count in class_dist.items():
        pct = count / len(df) * 100
        print(f"      {cls:<30s} {count:>10,d}  ({pct:5.2f}%)")

    # Verificar número de columnas
    n_cols = df.shape[1]
    if n_cols < 10:
        print(f"   ⚠️ Solo {n_cols} columnas — ¿archivo correcto?")
    else:
        print(f"   ✅ {n_cols} columnas detectadas")

    # Guardar como Parquet
    print(f"\n💾 Guardando Parquet en: {parquet_path}")
    df.to_parquet(parquet_path, index=False)
    parquet_size = parquet_path.stat().st_size / 1e6
    csv_size = csv_path.stat().st_size / 1e6
    print(f"   CSV: {csv_size:.1f} MB → Parquet: {parquet_size:.1f} MB "
          f"(compresión: {(1 - parquet_size/csv_size)*100:.0f}%)")

    return df

df = load_and_validate_dataset(csv_path, PARQUET_PATH)
print(f"\n✅ Dataset cargado: {df.shape[0]:,} filas × {df.shape[1]} columnas")

# %% [markdown]
# ---
# ## FASE 3 — Análisis Exploratorio de Datos (EDA)
# ---

# %%
# === 3.1 Información general del dataset ===
print("=" * 80)
print("3.1 — INFORMACIÓN GENERAL DEL DATASET")
print("=" * 80)
print(f"\nShape: {df.shape}")
print(f"Memoria: {df.memory_usage(deep=True).sum() / 1e6:.1f} MB")

print(f"\n--- Tipos de datos ---")
dtype_counts = df.dtypes.value_counts()
for dtype, count in dtype_counts.items():
    print(f"  {dtype}: {count} columnas")

print(f"\n--- Primeras 5 filas ---")
df.head()

# %%
# === 3.2 Calidad de datos: Nulls, duplicados, inf ===
print("=" * 80)
print("3.2 — CALIDAD DE DATOS")
print("=" * 80)

# Valores nulos
null_counts = df.isnull().sum()
null_cols = null_counts[null_counts > 0]
print(f"\nColumnas con valores nulos: {len(null_cols)}")
if len(null_cols) > 0:
    for col, count in null_cols.items():
        print(f"  {col}: {count:,} ({count/len(df)*100:.2f}%)")

# CRÍTICO: Detectar y tratar valores infinitos ANTES de cualquier análisis
# El dataset tiene inf en columnas de tasas de flujo (bytes/s cuando duración=0)
numeric_cols = df.select_dtypes(include=[np.number]).columns
inf_mask = np.isinf(df[numeric_cols].values) if len(numeric_cols) > 0 else np.array([])
if inf_mask.any():
    inf_count = inf_mask.sum()
    print(f"\n⚠️ Valores infinitos detectados: {inf_count:,}")
    inf_per_col = pd.Series(inf_mask.sum(axis=0), index=numeric_cols)
    inf_cols = inf_per_col[inf_per_col > 0]
    for col, count in inf_cols.items():
        print(f"  {col}: {count:,} inf values")
    # Reemplazar inf por NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    print(f"  ✅ Valores infinitos convertidos a NaN")
else:
    print("\n✅ No se detectaron valores infinitos")

# Total de NaN después de conversión de inf
total_nan = df.isnull().sum().sum()
total_cells = df.shape[0] * df.shape[1]
print(f"\nTotal NaN (incluyendo inf→NaN): {total_nan:,} ({total_nan/total_cells*100:.3f}%)")

# Duplicados
n_duplicates = df.duplicated().sum()
print(f"\nFilas duplicadas: {n_duplicates:,} ({n_duplicates/len(df)*100:.2f}%)")
if n_duplicates > 0:
    print("  ℹ️ Los duplicados se mantienen — en tráfico de red es normal")

# %%
# === 3.3 Distribución de clases y cuantificación del desbalanceo ===
print("=" * 80)
print("3.3 — DISTRIBUCIÓN DE CLASES Y DESBALANCEO")
print("=" * 80)

class_counts = df['Attack_type'].value_counts()
class_pcts = df['Attack_type'].value_counts(normalize=True) * 100

# Tabla de distribución
dist_table = pd.DataFrame({
    'Clase': class_counts.index,
    'Muestras': class_counts.values,
    'Porcentaje': class_pcts.values
})

# Ratio respecto a Normal (o clase mayoritaria)
majority_class = class_counts.index[0]
majority_count = class_counts.iloc[0]
dist_table['Ratio_1:N'] = (majority_count / dist_table['Muestras']).round(1)
dist_table = dist_table.reset_index(drop=True)

print(f"\nClase mayoritaria: '{majority_class}' ({majority_count:,} muestras)")
print(f"\n{dist_table.to_string(index=False)}")

# Calcular métricas de desbalanceo
imbalance_ratio = majority_count / class_counts.min()
print(f"\n📊 Ratio de desbalanceo máximo: 1:{imbalance_ratio:.0f}")
print(f"   Clase más rara: '{class_counts.index[-1]}' ({class_counts.iloc[-1]:,})")

# Guardar tabla para la memoria
dist_table.to_csv(PROJECT_ROOT / "docs" / "class_distribution.csv", index=False)

# %%
# Gráfico de distribución de clases
fig, axes = plt.subplots(1, 2, figsize=(18, 8))

# Barplot
colors = sns.color_palette("viridis", len(class_counts))
bars = axes[0].barh(class_counts.index[::-1], class_counts.values[::-1], color=colors)
axes[0].set_xlabel('Número de muestras')
axes[0].set_title('Distribución de clases — Edge-IIoTset')
for bar, val in zip(bars, class_counts.values[::-1]):
    axes[0].text(bar.get_width() + max(class_counts) * 0.01,
                 bar.get_y() + bar.get_height()/2,
                 f'{val:,}', va='center', fontsize=9)

# Log-scale barplot (para ver clases minoritarias)
axes[1].barh(class_counts.index[::-1], class_counts.values[::-1], color=colors)
axes[1].set_xscale('log')
axes[1].set_xlabel('Número de muestras (escala log)')
axes[1].set_title('Distribución de clases — Escala logarítmica')

plt.tight_layout()
plt.savefig(FIGURES_DIR / "class_distribution.png")
plt.show()
print(f"📄 Guardado: {FIGURES_DIR / 'class_distribution.png'}")

# %%
# === 3.4 Estadísticas descriptivas por clase ===
print("=" * 80)
print("3.4 — ESTADÍSTICAS DESCRIPTIVAS")
print("=" * 80)

# Estadísticas globales
desc = df[numeric_cols].describe().T
desc['null_pct'] = df[numeric_cols].isnull().mean() * 100
desc['nunique'] = df[numeric_cols].nunique()
print("\nEstadísticas globales (top 20 features por std):")
print(desc.sort_values('std', ascending=False).head(20).to_string())

# Estadísticas por clase (resumen)
print("\n--- Medias por clase (primeras 10 features numéricas) ---")
first_10_num = numeric_cols[:10]
class_means = df.groupby('Attack_type')[first_10_num].mean()
print(class_means.round(3).to_string())

# %%
# === 3.5 Detección de features constantes o casi constantes ===
print("=" * 80)
print("3.5 — FEATURES CONSTANTES O CASI CONSTANTES")
print("=" * 80)

VARIANCE_THRESHOLD = 1e-5
variances = df[numeric_cols].var()
constant_features = variances[variances < VARIANCE_THRESHOLD].index.tolist()
near_constant = variances[(variances >= VARIANCE_THRESHOLD) & (variances < 0.01)].index.tolist()

print(f"\nFeatures con varianza < {VARIANCE_THRESHOLD} (constantes): {len(constant_features)}")
for f in constant_features:
    unique_vals = df[f].nunique()
    print(f"  {f}: var={variances[f]:.2e}, unique={unique_vals}")

print(f"\nFeatures con varianza < 0.01 (casi constantes): {len(near_constant)}")
for f in near_constant[:10]:
    print(f"  {f}: var={variances[f]:.6f}, unique={df[f].nunique()}")

# Features con un solo valor único
single_value = [c for c in df.columns if df[c].nunique() <= 1]
print(f"\nFeatures con ≤1 valor único: {len(single_value)}")
if single_value:
    print(f"  → Se eliminarán: {single_value}")

# %%
# === 3.6 Correlación de features (Pearson + Spearman) ===
print("=" * 80)
print("3.6 — CORRELACIÓN DE FEATURES")
print("=" * 80)

# Eliminar constantes para el análisis
analysis_cols = [c for c in numeric_cols if c not in constant_features + single_value]
print(f"Features para análisis de correlación: {len(analysis_cols)}")

# Pearson
print("\n--- Calculando correlación de Pearson ---")
# Usar sample si el dataset es muy grande para velocidad
if len(df) > 100_000:
    df_sample = df[analysis_cols].sample(n=100_000, random_state=42)
else:
    df_sample = df[analysis_cols]

corr_pearson = df_sample.corr(method='pearson')

# Heatmap Pearson
fig, ax = plt.subplots(figsize=(20, 16))
mask = np.triu(np.ones_like(corr_pearson, dtype=bool))
sns.heatmap(corr_pearson, mask=mask, cmap='RdBu_r', center=0,
            vmin=-1, vmax=1, square=True, linewidths=0.5,
            cbar_kws={"shrink": 0.8, "label": "Correlación Pearson"},
            xticklabels=True, yticklabels=True, ax=ax)
ax.set_title('Matriz de Correlación de Pearson — Edge-IIoTset', fontsize=16)
plt.xticks(rotation=90, fontsize=7)
plt.yticks(fontsize=7)
plt.tight_layout()
plt.savefig(FIGURES_DIR / "correlation_heatmap_pearson.png")
plt.show()

# Pares altamente correlacionados
high_corr_threshold = 0.95
high_corr_pairs = []
for i in range(len(corr_pearson.columns)):
    for j in range(i+1, len(corr_pearson.columns)):
        val = corr_pearson.iloc[i, j]
        if abs(val) > high_corr_threshold:
            high_corr_pairs.append((
                corr_pearson.columns[i],
                corr_pearson.columns[j],
                round(val, 4)
            ))

print(f"\nPares con |r| > {high_corr_threshold}: {len(high_corr_pairs)}")
for f1, f2, r in sorted(high_corr_pairs, key=lambda x: abs(x[2]), reverse=True)[:20]:
    print(f"  {f1} ↔ {f2}: r={r}")

# Spearman (más robusto ante no-linealidad)
print("\n--- Calculando correlación de Spearman ---")
corr_spearman = df_sample.corr(method='spearman')

fig, ax = plt.subplots(figsize=(20, 16))
sns.heatmap(corr_spearman, mask=mask, cmap='RdBu_r', center=0,
            vmin=-1, vmax=1, square=True, linewidths=0.5,
            cbar_kws={"shrink": 0.8, "label": "Correlación Spearman"},
            xticklabels=True, yticklabels=True, ax=ax)
ax.set_title('Matriz de Correlación de Spearman — Edge-IIoTset', fontsize=16)
plt.xticks(rotation=90, fontsize=7)
plt.yticks(fontsize=7)
plt.tight_layout()
plt.savefig(FIGURES_DIR / "correlation_heatmap_spearman.png")
plt.show()

# %%
# === 3.7 ANOVA F-test (comparación con paper original) ===
print("=" * 80)
print("3.7 — ANOVA F-TEST (Selección univariante — ref. paper Ferrag et al.)")
print("=" * 80)

from sklearn.feature_selection import f_classif
from sklearn.preprocessing import LabelEncoder

le_temp = LabelEncoder()
y_encoded = le_temp.fit_transform(df['Attack_type'])

# Imputar NaN para ANOVA (media)
X_anova = df[analysis_cols].fillna(df[analysis_cols].median())

f_scores, p_values = f_classif(X_anova, y_encoded)

anova_results = pd.DataFrame({
    'Feature': analysis_cols,
    'F_score': f_scores,
    'p_value': p_values
}).sort_values('F_score', ascending=False)

print("\nTop 20 features por ANOVA F-score:")
print(anova_results.head(20).to_string(index=False))

# Gráfico ANOVA
fig, ax = plt.subplots(figsize=(14, 10))
top_30 = anova_results.head(30)
ax.barh(top_30['Feature'][::-1], top_30['F_score'][::-1],
        color=sns.color_palette("magma", 30))
ax.set_xlabel('ANOVA F-score')
ax.set_title('Top 30 Features por ANOVA F-score\n(Método del paper original — Ferrag et al., 2022)')
plt.tight_layout()
plt.savefig(FIGURES_DIR / "anova_f_scores.png")
plt.show()

# Guardar resultados ANOVA
anova_results.to_csv(PROJECT_ROOT / "docs" / "anova_feature_ranking.csv", index=False)
print(f"📄 Ranking ANOVA guardado en docs/anova_feature_ranking.csv")

# %%
# === 3.8 Análisis de Leakage ===
print("=" * 80)
print("3.8 — ANÁLISIS DE LEAKAGE (feature → etiqueta)")
print("=" * 80)

# Correlación point-biserial para cada feature vs cada clase
print("Buscando features con correlación casi perfecta con la etiqueta...\n")

# Método: para cada feature, calcular mutual information o correlación con y
from sklearn.feature_selection import mutual_info_classif

mi_scores = mutual_info_classif(X_anova, y_encoded, random_state=42, n_neighbors=5)
mi_results = pd.DataFrame({
    'Feature': analysis_cols,
    'MI_score': mi_scores
}).sort_values('MI_score', ascending=False)

print("Top 20 features por Mutual Information (potencial leakage):")
print(mi_results.head(20).to_string(index=False))

# Detectar leakage: features con MI anormalmente alto
mi_mean = mi_results['MI_score'].mean()
mi_std = mi_results['MI_score'].std()
leakage_threshold = mi_mean + 3 * mi_std  # >3 std = sospechoso

leakage_candidates = mi_results[mi_results['MI_score'] > leakage_threshold]
print(f"\n⚠️ Features con MI > {leakage_threshold:.3f} (>3σ, potencial leakage):")
if len(leakage_candidates) > 0:
    for _, row in leakage_candidates.iterrows():
        print(f"  {row['Feature']}: MI={row['MI_score']:.4f}")
    print("\n  → Investigar si estas features son artefactos del testbed")
    print("  → Ejemplo: Modbus function codes específicos de ataque")
else:
    print("  ✅ No se detectó leakage evidente")

# Gráfico MI
fig, ax = plt.subplots(figsize=(14, 10))
top_30_mi = mi_results.head(30)
colors_mi = ['red' if mi > leakage_threshold else 'steelblue'
             for mi in top_30_mi['MI_score']]
ax.barh(top_30_mi['Feature'][::-1], top_30_mi['MI_score'][::-1], color=colors_mi[::-1])
ax.axvline(x=leakage_threshold, color='red', linestyle='--', label=f'Umbral leakage (3σ={leakage_threshold:.3f})')
ax.set_xlabel('Mutual Information')
ax.set_title('Mutual Information: Feature → Etiqueta\n(Rojo = potencial leakage)')
ax.legend()
plt.tight_layout()
plt.savefig(FIGURES_DIR / "leakage_analysis.png")
plt.show()

# %%
# === 3.9 Distribución temporal de ataques ===
print("=" * 80)
print("3.9 — DISTRIBUCIÓN TEMPORAL DE ATAQUES")
print("=" * 80)

# Buscar columnas temporales
time_cols = [c for c in df.columns if any(t in c.lower()
             for t in ['time', 'timestamp', 'date', 'epoch', 'frame.time'])]

if time_cols:
    print(f"Columnas temporales encontradas: {time_cols}")
    time_col = time_cols[0]
    print(f"Usando: '{time_col}'")

    # Intentar convertir a datetime
    try:
        df['_timestamp'] = pd.to_datetime(df[time_col], errors='coerce')
        valid_ts = df['_timestamp'].notna().sum()
        print(f"Timestamps válidos: {valid_ts:,} / {len(df):,}")

        if valid_ts > 0:
            # Distribución temporal por clase
            fig, ax = plt.subplots(figsize=(16, 8))
            for attack_type in df['Attack_type'].unique():
                mask = df['Attack_type'] == attack_type
                ts = df.loc[mask, '_timestamp'].dropna()
                if len(ts) > 0:
                    ax.hist(ts, bins=50, alpha=0.5, label=attack_type)
            ax.set_xlabel('Tiempo')
            ax.set_ylabel('Frecuencia')
            ax.set_title('Distribución Temporal de Ataques')
            ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left', fontsize=8)
            plt.tight_layout()
            plt.savefig(FIGURES_DIR / "temporal_distribution.png")
            plt.show()

            # ¿Los ataques están concentrados?
            for attack_type in df['Attack_type'].unique():
                mask = (df['Attack_type'] == attack_type) & df['_timestamp'].notna()
                ts = df.loc[mask, '_timestamp']
                if len(ts) > 1:
                    duration = (ts.max() - ts.min()).total_seconds()
                    print(f"  {attack_type:<30s} duración: {duration:.0f}s, "
                          f"muestras: {len(ts):,}")

        df.drop(columns=['_timestamp'], inplace=True, errors='ignore')
    except Exception as e:
        print(f"  No se pudo parsear timestamps: {e}")
else:
    print("ℹ️ No se encontraron columnas temporales en el dataset.")
    print("  El dataset DNN-EdgeIIoT pre-seleccionado no incluye timestamps.")
    print("  → Split train/test será estratificado por clase (sin temporal)")
    print("  → Si necesitas análisis temporal, usar archivos PCAP/CSV individuales")

# Buscar si hay un índice implícito (orden de captura)
print("\n--- Análisis de orden de captura (por índice) ---")
fig, ax = plt.subplots(figsize=(16, 6))
attack_map = {name: i for i, name in enumerate(df['Attack_type'].unique())}
y_plot = df['Attack_type'].map(attack_map).values
scatter = ax.scatter(range(len(y_plot)), y_plot, c=y_plot, cmap='tab20',
                     alpha=0.01, s=1, rasterized=True)
ax.set_yticks(list(attack_map.values()))
ax.set_yticklabels(list(attack_map.keys()), fontsize=8)
ax.set_xlabel('Índice de muestra (orden en el CSV)')
ax.set_title('Distribución de clases por orden de captura\n'
             '(Bandas = ataques concentrados en ventanas → riesgo en split)')
plt.tight_layout()
plt.savefig(FIGURES_DIR / "temporal_order_distribution.png")
plt.show()
print("📄 Si los ataques aparecen en bandas, usar shuffle antes del split")

# %% [markdown]
# ---
# ## FASE 3.5 — Correlación Feature-Etiqueta por Tipo de Ataque
# ---
# > Material para la memoria: qué features discriminan cada tipo de ataque.

# %%
print("=" * 80)
print("3.5 — FEATURES DISCRIMINANTES POR TIPO DE ATAQUE")
print("=" * 80)

# Para cada clase, calcular qué features tienen mayor diferencia vs resto
top_features_per_attack = {}
for attack in df['Attack_type'].unique():
    mask = df['Attack_type'] == attack
    # Diferencia de medias normalizada (effect size simplificado)
    means_attack = df.loc[mask, analysis_cols].mean()
    means_rest = df.loc[~mask, analysis_cols].mean()
    stds_all = df[analysis_cols].std().replace(0, 1)
    effect_size = ((means_attack - means_rest) / stds_all).abs().sort_values(ascending=False)
    top_features_per_attack[attack] = effect_size.head(5).index.tolist()

print("\nTop 5 features discriminantes por tipo de ataque (effect size):")
for attack, feats in top_features_per_attack.items():
    print(f"  {attack:<30s} → {', '.join(feats)}")

# Heatmap: top features por ataque
top_feats_all = list(set(f for feats in top_features_per_attack.values() for f in feats))
class_means_top = df.groupby('Attack_type')[top_feats_all].mean()

# Normalizar por columna para el heatmap
class_means_norm = (class_means_top - class_means_top.mean()) / class_means_top.std()

fig, ax = plt.subplots(figsize=(20, 10))
sns.heatmap(class_means_norm, cmap='RdYlBu_r', center=0, annot=False,
            xticklabels=True, yticklabels=True, ax=ax,
            cbar_kws={"label": "Z-score (media normalizada)"})
ax.set_title('Features discriminantes por tipo de ataque\n(Z-score de medias por clase)')
plt.xticks(rotation=90, fontsize=8)
plt.yticks(fontsize=9)
plt.tight_layout()
plt.savefig(FIGURES_DIR / "features_per_attack_heatmap.png")
plt.show()

# %% [markdown]
# ---
# ## FASE 4 — Preprocesamiento
# ### ⚠️ Orden correcto: Split PRIMERO, SMOTE solo en train
# ---

# %%
# === 4.1 Eliminar columnas innecesarias/constantes ===
print("=" * 80)
print("4.1 — ELIMINACIÓN DE COLUMNAS")
print("=" * 80)

cols_to_drop = list(set(constant_features + single_value))

# Columnas no informativas comunes en datasets de red
non_informative = ['frame.time', 'ip.src_host', 'ip.dst_host',
                   'arp.src.proto_ipv4', 'arp.dst.proto_ipv4',
                   'Attack_label']  # Label binario si existe
for col in non_informative:
    if col in df.columns and col not in cols_to_drop:
        cols_to_drop.append(col)

# Eliminar features con leakage identificado (si las hay)
if len(leakage_candidates) > 0:
    print("\n⚠️ Features con leakage detectado — evaluar si eliminar:")
    for _, row in leakage_candidates.iterrows():
        print(f"  {row['Feature']}: MI={row['MI_score']:.4f}")
    # NO eliminamos automáticamente: el usuario debe decidir
    # cols_to_drop.extend(leakage_candidates['Feature'].tolist())

existing_drops = [c for c in cols_to_drop if c in df.columns]
print(f"\nEliminando {len(existing_drops)} columnas: {existing_drops}")
df_clean = df.drop(columns=existing_drops, errors='ignore')

# Separar features y etiqueta
X = df_clean.drop(columns=['Attack_type'])
y = df_clean['Attack_type']
print(f"\nX shape: {X.shape}")
print(f"y shape: {y.shape}, clases: {y.nunique()}")

# %%
# === 4.2 SPLIT TRAIN/TEST — ANTES de cualquier transformación ===
print("=" * 80)
print("4.2 — SPLIT TRAIN/TEST (PRIMERO, sin tocar nada)")
print("=" * 80)

from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y, shuffle=True
)
print(f"\nTrain: {X_train.shape[0]:,} ({X_train.shape[0]/len(X)*100:.0f}%)")
print(f"Test:  {X_test.shape[0]:,} ({X_test.shape[0]/len(X)*100:.0f}%)")
print(f"\nDistribución en train:")
print(y_train.value_counts().to_string())
print(f"\nDistribución en test:")
print(y_test.value_counts().to_string())

# %%
# === 4.3 Encoding de categóricas (fit en train, transform en ambos) ===
print("=" * 80)
print("4.3 — ENCODING DE VARIABLES CATEGÓRICAS")
print("=" * 80)

cat_cols = X_train.select_dtypes(include=['object', 'category']).columns.tolist()
print(f"Columnas categóricas: {len(cat_cols)}")

if cat_cols:
    from sklearn.preprocessing import OrdinalEncoder
    oe = OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1)
    X_train[cat_cols] = oe.fit_transform(X_train[cat_cols])
    X_test[cat_cols] = oe.transform(X_test[cat_cols])
    print(f"  ✅ Encoded {len(cat_cols)} columnas: {cat_cols}")
else:
    print("  ℹ️ No hay columnas categóricas (ya son todas numéricas)")

# Imputar NaN con mediana (fit en train)
from sklearn.impute import SimpleImputer
imputer = SimpleImputer(strategy='median')
X_train_cols = X_train.columns
X_train = pd.DataFrame(imputer.fit_transform(X_train), columns=X_train_cols, index=X_train.index)
X_test = pd.DataFrame(imputer.transform(X_test), columns=X_train_cols, index=X_test.index)
print(f"  ✅ NaN imputados con mediana (fit en train)")

# %%
# === 4.4 Normalización (fit en train, transform en ambos) ===
print("=" * 80)
print("4.4 — NORMALIZACIÓN")
print("=" * 80)

from sklearn.preprocessing import StandardScaler

scaler = StandardScaler()
feature_names = X_train.columns
X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=feature_names, index=X_train.index)
X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=feature_names, index=X_test.index)
print(f"  ✅ StandardScaler — fit en train, transform en train+test")
print(f"  Train: mean≈{X_train_scaled.mean().mean():.6f}, std≈{X_train_scaled.std().mean():.4f}")

# Encoding de la etiqueta
le = LabelEncoder()
y_train_enc = le.fit_transform(y_train)
y_test_enc = le.transform(y_test)
print(f"\n  Clases codificadas: {dict(zip(le.classes_, le.transform(le.classes_)))}")

# %% [markdown]
# ---
# ## FASE 5 — Selección de Features
# ### ⚠️ Después de preprocesamiento, ANTES de SMOTE
# ---

# %%
# === 5.1 Eliminar features altamente correlacionadas entre sí ===
print("=" * 80)
print("5.1 — ELIMINACIÓN DE FEATURES REDUNDANTES (|r| > 0.95)")
print("=" * 80)

corr_train = X_train_scaled.corr(method='pearson').abs()
upper = corr_train.where(np.triu(np.ones(corr_train.shape), k=1).astype(bool))
to_drop_corr = [col for col in upper.columns if any(upper[col] > 0.95)]
print(f"\nFeatures a eliminar por alta correlación mutua: {len(to_drop_corr)}")
if to_drop_corr:
    for col in to_drop_corr[:15]:
        print(f"  {col}")
    if len(to_drop_corr) > 15:
        print(f"  ... y {len(to_drop_corr) - 15} más")

X_train_sel = X_train_scaled.drop(columns=to_drop_corr)
X_test_sel = X_test_scaled.drop(columns=to_drop_corr)
print(f"\nFeatures restantes: {X_train_sel.shape[1]}")

# %%
# === 5.2 ANOVA + RFE ===
print("=" * 80)
print("5.2 — SELECCIÓN DE FEATURES: ANOVA + Importancia de Árboles")
print("=" * 80)

# ANOVA sobre el train set
f_scores_train, p_vals_train = f_classif(X_train_sel, y_train_enc)
anova_train = pd.DataFrame({
    'Feature': X_train_sel.columns,
    'F_score': f_scores_train,
    'p_value': p_vals_train
}).sort_values('F_score', ascending=False)
print("\nTop 20 features ANOVA (train set):")
print(anova_train.head(20).to_string(index=False))

# Importancia con LightGBM (rápido)
print("\n--- Importancia de features con LightGBM ---")
import lightgbm as lgb

lgb_temp = lgb.LGBMClassifier(n_estimators=100, max_depth=6, random_state=42,
                               verbosity=-1, n_jobs=-1)
lgb_temp.fit(X_train_sel, y_train_enc)

lgb_importance = pd.DataFrame({
    'Feature': X_train_sel.columns,
    'Importance': lgb_temp.feature_importances_
}).sort_values('Importance', ascending=False)

print("\nTop 20 features por LightGBM importance:")
print(lgb_importance.head(20).to_string(index=False))

# Gráfico comparativo
fig, axes = plt.subplots(1, 2, figsize=(18, 10))

top20_anova = anova_train.head(20)
axes[0].barh(top20_anova['Feature'][::-1], top20_anova['F_score'][::-1],
             color=sns.color_palette("magma", 20))
axes[0].set_xlabel('ANOVA F-score')
axes[0].set_title('Top 20 Features — ANOVA')

top20_lgb = lgb_importance.head(20)
axes[1].barh(top20_lgb['Feature'][::-1], top20_lgb['Importance'][::-1],
             color=sns.color_palette("viridis", 20))
axes[1].set_xlabel('LightGBM Importance')
axes[1].set_title('Top 20 Features — LightGBM')

plt.tight_layout()
plt.savefig(FIGURES_DIR / "feature_selection_comparison.png")
plt.show()

# Seleccionar top N features (intersección de ambos métodos)
N_FEATURES = min(30, X_train_sel.shape[1])
top_anova = set(anova_train.head(N_FEATURES)['Feature'])
top_lgb = set(lgb_importance.head(N_FEATURES)['Feature'])
consensus_features = list(top_anova | top_lgb)  # Unión para no perder info
print(f"\n📊 Features seleccionadas: {len(consensus_features)}")
print(f"   ANOVA top-{N_FEATURES}: {len(top_anova)}")
print(f"   LightGBM top-{N_FEATURES}: {len(top_lgb)}")
print(f"   Intersección: {len(top_anova & top_lgb)}")
print(f"   Unión (usadas): {len(consensus_features)}")

X_train_final = X_train_sel[consensus_features]
X_test_final = X_test_sel[consensus_features]

# %%
# === 5.3 Tratamiento del desbalanceo — SMOTE solo en train ===
print("=" * 80)
print("5.3 — TRATAMIENTO DEL DESBALANCEO (SMOTE en train)")
print("=" * 80)

from imblearn.over_sampling import SMOTE, ADASYN
from imblearn.under_sampling import RandomUnderSampler
from imblearn.combine import SMOTETomek

print(f"\nDistribución ANTES de resampling (train):")
print(pd.Series(y_train_enc).value_counts().sort_index().to_string())

# Estrategia combinada: submuestrear mayoritaria + SMOTE minoritarias
# Primero verificar que todas las clases tienen suficientes muestras
min_class_count = pd.Series(y_train_enc).value_counts().min()
k_neighbors = min(5, min_class_count - 1) if min_class_count > 1 else 1
print(f"\nClase minoritaria en train: {min_class_count} muestras")
print(f"k_neighbors para SMOTE: {k_neighbors}")

try:
    smote = SMOTE(random_state=42, k_neighbors=k_neighbors, n_jobs=-1)
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train_final, y_train_enc)
    print(f"\n✅ SMOTE aplicado exitosamente")
    print(f"   Train antes: {len(X_train_final):,}")
    print(f"   Train después: {len(X_train_resampled):,}")
    print(f"\nDistribución DESPUÉS de SMOTE:")
    print(pd.Series(y_train_resampled).value_counts().sort_index().to_string())
except Exception as e:
    print(f"\n⚠️ SMOTE falló: {e}")
    print("   Usando class_weight='balanced' en los modelos como alternativa")
    X_train_resampled = X_train_final.values if hasattr(X_train_final, 'values') else X_train_final
    y_train_resampled = y_train_enc

# Guardar datasets procesados
print(f"\n💾 Datasets listos para modelado:")
print(f"   X_train_resampled: {X_train_resampled.shape}")
print(f"   X_test_final: {X_test_final.shape}")

# %% [markdown]
# ---
# ## FASE 6 — Modelado
# ### Baseline: DT, RF, XGBoost, LightGBM + MLP (DL)
# ### ⚠️ Sin LSTM — el dataset es de flujos, no series temporales
# ---

# %%
print("=" * 80)
print("FASE 6 — MODELADO")
print("=" * 80)

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score,
                             accuracy_score, roc_auc_score)
import xgboost as xgb

X_test_np = X_test_final.values if hasattr(X_test_final, 'values') else X_test_final
X_train_np = X_train_resampled if isinstance(X_train_resampled, np.ndarray) else X_train_resampled.values

MODELS = {
    "Decision Tree": DecisionTreeClassifier(
        max_depth=20, random_state=42, class_weight='balanced'
    ),
    "Random Forest": RandomForestClassifier(
        n_estimators=200, max_depth=20, random_state=42,
        class_weight='balanced', n_jobs=-1
    ),
    "XGBoost": xgb.XGBClassifier(
        n_estimators=200, max_depth=8, learning_rate=0.1,
        random_state=42, use_label_encoder=False,
        eval_metric='mlogloss', n_jobs=-1, tree_method='hist'
    ),
    "LightGBM": lgb.LGBMClassifier(
        n_estimators=200, max_depth=8, learning_rate=0.1,
        random_state=42, class_weight='balanced',
        verbosity=-1, n_jobs=-1
    ),
    "MLP": MLPClassifier(
        hidden_layer_sizes=(256, 128, 64), max_iter=100,
        random_state=42, early_stopping=True,
        validation_fraction=0.1, batch_size=256,
        learning_rate='adaptive', alpha=0.001
    ),
}

results = {}
trained_models = {}

for name, model in MODELS.items():
    print(f"\n{'─' * 60}")
    print(f"🔧 Entrenando: {name}")
    print(f"{'─' * 60}")

    # Entrenar
    t_start = time.perf_counter()
    model.fit(X_train_np, y_train_resampled)
    train_time = time.perf_counter() - t_start
    print(f"  Tiempo de entrenamiento: {train_time:.2f}s")

    # Predecir
    t_start = time.perf_counter()
    y_pred = model.predict(X_test_np)
    inference_total = time.perf_counter() - t_start
    inference_per_sample_ms = inference_total / len(X_test_np) * 1000

    # Métricas
    acc = accuracy_score(y_test_enc, y_pred)
    f1_macro = f1_score(y_test_enc, y_pred, average='macro')
    f1_weighted = f1_score(y_test_enc, y_pred, average='weighted')
    precision_macro = precision_score(y_test_enc, y_pred, average='macro', zero_division=0)
    recall_macro = recall_score(y_test_enc, y_pred, average='macro', zero_division=0)

    results[name] = {
        'Accuracy': acc,
        'F1_macro': f1_macro,
        'F1_weighted': f1_weighted,
        'Precision_macro': precision_macro,
        'Recall_macro': recall_macro,
        'Train_time_s': round(train_time, 2),
        'Inference_ms_per_sample': round(inference_per_sample_ms, 4),
        'Inference_total_s': round(inference_total, 3)
    }
    trained_models[name] = model

    print(f"  Accuracy:    {acc:.4f}")
    print(f"  F1 (macro):  {f1_macro:.4f}")
    print(f"  F1 (weight): {f1_weighted:.4f}")
    print(f"  Precision:   {precision_macro:.4f}")
    print(f"  Recall:      {recall_macro:.4f}")
    print(f"  ⏱️ Inferencia: {inference_per_sample_ms:.4f} ms/muestra")

# Tabla comparativa
results_df = pd.DataFrame(results).T
results_df = results_df.sort_values('F1_macro', ascending=False)
print("\n" + "=" * 80)
print("TABLA COMPARATIVA DE MODELOS")
print("=" * 80)
print(results_df.to_string())
results_df.to_csv(PROJECT_ROOT / "docs" / "model_comparison.csv")
print(f"\n📄 Tabla guardada en docs/model_comparison.csv")

# Gráfico comparativo
fig, axes = plt.subplots(1, 3, figsize=(20, 7))

# F1 macro
results_df['F1_macro'].plot(kind='barh', ax=axes[0],
    color=sns.color_palette("viridis", len(results_df)))
axes[0].set_xlabel('F1 Score (macro)')
axes[0].set_title('F1 Macro por Modelo')
axes[0].set_xlim(0, 1)

# Tiempo de inferencia
results_df['Inference_ms_per_sample'].plot(kind='barh', ax=axes[1],
    color=sns.color_palette("magma", len(results_df)))
axes[1].set_xlabel('ms por muestra')
axes[1].set_title('Tiempo de Inferencia\n(clave para Raspberry Pi)')

# Accuracy
results_df['Accuracy'].plot(kind='barh', ax=axes[2],
    color=sns.color_palette("cividis", len(results_df)))
axes[2].set_xlabel('Accuracy')
axes[2].set_title('Accuracy por Modelo')
axes[2].set_xlim(0, 1)

plt.tight_layout()
plt.savefig(FIGURES_DIR / "model_comparison.png")
plt.show()

# %% [markdown]
# ---
# ## FASE 7 — Evaluación y Análisis de Resultados
# ---

# %%
# === 7.1 Mejor modelo — Classification Report detallado ===
print("=" * 80)
print("7.1 — CLASSIFICATION REPORT DETALLADO")
print("=" * 80)

best_model_name = results_df.index[0]
best_model = trained_models[best_model_name]
y_pred_best = best_model.predict(X_test_np)

print(f"\nMejor modelo: {best_model_name}")
print(f"\n{classification_report(y_test_enc, y_pred_best, target_names=le.classes_, zero_division=0)}")

# %%
# === 7.2 Matrices de confusión ===
print("=" * 80)
print("7.2 — MATRICES DE CONFUSIÓN")
print("=" * 80)

fig, axes = plt.subplots(2, 3, figsize=(24, 16))
axes = axes.flatten()

for idx, (name, model) in enumerate(trained_models.items()):
    if idx >= 5:
        break
    y_pred_m = model.predict(X_test_np)
    cm = confusion_matrix(y_test_enc, y_pred_m)
    # Normalizar por fila
    cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    cm_norm = np.nan_to_num(cm_norm)

    sns.heatmap(cm_norm, annot=True, fmt='.2f', cmap='Blues',
                xticklabels=le.classes_, yticklabels=le.classes_,
                ax=axes[idx], vmin=0, vmax=1, cbar_kws={"shrink": 0.8})
    axes[idx].set_title(f'{name}\nF1={results[name]["F1_macro"]:.4f}', fontsize=11)
    axes[idx].set_xlabel('Predicho')
    axes[idx].set_ylabel('Real')
    axes[idx].tick_params(axis='both', labelsize=6)
    plt.setp(axes[idx].get_xticklabels(), rotation=45, ha='right')
    plt.setp(axes[idx].get_yticklabels(), rotation=0)

# Ocultar subplot vacío
if len(trained_models) < 6:
    axes[5].set_visible(False)

plt.suptitle('Matrices de Confusión Normalizadas — Todos los Modelos', fontsize=16, y=1.02)
plt.tight_layout()
plt.savefig(FIGURES_DIR / "confusion_matrices.png")
plt.show()

# %%
# === 7.3 ROC-AUC y PR-AUC ===
print("=" * 80)
print("7.3 — ROC-AUC Y PR-AUC")
print("=" * 80)

from sklearn.metrics import roc_auc_score, average_precision_score
from sklearn.preprocessing import label_binarize

y_test_bin = label_binarize(y_test_enc, classes=range(len(le.classes_)))
n_classes = y_test_bin.shape[1]

auc_results = {}
for name, model in trained_models.items():
    try:
        if hasattr(model, 'predict_proba'):
            y_proba = model.predict_proba(X_test_np)
            roc = roc_auc_score(y_test_bin, y_proba, multi_class='ovr', average='macro')
            pr = average_precision_score(y_test_bin, y_proba, average='macro')
        else:
            roc = pr = float('nan')
        auc_results[name] = {'ROC-AUC': round(roc, 4), 'PR-AUC': round(pr, 4)}
        print(f"  {name:<20s} ROC-AUC: {roc:.4f}  PR-AUC: {pr:.4f}")
    except Exception as e:
        print(f"  {name:<20s} Error: {e}")
        auc_results[name] = {'ROC-AUC': float('nan'), 'PR-AUC': float('nan')}

# %%
# === 7.4 FPR Operacional ===
print("=" * 80)
print("7.4 — FALSE POSITIVE RATE (FPR) OPERACIONAL")
print("=" * 80)
print("(Clave para IDS: qué porcentaje de tráfico Normal se clasifica como ataque)\n")

normal_class_idx = list(le.classes_).index('Normal') if 'Normal' in le.classes_ else 0
for name, model in trained_models.items():
    y_pred_m = model.predict(X_test_np)
    # FPR = FP / (FP + TN) para la clase Normal
    normal_mask = y_test_enc == normal_class_idx
    if normal_mask.sum() > 0:
        fp = ((y_pred_m != normal_class_idx) & normal_mask).sum()
        tn = ((y_pred_m == normal_class_idx) & normal_mask).sum()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        print(f"  {name:<20s} FPR: {fpr:.4f} ({fpr*100:.2f}%)")
    else:
        print(f"  {name:<20s} No se encontró clase 'Normal'")

# %%
# === 7.5 SHAP — Explicabilidad ===
print("=" * 80)
print("7.5 — SHAP: EXPLICABILIDAD DEL MEJOR MODELO")
print("=" * 80)

import shap

# Usar el mejor modelo basado en árboles para SHAP (mucho más eficiente)
tree_models = {k: v for k, v in trained_models.items()
               if k in ["LightGBM", "XGBoost", "Random Forest"]}

if tree_models:
    shap_model_name = list(tree_models.keys())[0]
    shap_model = tree_models[shap_model_name]
    print(f"Modelo para SHAP: {shap_model_name}")

    # Sample para SHAP (es costoso computacionalmente)
    shap_sample_size = min(1000, len(X_test_np))
    X_shap = X_test_np[:shap_sample_size]
    feature_labels = consensus_features

    try:
        explainer = shap.TreeExplainer(shap_model)
        shap_values = explainer.shap_values(X_shap)

        # Summary plot
        fig, ax = plt.subplots(figsize=(14, 10))
        # Para multiclase, shap_values es una lista
        if isinstance(shap_values, list):
            shap.summary_plot(shap_values, X_shap, feature_names=feature_labels,
                            plot_type="bar", show=False, max_display=20)
        else:
            shap.summary_plot(shap_values, X_shap, feature_names=feature_labels,
                            show=False, max_display=20)
        plt.title(f'SHAP Feature Importance — {shap_model_name}')
        plt.tight_layout()
        plt.savefig(FIGURES_DIR / "shap_importance.png")
        plt.show()
        print(f"📄 SHAP plot guardado en docs/figures/shap_importance.png")
    except Exception as e:
        print(f"⚠️ Error en SHAP: {e}")
        print("   SHAP puede fallar con datasets muy grandes. Intentar con menos muestras.")
else:
    print("⚠️ No hay modelos basados en árboles para SHAP")

# %% [markdown]
# ---
# ## FASE 8 — Documentación para la Memoria
# ### Comparación crítica con resultados del paper original
# ---

# %%
print("=" * 80)
print("FASE 8 — COMPARACIÓN CON PAPER ORIGINAL (Ferrag et al., 2022)")
print("=" * 80)

# Resultados reportados en el paper original
PAPER_RESULTS = {
    "DT (Paper)":   {"Accuracy": 0.9392, "Precision": 0.9450, "Recall": 0.9392, "F1": 0.9376},
    "RF (Paper)":   {"Accuracy": 0.9475, "Precision": 0.9541, "Recall": 0.9475, "F1": 0.9463},
    "DNN (Paper)":  {"Accuracy": 0.9523, "Precision": 0.9543, "Recall": 0.9523, "F1": 0.9515},
    "KNN (Paper)":  {"Accuracy": 0.6168, "Precision": 0.5746, "Recall": 0.6168, "F1": 0.5607},
}

# Nuestros resultados
our_results = {}
for name in results:
    our_results[f"{name} (Nuestro)"] = {
        "Accuracy": results[name]['Accuracy'],
        "Precision": results[name]['Precision_macro'],
        "Recall": results[name]['Recall_macro'],
        "F1": results[name]['F1_macro'],
        "Inference_ms": results[name]['Inference_ms_per_sample']
    }

# Combinar
comparison = pd.DataFrame({**PAPER_RESULTS, **our_results}).T
comparison = comparison.round(4)

print("\n📊 TABLA COMPARATIVA: Nuestros resultados vs. Paper original")
print("=" * 80)
print(comparison.to_string())

comparison.to_csv(PROJECT_ROOT / "docs" / "paper_comparison.csv")
print(f"\n📄 Tabla guardada en docs/paper_comparison.csv")

# Análisis crítico
print("\n" + "=" * 80)
print("ANÁLISIS CRÍTICO")
print("=" * 80)
print("""
📝 NOTAS PARA LA MEMORIA:

1. REPRODUCIBILIDAD del F1 > 99% del paper:
   - El paper reporta DNN con F1=0.9515 (multiclase, 15 clases).
   - Versiones más recientes del paper/dataset reportan F1 > 99% pero
     potencialmente incluyen features con alta mutual information que
     podrían constituir leakage (verificar sección 3.8 de este notebook).

2. DIFERENCIAS METODOLÓGICAS:
   - Paper: 1176 features → 61 por correlación
   - Nuestro: 61 features → N por ANOVA + LightGBM + correlación
   - Paper: Split no especificado (posible leakage temporal)
   - Nuestro: 80/20 estratificado con shuffle

3. VALOR AÑADIDO de este TFM:
   - Tiempo de inferencia por muestra (ms) — crítico para Raspberry Pi
   - Análisis de leakage no presente en el paper original
   - SMOTE aplicado correctamente (solo en train)
   - SHAP para explicabilidad

4. RECOMENDACIÓN para despliegue en Raspberry Pi:
   - Priorizar LightGBM o Random Forest (balance F1 vs inference time)
   - Evitar MLP/DNN si el tiempo de inferencia es crítico
""")

# %%
# === Gráfico final: Nuestros resultados vs Paper ===
fig, ax = plt.subplots(figsize=(14, 8))

paper_names = list(PAPER_RESULTS.keys())
our_names = list(our_results.keys())

# F1 scores
paper_f1 = [PAPER_RESULTS[n]["F1"] for n in paper_names]
our_f1 = [our_results[n]["F1"] for n in our_names]

all_names = paper_names + our_names
all_f1 = paper_f1 + our_f1
colors = ['#2196F3'] * len(paper_names) + ['#4CAF50'] * len(our_names)

bars = ax.barh(all_names[::-1], all_f1[::-1], color=colors[::-1])
ax.set_xlabel('F1 Score (macro)')
ax.set_title('Comparación con Paper Original (Ferrag et al., 2022)')
ax.axvline(x=0.95, color='red', linestyle='--', alpha=0.5, label='F1 = 0.95')

# Leyenda
from matplotlib.patches import Patch
legend_elements = [Patch(facecolor='#2196F3', label='Paper original'),
                   Patch(facecolor='#4CAF50', label='Este TFM')]
ax.legend(handles=legend_elements, loc='lower right')

for bar, val in zip(bars, all_f1[::-1]):
    ax.text(bar.get_width() + 0.005, bar.get_y() + bar.get_height()/2,
            f'{val:.4f}', va='center', fontsize=9)

plt.tight_layout()
plt.savefig(FIGURES_DIR / "paper_comparison.png")
plt.show()

# %%
# === Guardar modelos y artefactos finales ===
print("=" * 80)
print("GUARDADO DE ARTEFACTOS FINALES")
print("=" * 80)

import joblib

models_dir = PROJECT_ROOT / "data" / "models"
models_dir.mkdir(parents=True, exist_ok=True)

for name, model in trained_models.items():
    model_path = models_dir / f"{name.lower().replace(' ', '_')}_model.joblib"
    joblib.dump(model, model_path)
    print(f"  💾 {name} → {model_path}")

# Guardar scaler y encoder
joblib.dump(scaler, models_dir / "scaler.joblib")
joblib.dump(le, models_dir / "label_encoder.joblib")
joblib.dump(consensus_features, models_dir / "selected_features.joblib")
print(f"  💾 Scaler → {models_dir / 'scaler.joblib'}")
print(f"  💾 LabelEncoder → {models_dir / 'label_encoder.joblib'}")
print(f"  💾 Features → {models_dir / 'selected_features.joblib'}")

# Resumen final
print("\n" + "=" * 80)
print("✅ ANÁLISIS COMPLETO FINALIZADO")
print("=" * 80)
print(f"""
📊 Resumen:
   Dataset: Edge-IIoTset ({df.shape[0]:,} muestras, {df.shape[1]} columnas)
   Clases: {len(le.classes_)} ({', '.join(le.classes_)})
   Features seleccionadas: {len(consensus_features)}
   Mejor modelo: {best_model_name} (F1={results[best_model_name]['F1_macro']:.4f})

📁 Archivos generados:
   docs/figures/*.png — Gráficos para la memoria
   docs/attack_taxonomy.json — Taxonomía de ataques
   docs/class_distribution.csv — Distribución de clases
   docs/anova_feature_ranking.csv — Ranking ANOVA
   docs/model_comparison.csv — Comparativa de modelos
   docs/paper_comparison.csv — Comparación con paper
   data/models/*.joblib — Modelos entrenados
   data/processed/edge_iiot_dataset.parquet — Dataset en Parquet
""")


