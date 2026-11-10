# Monitoreo distribuido con Wazuh en cuatro servidores

Materiales del documento técnico de la Unidad II del curso SI-985 Seguridad de Tecnología de Información (Universidad Privada de Tacna, 2026): *Diseño de una solución de monitoreo distribuido con Wazuh en cuatro servidores para la correlación de alertas y la detección de ataques multietapa con aprendizaje automático*.

Autores: Anampa Pancca, David Jordan · Vargas Gutiérrez, Ángel José · Salas Jimenez, Walter Emmanuel · Huanca Merma, Gregory Brandon.

## Descargas

| Archivo | Contenido |
|---|---|
| [documento/Articulo_Wazuh_Cuatro_Servidores.pdf](documento/Articulo_Wazuh_Cuatro_Servidores.pdf) | Documento técnico (PDF) |
| [documento/Articulo_Wazuh_Cuatro_Servidores.docx](documento/Articulo_Wazuh_Cuatro_Servidores.docx) | Documento técnico (Word) |
| [documento/Anexo_A_Triaje_de_Candidatos.csv](documento/Anexo_A_Triaje_de_Candidatos.csv) | Decisión y motivo para cada uno de los 639 registros bibliográficos evaluados |
| [documento/Anexo_B_Verificacion_de_Referencias.csv](documento/Anexo_B_Verificacion_de_Referencias.csv) | Datos de registro (Crossref, DataCite o sitio oficial) consultados el 10/11/2026 para cada referencia |
| [metadata/corpus_80.csv](metadata/corpus_80.csv) | Catálogo de los 80 artículos del corpus con DOI y SHA-256 del PDF |
| [metadata/ENLACES.md](metadata/ENLACES.md) | Enlaces a los 80 artículos y a los 3 conjuntos de datos |

Sitio del proyecto: https://angelvargasgutierrez.github.io/wazuh-cuatro-servidores/

## Estructura

- `scripts/`: código de selección bibliográfica, prueba de concepto de aprendizaje automático, validación de reglas de red, figuras y generación del documento.
- `resultados/`: ventanas de 60 s por rol (`ventanas_multiservidor.csv.gz`), métricas por método y por escenario, cobertura por fase de ataque, mediciones del clúster de referencia y validación analítica de las reglas del cortafuegos.
- `figuras/`: diagramas y gráficos del documento.
- `metadata/`: catálogo del corpus y enlaces.

## Datos de origen

Los conjuntos de datos no se incluyen en el repositorio; se descargan de Zenodo:

- AIT Alert Data Set: https://doi.org/10.5281/zenodo.8263181 (CC BY 4.0)
- Task-specific dataset for Structural Leakage in Host Intrusion Alert Corpora: https://doi.org/10.5281/zenodo.19691904 (CC BY 4.0)
- Dataset and Scripts for "Timeliness Fails Before Compute": https://doi.org/10.5281/zenodo.22763421 (CC BY 4.0)

Los 80 artículos del corpus son de acceso abierto y se enlazan por DOI en `metadata/ENLACES.md`; no se redistribuyen sus PDF.

## Reproducir la prueba de concepto

Requiere Python 3.13 con `pandas`, `scikit-learn`, `scipy`, `matplotlib` y `pymupdf`.

1. Descargar `ait_ads.zip` y `labels.csv` del AIT Alert Data Set en `datasets/ait_ads/`.
2. `python scripts/poc_ml.py`: depura las alertas, construye las ventanas y ejecuta la primera ronda.
3. `python scripts/poc_ml2.py`: ejecuta la validación por escenario no visto con umbral anidado y genera `resultados/resultados_modelos_v2.csv`, `resultados_por_escenario_v2.csv` y `cobertura_fases_v2.csv`.
4. `python scripts/charts.py`: genera los gráficos de resultados.
5. `python scripts/valida_red.py`: evalúa los 27 flujos de red contra las reglas FW-01 a FW-11 y escribe `resultados/validacion_red.csv`.

Las rutas de los scripts apuntan a `D:\ARTICULO_WAZUH`; ajústelas a su entorno.

## Licencias

Código bajo licencia MIT. El documento técnico y las figuras son obra de los autores para fines académicos. Los conjuntos de datos conservan sus licencias originales.
