p = r"D:\ARTICULO_WAZUH\documento\contenido.txt"
s = open(p, encoding="utf-8").read()
old = "De 626 candidatos iniciales se retuvieron documentos con resumen, tipo elegible y texto completo extraíble. Una búsqueda complementaria añadió trabajos sobre despliegue distribuido, movimiento lateral y origen de los datos. Cada DOI se verificó en Crossref y el título se comparó con el PDF. Se excluyeron tres documentos ajenos a ciberseguridad captados por coincidencias léxicas, y cuatro artículos fueron localizados y aportados por el grupo."
new = """Cada DOI del corpus final se verificó en Crossref y el título se comparó con el PDF.

El triaje siguió los criterios de la {{T:triaje}} y su recorrido se resume en la {{F:seleccion}}. Se incluyeron artículos de revista, ponencias, revisiones, preprints y capítulos con resumen, enlace a PDF abierto, texto extraíble y pertinencia temática; las consultas de Wazuh exigieron mencionar la plataforma en el título o el resumen. Los elegibles se ordenaron por revisión por pares, presencia de Wazuh en el título, citas y año, y se descargaron hasta completar cupos por tema: 50 de Wazuh y 30 de temas relacionados. El detalle de cada registro, con su decisión y motivo, se presenta en el Anexo A (`Anexo_A_Triaje_de_Candidatos.csv`).

La revisión manual del corpus inicial retiró 20 documentos: 3 ajenos a ciberseguridad captados por coincidencias léxicas, 12 con aporte limitado al tema multiservidor y 5 sustituidos a propuesta del grupo. Estos últimos se eligieron de una lista de 12 artículos, de los cuales 7 no se incorporaron porque no se pudo obtener su texto completo. Para reemplazar los retirados se usaron 3 candidatos de la misma base, 12 artículos de una búsqueda complementaria sobre despliegue distribuido, movimiento lateral y origen de los datos, y los 5 artículos de la lista. La selección no fue, por tanto, completamente automática, y estas decisiones manuales forman parte del proceso declarado.

@fig seleccion|d_seleccion.png|Diagrama de flujo de la selección de artículos|Elaboración propia.

@tabla triaje|Etapas del triaje bibliográfico y registros restantes
| Etapa | Criterio | Retirados | Restantes |
| Identificación | Nueve consultas en OpenAlex, acceso abierto, desde 2018 | — | 1 142 |
| Consolidación | Duplicados entre consultas o sin enlace a PDF | 516 | 626 |
| Tipo documental | Tesis, libros, editoriales y otros no elegibles | 67 | 559 |
| Resumen | Sin resumen disponible | 8 | 551 |
| Pertinencia | Sin términos de ciberseguridad (2); consulta SIEM sin mención de SIEM (2) | 4 | 547 |
| Título repetido | Mismo título con otro identificador | 1 | 546 |
| Cupo temático | Elegibles no intentados por cupo ya completo | 383 | 163 |
| Acceso al texto | Sin PDF válido (63); excedente de cupo (20) | 83 | 80 |
| Revisión manual | Ajenos (3); aporte limitado (12); sustituidos (5) | 20 | 60 |
| Incorporación | Misma base (3); búsqueda complementaria (12); lista del grupo (5) | +20 | 80 |
@nota Elaboración propia. Los motivos de falla de descarga se registraron de forma agregada, por lo que el Anexo A no los distingue por artículo. De las búsquedas complementarias solo se conservan los artículos seleccionados.
"""
assert s.count(old) == 1
s = s.replace(old, new)
a = "No se aplicó un protocolo PRISMA completo y la calidad"
assert s.count(a) == 1
s = s.replace(a, "No se aplicó un protocolo PRISMA completo, no hubo doble revisión independiente y la calidad")
open(p, "w", encoding="utf-8").write(s)
