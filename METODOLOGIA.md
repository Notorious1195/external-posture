# Modelo de postura externa v24

Este índice mide cumplimiento acreditado de controles públicos. No estima probabilidad de ataque, seguridad interna ni equivale a BitSight. Ningún modelo de IA calcula ni modifica puntuaciones.

Para cada control y activo:
- Evaluado: crédito = 1 − penalización, con penalización entre 0 y 1.
- No evaluado: crédito = 0. Se mantiene la distinción entre falta de evidencia e incumplimiento observado.
- No aplica: se excluye únicamente con justificación.

Se promedian los créditos por tipo de control dentro de cada dimensión y se ponderan por su peso interno. Así una gran cantidad de URLs no multiplica una única condición. S_d = 100 × Σ(w_c × promedio de crédito por activo) / Σw_c.

P = Σ(w_d × S_d) / Σw_d para las dimensiones aplicables. Pesos: exposiciones web 30%, servicios 25%, cabeceras 20%, transporte/TLS 15%, correo/DNS 10%. Una dimensión con todos sus controles justificados como No aplica se excluye; no se le asigna 100. Una dimensión con controles pendientes conserva estos en el denominador con cero crédito.

SPF, DMARC y DKIM tienen pesos iguales: un control plenamente cumplido y dos pendientes da 33,33. Una comprobación ejecutada no es necesariamente cumplida. Cumplimiento parcial conserva un valor intermedio y se explica.

HTTP que sirve contenido sin redirigir a HTTPS incumple T-03 con crédito cero. T-01/T-02 del endpoint HTTP son No aplica; el mismo hecho no se vuelve a penalizar en servicios. Puerto 80 usado solo para redirigir a HTTPS válido no implica incumplimiento por sí solo.

V-01 pesa 3; cada prueba específica de archivo pesa 1. Alertas ZAP: Low/Medium/High=.20/.60/.90; confianza Low/Medium/High=.50/.75/1. Se toma el peor valor por regla y origen, combinando familias por 1−producto(1−p), hasta .95. Es un índice experimental, NO probabilidad. Informativas, falsos positivos y fuera de origen no penalizan. Reglas 10020/10021 de cabeceras ya medidas no vuelven a penalizar V. Cero alertas pasivas no demuestra seguridad.

Categorías: 85–100 Favorable; 65–<85 Moderada; 40–<65 Deficiente; 0–<40 Crítica. Describen cumplimiento acreditado, no certeza de exposición ni una clasificación de vulnerabilidades CVSS. La cobertura se muestra aparte y el rango superior representa únicamente la hipótesis de que los pendientes cumplieran.

ZAP por sitio: 900 segundos iniciales; espera ampliable mientras avanza; 100% del recorrido y cero respuestas pendientes para OK. Máximos configurables; falta de avance o límites quedan PARCIAL con motivo y evidencia conservada. Sin active scan ni autenticación inventada.

Antes de publicar un artículo, calibrar pesos, umbrales y confianza con conjuntos de referencia, comparar falsos positivos/negativos y reproducibilidad. Versiones con reglas distintas no deben compararse como si usaran la misma escala.


## Redacción contextual automática
El modelo seleccionado explica los hechos y las recomendaciones con contexto de organización, metodología, dimensiones y fuentes públicas. La nota, los estados y el riesgo se calculan por reglas. No requiere aprobación manual para exportar: se aplican comprobaciones estructurales y de contradicciones conocidas; fallos o textos rechazados usan el catálogo determinista. Esas comprobaciones no sustituyen la revisión profesional del informe.

Los hallazgos se consolidan por condición y aplicación, con IDs estables HAL. Una condición puede tener varias rutas y herramientas de corroboración. WAF y alertas potenciales no explotadas pueden ser informativas; las deficiencias menores de cabeceras o SPF no reciben automáticamente riesgo medio. No se presenta CVSS calculado sin sus datos. CVEs de fuentes públicas son indicios, no explotación confirmada.

## Cobertura y acceso v24
Con cobertura inferior al 70% la categoría es No concluyente; se mantienen nota conservadora y rango por pendientes. Este umbral propio requiere validación empírica. El resumen solo presenta como deficiencias los controles evaluados con penalización. Respuestas de bloqueo no representan la aplicación normal; sus alertas se conservan en los registros, excluidas de fichas y penalizaciones web. Puertos y TLS son independientes del acceso HTML.

## IPs candidatas y autorización
Una búsqueda pública genera candidatos, no activos propios confirmados. Se conservan consultas, fechas, nombres, PTR y RDAP para revisión. No se suman candidatos pendientes al denominador de controles ni se les asigna nota de postura. Solo entran al inventario elegible cuando el operador declara pertenencia y autorización específica. Toda evaluación posterior procesa el inventario elegible completo.

## Segundo pase editorial
Qwen redacta explicaciones y recomendaciones con el contexto registrado. El cálculo de postura, riesgos y estados conserva las reglas anteriores. No se incorpora otro proveedor de IA ni un segundo pase automático.

La revisión con Claude es manual, a partir del DOCX, JSON de evidencias y prompt descargable. El prompt preserva cifras y hechos; pide distinguir indicios de comprobaciones y documentar inconsistencias. No representa un retest: un retest requiere nuevas pruebas ejecutadas y evidencia fechada. No se envía automáticamente contenido a Claude.

## Redacción v24

Peticiones de un hallazgo con contexto compacto, salida ampliable y validación textual. La reducción de tamaño no modifica notas, riesgos ni estados. ZAP obligatorio en aplicaciones evaluables; un bloqueo o error conserva el límite de evaluación.
