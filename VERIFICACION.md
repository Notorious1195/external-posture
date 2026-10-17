# Verificación v24

Pasaron 41 ejecuciones de métodos unittest y los escenarios independientes test_flow y test_ui. Incluyen petición individual, presupuesto ampliado, fallback de modo JSON explícitamente rechazado, parseo de reasoning/Markdown, rechazo de JSON truncado, inmutabilidad de la puntuación y regresiones de inventario/ZAP/evidencias.

Streamlit AppTest con el checkpoint aportado: páginas Modelo de IA, Inventario externo, Evaluación completa y Postura externa sin errores. Campo de token eliminado, bloque de IPs candidatas eliminado y checkbox ZAP eliminado. Todos los valores de tarjetas de postura son numéricos en este escenario.

El diagnóstico aportado confirma conexión del modelo correcta y redacción parcial 2/15, con truncamientos y JSON inválido. ZAP figura OK, recorrido 100 y cero pendientes; el DOCX aportado contiene 15 imágenes. No se ejecutaron nuevas pruebas sobre esos activos ni se alteraron los archivos aportados.

Los contratos de Qwen se probaron con respuestas simuladas. Falta probar la nueva redacción en tu Qwen/LM Studio real. No se garantiza que todo modelo local complete todas las redacciones; se conserva fallback documentado y diagnóstico.

Las reglas y ponderaciones de postura son iguales a v23; solo cambia el identificador de versión. El informe DOCX y la revisión manual con Claude conservan su flujo anterior.
