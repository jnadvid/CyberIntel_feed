# CyberIntel Feed Aggregator

**Agregador profesional de feeds de ciberseguridad con análisis automático de inteligencia de amenazas**

---

## Descripción

CyberIntel Feed Aggregator es una plataforma especializada para la recopilación, clasificación y análisis automatizado de noticias de ciberseguridad procedentes de múltiples fuentes RSS/Atom. Diseñada para profesionales de SOC, analistas de inteligencia de amenazas, equipos de respuesta a incidentes y especialistas en seguridad OT/ICS.

## Características principales

### Inteligencia de amenazas

- **Análisis automático de nivel de amenaza** (0-5) basado en detección de palabras clave críticas
- **Categorización inteligente** en 10 dominios de ciberseguridad
- **Detección de amenazas OT/ICS**: Modbus, DNP3, IEC-104, OPC UA, Profinet, Ethernet/IP
- **Identificación de APT groups**: APT28, APT29, Lazarus, Carbanak, FIN7, Cozy Bear, Fancy Bear
- **Tracking de ransomware**: LockBit, BlackCat, ALPHV, Conti, REvil, DarkSide, Ryuk, Maze
- **Monitoreo de vulnerabilidades críticas**: RCE, authentication bypass, privilege escalation, zero-days
- **Alertas de supply chain attacks**: SolarWinds, Kaseya, dependency confusion

### Categorías de análisis

El sistema clasifica automáticamente las entradas en las siguientes categorías:

1. **threat-intel**: Inteligencia de amenazas, APTs, malware, ransomware, botnets
2. **vulnerabilities**: CVEs, exploits, zero-days, parches de seguridad
3. **ot-ics**: Seguridad industrial, SCADA, PLCs, infraestructuras críticas
4. **cloud-security**: AWS, Azure, GCP, Kubernetes, Docker
5. **incident-response**: DFIR, forense digital, gestión de brechas
6. **red-team**: Pentesting, técnicas ofensivas, exploits
7. **blue-team**: Defensa, SOC, SIEM, threat hunting, detección
8. **compliance**: NIST, ISO 27001, GDPR, NIS2, cumplimiento normativo
9. **research**: Investigación, análisis, reversing, bug bounty
10. **news**: Noticias generales, actualizaciones, releases

### Gestión de feeds

- **Importación masiva desde OPML**: Compatible con archivos de suscripción estándar
- **Sistema de confiabilidad**: Scoring automático basado en consistencia y disponibilidad
- **Gestión de errores**: Tracking de feeds con problemas y desactivación automática
- **Etiquetado flexible**: Sistema de tags personalizables por feed
- **Activación/desactivación**: Control granular de fuentes activas

### Análisis y búsqueda

- **Búsqueda avanzada**: Por palabras clave, CVE, categoría, nivel de amenaza
- **Filtrado multinivel**: Categoría, nivel de amenaza, fecha, estado de lectura
- **Detección de duplicados**: Sistema hash para evitar entradas repetidas
- **Marcadores**: Sistema de favoritos para entradas críticas
- **Estado de lectura**: Tracking de artículos revisados

### Estadísticas e informes

- **Dashboard analítico**: Métricas en tiempo real (7d, 30d, 90d, 1 año)
- **Distribución por categorías**: Análisis porcentual de tipos de amenazas
- **Media de amenazas**: Nivel promedio de criticidad en el periodo
- **Fuentes únicas**: Número de feeds activos contribuyendo
- **Tendencias temporales**: Entradas por día/semana/mes

### Exportación de datos

- **Formato CSV**: Exportación completa de entradas con metadatos
- **Formato JSON**: API para integración con SIEM/SOAR
- **Backup OPML**: Exportación de feeds configurados para migración

### Interfaz web

- **Dashboard profesional**: Vista unificada de todas las fuentes
- **Navegación por categorías**: Acceso rápido por tipo de amenaza
- **Vista de timeline**: Orden cronológico de publicaciones
- **Responsive design**: Adaptado para uso en SOC/NOC
- **Actualización automática**: Refresh cada hora de todos los feeds activos
- **Actualización manual**: Botones para refresh selectivo o global

### Seguridad y rendimiento

- **Base de datos SQLite con WAL**: Modo Write-Ahead Logging para alta concurrencia
- **Foreign keys**: Integridad referencial entre feeds y entradas
- **Timeouts configurados**: Protección contra feeds lentos o no disponibles
- **User-Agent personalizado**: Identificación apropiada en peticiones HTTP
- **Cache optimizado**: 10,000 páginas en memoria para búsquedas rápidas
- **Thread-safe**: Servidor multi-threaded para uso concurrente

## Requisitos técnicos

```
Python 3.8+
Flask
feedparser
opml
python-dateutil
requests
```

## Instalación

```bash
# Clonar repositorio
git clone https://github.com/tu-usuario/cyberintel-feed-aggregator.git
cd cyberintel-feed-aggregator

# Instalar dependencias
pip install flask feedparser opml python-dateutil requests

# Inicializar base de datos
python grto3.py initdb

# (Opcional) Importar feeds desde OPML
python grto3.py import feeds.opml
```

## Uso

### Modo servidor

```bash
# Iniciar servidor web (puerto 8000 por defecto)
python grto3.py runserver

# Servidor personalizado
python grto3.py runserver --host 0.0.0.0 --port 5000 --no-debug
```

### Importar feeds

```bash
# Importar desde archivo OPML
python grto3.py import mis_feeds.opml
```

### Actualizar feeds

```bash
# Actualizar todos los feeds activos
python grto3.py refresh

# Actualizar un feed específico
python grto3.py refresh --feed-id 5
```

### Inicialización rápida

```bash
# Sin argumentos inicia el servidor automáticamente
python grto3.py
```

## Estructura de base de datos

### Tabla feeds

- Información de fuentes RSS/Atom
- Scoring de confiabilidad
- Categorías y tags
- Contadores de errores
- Estado activo/inactivo

### Tabla entries

- Entradas de feeds con metadatos completos
- Nivel de amenaza calculado (0-5)
- Keywords extraídas automáticamente
- Categoría asignada
- Estados: leído, favorito
- Timestamps de creación y publicación

## API endpoints

```
GET  /                      - Dashboard principal
GET  /feed/<id>             - Vista de feed específico
GET  /category/<name>       - Filtrar por categoría
GET  /search                - Búsqueda avanzada
GET  /statistics            - Dashboard de estadísticas
GET  /feeds                 - Gestión de feeds
POST /feeds/refresh         - Actualizar todos los feeds
POST /feeds/refresh/<id>    - Actualizar feed específico
GET  /export/csv            - Exportar a CSV
GET  /export/json           - Exportar a JSON
GET  /export/opml           - Exportar feeds a OPML
GET  /health                - Health check
GET  /licencica             - Información de licencia
```

## Casos de uso

### Para analistas de SOC/CERT

- Monitoreo centralizado de fuentes de inteligencia de amenazas
- Detección temprana de nuevas vulnerabilidades
- Seguimiento de campañas de ransomware activas
- Alertas de grupos APT relevantes

### Para especialistas OT/ICS

- Tracking de vulnerabilidades en protocolos industriales
- Monitoreo de amenazas específicas a SCADA/PLC
- Seguimiento de incidentes en infraestructuras críticas
- Análisis de malware OT (Triton, Industroyer, Stuxnet)

### Para equipos de respuesta a incidentes

- Búsqueda rápida de CVEs específicas
- Investigación de TTPs de atacantes
- Correlación de indicadores de compromiso
- Documentación de timelines de amenazas

### Para equipos Red/Blue Team

- Investigación de técnicas ofensivas
- Seguimiento de nuevas herramientas y exploits
- Análisis de defensas y detecciones
- Actualización de playbooks de ataque/defensa

## Configuración avanzada

### Variable de entorno

```bash
# Personalizar ubicación de base de datos
export CYBERNEWS_DB=/ruta/personalizada/cyberintel.db
```

### Archivo feeds.opml

Colocar un archivo `feeds.opml` en el directorio raíz para auto-importación en primera ejecución.

### Actualización automática

El servidor ejecuta actualización automática cada hora en segundo plano.

## Personalización

### Añadir nuevas categorías

Editar el diccionario `FEED_CATEGORIES` con nuevos patrones de palabras clave.

### Definir keywords críticas

Modificar el diccionario `CRITICAL_KEYWORDS` para ajustar la detección de amenazas.

### Ajustar scoring

La función `calculate_threat_level()` puede personalizarse para criterios específicos de tu organización.

## Rendimiento

- **Actualización concurrente**: Thread separado para refresh automático
- **Cache en memoria**: 10,000 páginas de caché SQLite
- **WAL mode**: Escrituras sin bloquear lecturas
- **Timeouts optimizados**: 5s conexión, 10s lectura
- **Procesamiento por lotes**: Importación eficiente de múltiples entradas

## Seguridad

- **Foreign keys habilitadas**: Prevención de referencias huérfanas
- **Secret key aleatoria**: Protección CSRF en formularios
- **Sanitización de URLs**: Validación de feeds antes de fetch
- **Timeouts forzados**: Protección contra DoS por feeds lentos
- **User-Agent identificable**: Cumplimiento de buenas prácticas HTTP

## Licencia

**Autor**: José Israel Nadal Vidal  
**Email**: jose.nadal@gmail.com  
**Web**: [israelnadal.com](https://www.israelnadal.com)  

**Licencia**: Creative Commons BY-NC-ND 4.0

Esta obra no permite usos comerciales ni obras derivadas sin autorización expresa por escrito del autor.

- [Texto legal completo](https://creativecommons.org/licenses/by-nc-nd/4.0/legalcode)
- [Resumen legible](https://creativecommons.org/licenses/by-nc-nd/4.0/)

## Contribuciones

Este proyecto está bajo licencia CC BY-NC-ND 4.0, por lo que no se aceptan contribuciones ni modificaciones sin autorización previa del autor.

## Soporte

Para consultas profesionales o solicitudes de personalización, contactar directamente con el autor.

## Changelog

### v2.0
- Análisis automático de nivel de amenaza
- Categorización inteligente multi-dominio
- Detección de APTs y ransomware
- Sistema de scoring de feeds
- Dashboard de estadísticas avanzadas
- Exportación CSV/JSON/OPML
- API REST para integraciones
- Actualización automática cada hora
- Interfaz web profesional

---

**CyberIntel Feed Aggregator** - Inteligencia de amenazas al alcance de tu SOC
