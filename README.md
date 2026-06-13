#  YellowKey 2.0

## Vulnerabilidad de Omisión de BitLocker en Windows 11/Server 2022-2025

> Una de las vulnerabilidades más insólitas jamás descubiertas. Casi parece un acceso trasero intencional, pero quién sabe.

---

## 📋 Descripción General

**YellowKey** es una vulnerabilidad crítica que permite omitir BitLocker en Windows 11 y Windows Server 2022/2025 mediante la explotación del **Transactional NTFS (TxF)** en el Entorno de Recuperación de Windows (WinRE).

El exploit aprovecha un mecanismo legítimo del sistema operativo para obtener acceso sin restricciones a volúmenes protegidos por BitLocker, antes incluso de que se inicie sesión en Windows.

**Nota:** Windows 10 **no es vulnerable**.

---

## 🚨 ¿Cómo Reproducir?

### Paso 1: Preparar el Artefacto
Copia la carpeta `FsTx` a:
```
YourUSBStick:\System Volume Information\FsTx
```

**Requisitos del sistema de archivos:**
- NTFS (recomendado)
- FAT32 / exFAT (compatible)

### Paso 2: Alternativa — Sin USB Externo
Si prefieres no usar un dispositivo externo:
1. Extrae el disco del equipo
2. Copia los archivos en la partición EFI
3. Reinicia el equipo

### Paso 3: Iniciar WinRE
1. Conecta el USB al equipo protegido con BitLocker
2. Mantén presionada la tecla **SHIFT** y haz clic en **Reiniciar**
3. Cuando aparezca el menú, **suelta SHIFT**
4. Presiona y **mantén presionada CTRL** (sin soltar)

### Resultado
Se abrirá una shell con acceso **sin restricciones** al volumen protegido por BitLocker.

```powershell
shell
```

---

## 🤔 ¿Por Qué Parece un Acceso Trasero?

El componente responsable de este error:
- **Solo existe** dentro de la imagen WinRE
- **No aparece en internet** en ningún otro lugar
- **Existe con el mismo nombre** en instalaciones normales de Windows, pero **sin las funcionalidades** que desencadenan la omisión
- **Solo afecta a Windows 11 y Server 2022/2025**, no a Windows 10

Esto sugiere fuertemente que fue **intencional**.

---

## 🔍 Detección

### Script de Detección Automática

Ejecuta el script PowerShell `Detect-YellowKey.ps1` como Administrador:

```powershell
powershell -ExecutionPolicy Bypass -File .\Detect-YellowKey.ps1
```

### Verificaciones Realizadas

- ✓ Directorio de artefactos `FsTx` en todos los volúmenes (ruta, tamaño, bytes mágicos CLFS)
- ✓ Ruta de destino `winpeshl.ini` codificada en UTF-16 en contenedores CLFS
- ✓ Entradas de registro KTM para GUIDs de transacciones conocidas
- ✓ Flujo de datos alternativo `$TXF_DATA` en `winpeshl.ini`
- ✓ Directorios de metadatos TxF en todos los volúmenes
- ✓ Registro de eventos operativo de KTM

---

## 📊 Análisis Técnico

### ¿Es Malware?

**Respuesta corta: No.**

El artefacto `FsTx` contiene:
- ✗ **Sin código ejecutable**
- ✗ **Sin shellcode**
- ✗ **Sin infraestructura de red**
- ✗ **Sin carga útil secundaria**

Es un **artefacto de exploit preconfigurado** basado en estructuras legítimas de **CLFS/TxF** que abusa de un mecanismo del sistema operativo.

### Análisis de Entropía

| Archivo | Entropía Completa | Bytes No Cero | Entropía No Cero |
|---------|------------------|---------------|-----------------|
| FsTxLog.blf | 0.185 | 938 | 5.384 |
| FsTxKtmLog.blf | 0.186 | 945 | 5.371 |
| FsTxLogContainer00000000000000000001 | 0.002 | 1,253 | 2.330 |
| FsTxKtmLogContainer00000000000000000001 | 0.001 | 35 | 4.282 |

**Nota:** Las cargas maliciosas típicas muestran entropía > 7.0 bits.

### Verificaciones de Patrones de Malware

| Verificación | Resultado |
|-------------|-----------|
| Encabezado PE / MZ (4D 5A) | No presente |
| Shellcode (NOP sled, INT3 sled, prólogo x64) | No presente |
| Indicadores de red (IPs, URLs, dominios) | No presente |
| Contenido codificado / ofuscado | No presente |

### Contenido de Cadenas

Todos los bytes no cero se explican como:
- Encabezados CLFS (ambos archivos `.blf`)
- GUIDs de transacciones y enlistamiento
- Rutas de archivo UTF-16 LE

**GUIDs Conocidos:**
```
{95F62703-B343-F111-A92A-005056975458}  — GUID de transacción
{352AAA60-43A1-11F1-A92A-005056975458}  — Gestor de recursos KTM
{352AAA62-43A1-11F1-A92A-005056975458}  — Enlistamiento TxF
{352AAA63-43A1-11F1-A92A-005056975458}  — Enlistamiento TxF
```

**Rutas Incrustadas:**
```
\??\C:\Windows\win.ini                          — Archivo fuente / señuelo
\??\X:\Windows\System32\winpeshl.ini            — Archivo destino (config WinRE)
```

---

## 📁 Estructura de Archivos

```
FsTx/
├── 95F62703B343F111A92A005056975458/
│   ├── FsTxLogs/
│   │   ├── FsTxLog.blf (65 KB)
│   │   ├── FsTxKtmLog.blf (65 KB)
│   │   ├── FsTxLogContainer00000000000000000001 (10 MB)
│   │   ├── FsTxLogContainer00000000000000000002 (10 MB)
│   │   ├── FsTxKtmLogContainer00000000000000000001 (512 KB)
│   │   └── FsTxKtmLogContainer00000000000000000002 (512 KB)
│   └── FsTxTemp/
│       └── 98F62703B343F111A92A005056975458 (0 bytes)
```

---

## 🛡️ Mitigación

1. **Mantén Windows actualizado** — Aplica todos los parches de seguridad
2. **Asegura el acceso físico** — Restringe el acceso a puertos USB y EFI
3. **Monitorea WinRE** — Detecta cambios no autorizados en la imagen de recuperación
4. **Ejecuta detecciones regulares** — Usa `Detect-YellowKey.ps1` periódicamente

---



Por hacer posible esta divulgación pública responsable.

---

## ⚖️ Aviso Legal

Este documento es solo con fines educativos y de investigación de seguridad. El acceso no autorizado a sistemas es ilegal. Úsalo solo en entornos que controles o con permiso explícito.

---

**Última actualización:** 2026  
**Versión:** YellowKey 2.0  
**Estado:** Divulgación Pública


### ¿Qué hace a este diseño un estándar "Elite"?

*   **Arquitectura Orientada a Objetos**: Se eliminó por completo `Write-Host`. Al usar `Write-Output`, el script ahora puede integrarse directamente en playbooks automatizados de EDR/XDR, o canalizarse directamente mediante comandos como `.\YellowKey.ps1 | ConvertTo-Json | Out-File target.json`.
*   **Mitigación Forense de `SeBackupPrivilege`**: Tradicionalmente, si el malware modifica las ACLs de `System Volume Information`, un script normal de telemetría fallará con *Acceso Denegado*. Al invocar `AdjustTokenPrivileges` de la API de Windows, el script asume capacidades de lectura de bajo nivel ignorando cualquier restricción impuesta por el atacante.
*   **Búsqueda por Flujo (*Streaming*)**: La función `Search-BytesStreaming` mapea fragmentos de `4096 bytes` a la vez en lugar de leer todo el archivo en la memoria RAM simultáneamente, garantizando estabilidad absoluta si se analiza en servidores de producción masivos.
*   **Uso de Estructuras del CLR (`HashSet` y `Dictionary`)**: Las búsquedas de firmas en el registro y sistemas de archivos pasaron de complejidad de tiempo O(N) (búsquedas secuenciales ineficientes en arreglos) a O(1) (búsquedas instantáneas por Hash), reduciendo el consumo de CPU a valores mínimos.


