Script de detección (Detect-YellowKey.ps1)
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detecta IoCs asociados con el bypass de WinRE/BitLocker basado en TxF de YellowKey.

.DESCRIPTION
    Escanea todos los volúmenes montados, el registro, los registros de eventos y los metadatos de NTFS
    en busca de artefactos dejados por el exploit YellowKey. Las verificaciones incluyen:
      - Directorio y archivos del artefacto FsTx (por ruta, tamaño y contenido)
      - Bytes mágicos y checksum de CLFS en archivos .blf
      - Cadena winpeshl.ini en UTF-16 incrustada en contenedores de registro CLFS
      - Entradas de registro KTM para GUIDs de transacción conocidos
      - Flujo de datos alternativo $TXF_DATA en winpeshl.ini
      - Directorios de metadatos TxF en todos los volúmenes
      - Registro de eventos operativos de KTM

.NOTES
    Debe ejecutarse como Administrador para acceder a System Volume Information y metadatos NTFS.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

$script:Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:Hits    = 0

**---------------------------------------------------------------------------**
**Definiciones de IoC**
**---------------------------------------------------------------------------**

$TxnGuid       = "95F62703B343F111A92A005056975458"   # nombre del directorio (sin guiones)
$TempFileGuid  = "98F62703B343F111A92A005056975458"   # marcador temporal de cero bytes

$KTMGuids = @(
    "352AAA60-43A1-11F1-A92A-005056975458",
    "352AAA62-43A1-11F1-A92A-005056975458",
    "352AAA63-43A1-11F1-A92A-005056975458"
)

**Primeros 16 bytes de ambos archivos .blf: firma CLFS + versión + checksum fijo**
$CLFSMagic = [byte[]](
    0x15, 0x00, 0x01, 0x00,   # firma CLFS
    0x02, 0x00, 0x02, 0x00,   # versión 2.2
    0x00, 0x00, 0x00, 0x00,   # relleno
    0x4B, 0x82, 0x4C, 0xC6    # checksum CRC32 (fijo para este artefacto)
)

**Ruta objetivo codificada en UTF-16 LE incrustada en FsTxLogContainer***
$WinpeshlUTF16 = [System.Text.Encoding]::Unicode.GetBytes(
    "\??\X:\Windows\System32\winpeshl.ini"
)

**Archivos esperados bajo FsTxLogs\ con sus tamaños exactos**
$FsTxFiles = [ordered]@{
    "FsTxLog.blf"                            = 65536
    "FsTxKtmLog.blf"                         = 65536
    "FsTxLogContainer00000000000000000001"    = 10485760
    "FsTxLogContainer00000000000000000002"    = 10485760
    "FsTxKtmLogContainer00000000000000000001" = 524288
    "FsTxKtmLogContainer00000000000000000002" = 524288
}

**---------------------------------------------------------------------------**
**Funciones auxiliares**
**---------------------------------------------------------------------------**

function Write-Hit {
    param(
        [string]$Category,
        [string]$Detail,
        [string]$Path = ""
    )
    $script:Hits++
    $script:Results.Add([PSCustomObject]@{
        Category = $Category
        Detail   = $Detail
        Path     = $Path
    })
    Write-Host "[HIT] $Category" -ForegroundColor Red -NoNewline
    Write-Host " — $Detail" -ForegroundColor White
    if ($Path) {
        Write-Host "      $Path" -ForegroundColor Yellow
    }
}

function Write-Info {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

**Devuelve $true si los bytes de $Pattern aparecen en $Offset en el archivo**
function Test-BytesAt {
    param([string]$FilePath, [byte[]]$Pattern, [int]$Offset = 0)
    try {
        $fs  = [System.IO.File]::OpenRead($FilePath)
        $buf = New-Object byte[] $Pattern.Length
        [void]$fs.Seek($Offset, [System.IO.SeekOrigin]::Begin)
        $read = $fs.Read($buf, 0, $Pattern.Length)
        $fs.Close()
        if ($read -ne $Pattern.Length) { return $false }
        for ($i = 0; $i -lt $Pattern.Length; $i++) {
            if ($buf[$i] -ne $Pattern[$i]) { return $false }
        }
        return $true
    }
    catch { return $false }
}

**Devuelve $true si $Pattern aparece en cualquier parte del archivo**
function Search-Bytes {
    param([string]$FilePath, [byte[]]$Pattern)
    try {
        $data = [System.IO.File]::ReadAllBytes($FilePath)
        $plen = $Pattern.Length
        $limit = $data.Length - $plen
        for ($i = 0; $i -le $limit; $i++) {
            $match = $true
            for ($j = 0; $j -lt $plen; $j++) {
                if ($data[$i + $j] -ne $Pattern[$j]) { $match = $false; break }
            }
            if ($match) { return $true }
        }
        return $false
    }
    catch { return $false }
}

**Formatea una cadena GUID cruda de 32 caracteres como {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}**
function Format-Guid {
    param([string]$Raw)
    "{$($Raw.Insert(8,'-').Insert(13,'-').Insert(18,'-').Insert(23,'-'))}"
}

**---------------------------------------------------------------------------**
**Verificación 1 — Directorio del artefacto FsTx en todos los volúmenes**
**---------------------------------------------------------------------------**
Write-Info "Escaneando todos los volúmenes en busca del directorio del artefacto FsTx..."

$drives = Get-PSDrive -PSProvider FileSystem |
          Where-Object { $_.Root -match '^[A-Z]:\\$' }

foreach ($drive in $drives) {
    $sviPath  = Join-Path $drive.Root "System Volume Information\FsTx"
    $fstxBase = Join-Path $sviPath $TxnGuid

    # Verificación amplia: cualquier directorio FsTx (captura variantes con diferentes GUIDs)
    if (Test-Path $sviPath) {
        $children = Get-ChildItem $sviPath -Directory
        foreach ($child in $children) {
            if ($child.Name -ne $TxnGuid) {
                Write-Hit "FsTx Dir (GUID desconocido)" `
                    "GUID de transacción inesperado: $($child.Name)" `
                    $child.FullName
            }
        }
    }

    if (-not (Test-Path $fstxBase)) { continue }

    Write-Hit "FsTx Dir" "Directorio GUID de transacción conocido presente" $fstxBase

    # --- Verificaciones por archivo ---
    $logsDir = Join-Path $fstxBase "FsTxLogs"

    foreach ($kv in $FsTxFiles.GetEnumerator()) {
        $fp = Join-Path $logsDir $kv.Key
        if (-not (Test-Path $fp)) { continue }

        $actualSize = (Get-Item $fp).Length
        $sizeOk     = ($actualSize -eq $kv.Value)

        Write-Hit "FsTx File" "$($kv.Key) — tamaño $actualSize (esperado $($kv.Value), coincidencia: $sizeOk)" $fp

        # Bytes mágicos + checksum de CLFS en archivos .blf
        if ($kv.Key -like "*.blf") {
            if (Test-BytesAt -FilePath $fp -Pattern $CLFSMagic -Offset 0) {
                Write-Hit "Firma CLFS" "Bytes mágicos + CRC 0x4B824CC6 confirmados" $fp
            }
        }

        # Cadena winpeshl.ini en UTF-16 LE en contenedores de registro
        if ($kv.Key -like "FsTxLogContainer*") {
            if (Search-Bytes -FilePath $fp -Pattern $WinpeshlUTF16) {
                Write-Hit "Ruta incrustada" "Ruta objetivo de winpeshl.ini (UTF-16) encontrada en contenedor CLFS" $fp
            }
        }
    }

    # Marcador temporal de cero bytes
    $tempFile = Join-Path $fstxBase "FsTxTemp\$TempFileGuid"
    if (Test-Path $tempFile) {
        Write-Hit "FsTx Temp" "Marcador temporal de transacción de cero bytes presente" $tempFile
    }
}

**---------------------------------------------------------------------------**
**Verificación 2 — Registro KTM**
**---------------------------------------------------------------------------**
Write-Info "Verificando el registro KTM en busca de GUIDs de transacción de YellowKey..."

$ktmRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Ktm\ResourceManagers"
if (Test-Path $ktmRegPath) {
    $allGuids = $KTMGuids + @( (Format-Guid $TxnGuid).Trim('{}') )
    foreach ($guid in $allGuids) {
        $formatted = "{$guid}"
        $key = Get-ChildItem $ktmRegPath |
               Where-Object { $_.PSChildName -ieq $formatted }
        if ($key) {
            Write-Hit "Registro KTM" "GUID de YellowKey registrado: $formatted" `
                "$ktmRegPath\$formatted"
        }
    }
}

**---------------------------------------------------------------------------**
**Verificación 3 — Flujo de datos alternativo $TXF_DATA en winpeshl.ini**
**---------------------------------------------------------------------------**
Write-Info "Verificando winpeshl.ini en busca del flujo de datos alternativo `$TXF_DATA..."

$winpeshlLocations = @(
    "X:\Windows\System32\winpeshl.ini",
    "C:\Windows\System32\winpeshl.ini"
)
**Agregar winpeshl.ini en cada unidad montada**
foreach ($drive in $drives) {
    $winpeshlLocations += Join-Path $drive.Root "Windows\System32\winpeshl.ini"
}
$winpeshlLocations = $winpeshlLocations | Select-Object -Unique

foreach ($path in $winpeshlLocations) {
    if (-not (Test-Path $path)) { continue }
    $streams = Get-Item $path -Stream * 2>$null
    if ($streams | Where-Object { $_.Stream -eq '$TXF_DATA' }) {
        Write-Hit '$TXF_DATA ADS' "Marcador de transacción pendiente en winpeshl.ini" $path
    }
}

**---------------------------------------------------------------------------**
**Verificación 4 — Directorios de metadatos TxF en todos los volúmenes**
**---------------------------------------------------------------------------**
Write-Info "Verificando directorios de metadatos TxF activos..."

foreach ($drive in $drives) {
    $txfLog = Join-Path $drive.Root '$Extend\$RmMetadata\$TxfLog'
    if (Test-Path $txfLog) {
        $items = Get-ChildItem $txfLog 2>$null
        if ($items) {
            Write-Hit "Metadatos TxF" `
                "Registro TxF activo presente en $($drive.Root) ($($items.Count) elemento(s))" `
                $txfLog
        }
    }
}

**---------------------------------------------------------------------------**
**Verificación 5 — Registro de eventos operativos de KTM**
**---------------------------------------------------------------------------**
Write-Info "Escaneando el registro de eventos operativos de KTM en busca de GUIDs de YellowKey..."

$allSearchGuids = ($KTMGuids + @($TxnGuid, $TempFileGuid)) -join "|"

try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-KtmRm/Operational" `
                           -MaxEvents 1000 `
                           -ErrorAction Stop
    foreach ($event in $events) {
        if ($event.Message -match $allSearchGuids) {
            $matched = [regex]::Match($event.Message, $allSearchGuids).Value
            Write-Hit "Registro de eventos (KTM)" `
                "EventID $($event.Id) a las $($event.TimeCreated) referencia el GUID: $matched" `
                "Microsoft-Windows-KtmRm/Operational"
        }
    }
}
catch [System.Exception] {
    Write-Info "Registro operativo de KTM no disponible o vacío (normal en sistemas no afectados)"
}

**---------------------------------------------------------------------------**
**Resumen**
**---------------------------------------------------------------------------**
Write-Host ""
Write-Host ("=" * 50) -ForegroundColor White
Write-Host "  Resumen de detección de YellowKey" -ForegroundColor White
Write-Host ("=" * 50) -ForegroundColor White

if ($script:Hits -eq 0) {
    Write-Host "[LIMPIO] No se detectaron IoCs de YellowKey." -ForegroundColor Green
}
else {
    Write-Host "[ALERTA] Se detectaron $($script:Hits) indicador(es)." -ForegroundColor Red
    Write-Host ""
    $script:Results | Format-Table Category, Detail, Path -AutoSize -Wrap
}
