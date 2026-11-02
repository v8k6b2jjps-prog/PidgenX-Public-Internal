using namespace System.Text
using namespace System.Numerics

Import-Module NativeInteropLib -ErrorAction Stop
Clear-Host
Write-Host

# --- PidGenX2 call ---
$Pid2 = [Byte[]]::new(0x30)
$Pid3 = [Byte[]]::new(0xB0)
$Pid4 = [Byte[]]::new(0x500)

[BitConverter]::GetBytes([Int32]0x0A4).CopyTo($Pid3, 0)
[BitConverter]::GetBytes([Int32]0x4F8).CopyTo($Pid4, 0)

# Input Cd Key & Config
$MPC        = '00000' # Default-00000, Modern-03612
$CdKey      = 'MKKRJ-CBYG7-MK2Y4-DXHT6-8VCJB'
$ConfigPath = 'C:\Windows\System32\spp\tokens\pkeyconfig\pkeyconfig-downlevel.xrm-ms'

$Values = $CdKey, $ConfigPath, $MPC, 0, 0, $Pid2, $Pid3, $Pid4
$Hr = Invoke-UnmanagedMethod -Dll PidGenXIn -Function PidGenX2 -Values $Values
if ($Hr -lt 0) {
    Write-Error "Validation Failed Error: $Hr"
    return
}

# --- Init ---
$Upgrade  = 0
$Serial   = -1L
$Group    = -1L
$AlgoName = ''
$ActData  = ''
$Security = $null
$Is2009   = $false
$Is2005   = $false
$Legacy   = $false

# --- DPID3 m_abCdKey (+0x34): Algorithm GUID (16 bytes) ---
$AlgoData = $Pid3[0x34..0x43]
$AlgoGuid = [Guid]::new([byte[]]$AlgoData)

switch ($AlgoGuid) {
    ([Guid]'660672EF-7809-4CFD-8D54-41B7FB738988') { $Is2009 = $true;  $AlgoName = 'pkey2009' }
    ([Guid]'B8731595-A2F6-430B-A799-FBFFB81A8D73') { $Is2005 = $true;  $AlgoName = 'pkey2005' }
    ([Guid]'35BFEDB3-9131-4F58-9D9A-5B32D10F50E0') { $Legacy  = $true; $AlgoName = 'pkey980' }
    ([Guid]'9F44BF99-4976-4BFD-B00A-A8AEFBA45484') { $Legacy  = $true; $AlgoName = 'pkey985' }
    ([Guid]'2B864AA3-A736-4D50-8604-EBB3BD7D7C61') { $Legacy  = $true; $AlgoName = 'pkey986' }
}

# Channel-N keys are pkey2009 even when GUID patch is absent
if ($CdKey -match 'N') {
    $Is2009   = $true
    $AlgoName = 'pkey2009'
    $AlgoGuid = [Guid]'660672EF-7809-4CFD-8D54-41B7FB738988'
}

# --- DPID4 m_abCdKey (+0x328): DecodedM / ActData (16 bytes) ---
$Slot = [byte[]]::new(16)
[Array]::Copy($Pid4, 0x328, $Slot, 0, 16)

if ($Is2009) {
    # pkey2009: 104-bit ActData (13 bytes -> BigInteger)
    $U = [byte[]]::new(14)
    [Array]::Copy($Slot, 0, $U, 0, 13)
    $Act      = [BigInteger]::new($U)
    $Upgrade  = [int]($Act -band 1)
    $Serial   = [long](($Act -shr 1 ) -band ((1L -shl 30) - 1))
    $Group    = [long](($Act -shr 31) -band ((1L -shl 20) - 1))
    $Security = [long](($Act -shr 51) -band ((1L -shl 53) - 1))
    $ActData  = [Convert]::ToBase64String($Slot, 0, 13)

} elseif ($Is2005) {
    # pkey2005: 64-bit M
    $M        = [BitConverter]::ToInt64($Slot, 0)
    $Upgrade  = [int]($M -band 1)
    $Serial   = ($M -shr 1 ) -band 0x3FFFFFFF
    $Security = ($M -shr 31) -band 0x3FF
    $ActData  = [Convert]::ToBase64String($Slot, 0, 12)

} elseif ($Legacy) {
    # pkey980/985/986: 64-bit M, no security field
    $M        = [BitConverter]::ToInt64($Slot, 0)
    $Upgrade  = [int]($M -band 1)
    $Serial   = ($M -shr 1) -band 0x3FFFFFFF
    $ActData  = [Convert]::ToBase64String($Slot, 0, 12)

} else {
    # Unpatched DLL fallback: GUID unknown, try to detect from data
    $M        = [BitConverter]::ToInt64($Slot, 0)
    $Upgrade  = [int]($M -band 1)
    $Serial   = ($M -shr 1)  -band 0x3FFFFFFF
    $SecVal   = ($M -shr 31) -band 0x3FF
    $ActData  = [Convert]::ToBase64String($Slot, 0, 12)

    if ($SecVal -ne 0) {
        $Security = $SecVal
        $AlgoName = 'pkey2005'
        $AlgoGuid = [Guid]'B8731595-A2F6-430B-A799-FBFFB81A8D73'
    } else {
        $AlgoName = 'Legacy'
        $AlgoGuid = [Guid]::Empty
    }
}

# --- Fallbacks ---
# Group from DPID3+0x20 if not decoded above
if ($Group -eq -1L) {
    $Group = [BitConverter]::ToUInt32($Pid3, 0x20)
}

# Serial from AdvancedPid (DPID4+0x08, Unicode) if not decoded
if ($Serial -eq -1L) {
    $AdvPid   = [Encoding]::Unicode.GetString($Pid4, 0x08, 0x80).TrimEnd([char]0)
    $PidParts = $AdvPid.Split('-')
    $Serial   = ([int]$PidParts[2] * 1000000) + [int]$PidParts[3]
}

# PID String from PIDPtr (Unicode)
$PidString = [Encoding]::Unicode.GetString($Pid2).TrimEnd([char]0)

# --- Print Results ---
$Channel  = [Math]::Floor($Serial / 1000000)
$Sequence = $Serial % 1000000

Write-Host "  Product Key : $CdKey"
Write-Host "  PID String  : $PidString"
Write-Host "  Algorithm   : $AlgoName  {$AlgoGuid}"
Write-Host "  ActData     : $ActData"
Write-Host ""
Write-Host "  Upgrade     : $Upgrade"
Write-Host "  Serial      : $Serial  (Channel $Channel / Sequence $Sequence)"
Write-Host "  Group       : $Group"
Write-Host ("  Security    : {0}" -f $(if ($null -ne $Security){$Security} else {'Null'}))
Write-Host ""
Write-Host "  HRESULT     : 0x$($Hr.ToString('X8'))"
Write-Host