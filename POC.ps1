using namespace System.Text
using namespace System.Numerics
using namespace System.Management.Automation

# pidxcheckerclass.h
# https://github.com/IonBazan/pidgenx/blob/master/pidxcheckerclass.h

# Fallback new logic, ($GroupId -ge 0x40) { "PKey986" } else { "PKey980" }
# https://github.com/ntriver-org/PKeyMaster/commit/62a508d9fe027aec0dcda153c3a0c8aa85216fbf

Clear-Host

if (!([PSTypeName]'PidGenX').Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class PidGenX
{
    [DllImport("pidgenxIn.dll", EntryPoint = "PidGenX2", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int PidGenX2(
        string cdKey,
        string configPath,
        string mpc,
        int unknown1, // usually 0
        int unknown2, // usually 0
        byte[] pid2,
        byte[] pid3,
        byte[] pid4
    );
}
"@ -ErrorAction Stop
    
    # Add PSScriptRoot to Path, So it will find Our Dll
    $BinPath = Join-Path $PSScriptRoot 'Bin'
    $env:PATH = [string]::Format("{0};{1}", $BinPath.TrimEnd('\'), $env:PATH)
}

# --- PidGenX2 call ---
$Pid2 = [Byte[]]::new(0x30)
$Pid3 = [Byte[]]::new(0xB0)
$Pid4 = [Byte[]]::new(0x500)

[BitConverter]::GetBytes([Int32]0x0A4).CopyTo($Pid3, 0)
[BitConverter]::GetBytes([Int32]0x4F8).CopyTo($Pid4, 0)

# Input Cd Key & Config
$MPC        = '00000' # Default-00000, Modern-03612
$CdKey      = 'VKK3X-68KWM-X2YGT-QR4M6-4BWMV'
$ConfigPath = Join-Path $BinPath 'pkeyconfig.xrm-ms'

$values  = $CdKey, $ConfigPath, $MPC, 0, 0, $Pid2, $Pid3, $Pid4
$HResult = [PidGenX]::PidGenX2.Invoke($values)

# --- PidGenX2 result handling ---
# PidGenX2 collapses ~20 internal 0x80041xxx reasons into the few codes below
# before returning, so these are the only values the caller ever sees.
$Hex       = '0x{0:X8}' -f $HResult
$Unverified = $false

switch ($Hex) {
    '0x00000000' { }   # S_OK - valid & verified
    '0x8A010001' { throw "Specified key is valid but can't be verified ($Hex)" }
    '0x8A010101' { throw "Specified key is not valid - PGX_INVALIDKEY ($Hex)" }   # from 0x80041023/24/25
    '0x80070057' { throw "Malformed or empty key - E_INVALIDARG ($Hex)" }         # PGX_MALFORMEDKEY / null cdKey
    '0x8007000E' { throw "Out of memory - E_OUTOFMEMORY ($Hex)" }
    '0x80070002' { throw "Can't find specified pkeyconfig file - PGX_PKEYMISSING ($Hex)" }
    '0x80070003' { throw "Specified pkeyconfig path does not exist ($Hex)" }

    # Header defines PGX_BLACKLISTEDKEY = 0x0000000F, but no analyzed build
    # actually emits 0x8000000F - kept only for completeness.
    '0x8000000F' { throw "Specified key is blacklisted - PGX_BLACKLISTEDKEY ($Hex) [unverified]" }

    default      { if ($HResult -lt 0) { throw "Unhandled HRESULT ($Hex)" } }
}

# --- DPID3 m_abCdKey (+0x034): Algorithm GUID     (16 bytes) ---
# --- DPID4 m_abCdKey (+0x328): DecodedM / ActData (16 bytes) ---
$SlotData = [byte[]]$Pid4[0x328..0x337]
$AlgoData = [byte[]]$Pid3[0x034..0x043]

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

$AlgoGuid = $null
try { $AlgoGuid = [Guid]$AlgoData } catch {}
switch ($AlgoGuid) {
    ([Guid]'660672EF-7809-4CFD-8D54-41B7FB738988') { $Is2009  = $true; $AlgoName = 'pkey2009' }
    ([Guid]'B8731595-A2F6-430B-A799-FBFFB81A8D73') { $Is2005  = $true; $AlgoName = 'pkey2005' }
    ([Guid]'35BFEDB3-9131-4F58-9D9A-5B32D10F50E0') { $Legacy  = $true; $AlgoName = 'pkey980'  }
    ([Guid]'9F44BF99-4976-4BFD-B00A-A8AEFBA45484') { $Legacy  = $true; $AlgoName = 'pkey985'  }
    ([Guid]'2B864AA3-A736-4D50-8604-EBB3BD7D7C61') { $Legacy  = $true; $AlgoName = 'pkey986'  }
}

# Channel-N keys are pkey2009 even when GUID patch is absent
if ($CdKey -match 'N') {
    $Is2009   = $true
    $AlgoName = 'pkey2009'
    $AlgoGuid = [Guid]'660672EF-7809-4CFD-8D54-41B7FB738988'
}

# pkey2009: 104-bit ActData (13 bytes -> BigInteger)
if ($Is2009) {
    $U = [byte[]]::new(14)
    [Array]::Copy($SlotData, 0, $U, 0, 13)
    $Act      = [BigInteger]::new($U)
    $Upgrade  = [int]($Act -band 1)
    $Serial   = [long](($Act -shr 1 ) -band ((1L -shl 30) - 1))
    $Group    = [long](($Act -shr 31) -band ((1L -shl 20) - 1))
    $Security = [long](($Act -shr 51) -band ((1L -shl 53) - 1))
    $ActData  = [Convert]::ToBase64String($SlotData, 0, 13)

# pkey2005: 64-bit M
} elseif ($Is2005) {
    $M        = [BitConverter]::ToInt64($SlotData, 0)
    $Upgrade  = [int]($M -band 1)
    $Serial   = ($M -shr 1 ) -band 0x3FFFFFFF
    $Security = ($M -shr 31) -band 0x3FF
    $ActData  = [Convert]::ToBase64String($SlotData, 0, 12)

# pkey980/985/986: 64-bit M, no security field
} elseif ($Legacy) {
    $M        = [BitConverter]::ToInt64($SlotData, 0)
    $Upgrade  = [int]($M -band 1)
    $Serial   = ($M -shr 1) -band 0x3FFFFFFF
    $ActData  = [Convert]::ToBase64String($SlotData, 0, 12)

# Unpatched DLL fallback: GUID unknown, try to detect from data
} else {
    $M       = [BitConverter]::ToInt64($SlotData, 0)
    $Upgrade = [int]($M -band 1)
    $Serial  = ($M -shr 1)  -band 0x3FFFFFFF
    $SecVal  = ($M -shr 31) -band 0x3FF
    $Group   = [BitConverter]::ToUInt32($Pid3, 0x20)
    $ActData = [Convert]::ToBase64String($SlotData, 0, 12)

    if ($SecVal -ne 0) {
        $Security = $SecVal
        $AlgoName = 'pkey2005'
        $AlgoGuid = [Guid]'B8731595-A2F6-430B-A799-FBFFB81A8D73'
    } elseif ($Group -ge 0x40) { 
        $AlgoName = 'pkey986'
        $AlgoGuid = [Guid]'2B864AA3-A736-4D50-8604-EBB3BD7D7C61'
    } else { 
        $AlgoName = 'pkey980'
        $AlgoGuid = [Guid]'35BFEDB3-9131-4F58-9D9A-5B32D10F50E0'
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

Write-Host
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
Write-Host "  HRESULT     : 0x$($HResult.ToString('X8'))"
Write-Host