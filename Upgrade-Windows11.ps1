<#
.SYNOPSIS
Orchestrates the download and execution of the Windows 11 Upgrade Assistant.
.DESCRIPTION
This script performs all steps necessary to prepare for and initiate a Windows 11 upgrade.
It is designed to be run as an administrator.

The script will:
1. Check for Administrator privileges.
2. Create a log directory at 'C:\Temp\UpgradeLog'.
3. Run a hardware readiness check (unless -SkipReadinessCheck is used).
4. Resolve the download URL and download the Windows 11 Installation Assistant to the temp folder.
5. Either execute the upgrade immediately (if -UpgradeNow is specified) or create a public desktop shortcut
   for a user to run the upgrade manually.

The upgrade is run quietly and will copy its logs to 'C:\Temp\UpgradeLog'.
.PARAMETER UpgradeNow
A switch parameter that, if present, causes the script to immediately execute the
Windows 11 Installation Assistant in quiet mode.
If this parameter is omitted, the script will instead create a 'Upgrade Windows' shortcut
on the public desktop (C:\Users\Public\Desktop).
.PARAMETER SkipReadinessCheck
A switch parameter that, if present, skips the Windows 11 hardware readiness check
(which is performed by the Check-Win11Readiness function).
.EXAMPLE
    .\Upgrade-Windows11.ps1

Description:
This is the default mode. The script runs the readiness check, downloads the installer,
and creates a shortcut named 'Upgrade Windows' on the public desktop.
No upgrade is performed at this time.
.EXAMPLE
    .\Upgrade-Windows11.ps1 -UpgradeNow

Description:
Runs the readiness check, downloads the installer, and immediately begins the
Windows 11 upgrade in quiet mode.
.EXAMPLE
    .\Upgrade-Windows11.ps1 -UpgradeNow -SkipReadinessCheck

Description:
Skips the hardware readiness check, downloads the installer, and immediately begins
the Windows 11 upgrade in quiet mode. This is useful for testing or on machines
that are known to be compatible.
.NOTES
Author:         Chris Stone
Version:        1.2.23
Dependencies:   This script requires the following functions to be defined in the same scope:
                - Test-Win11Readiness
                - Resolve-UrlFinalFileName
Requirements:   Must be run with Administrator privileges.
Signing:        This file previously carried an embedded Authenticode signature block. Any edit to
                the script body invalidates that signature (PowerShell's signing model covers the
                whole file), so the block was removed rather than left stale/HashMismatch. Re-sign
                before distributing under an AllSigned/RemoteSigned execution policy that requires it.
.LINK
Based on the Microsoft HardwareReadiness script.
#>

[CmdletBinding()]
param(
	[switch]$UpgradeNow,
	[switch]$SkipReadinessCheck,
	[switch]$SkipSKUCheck,
	[switch]$SkipESUCheck
)

#region --- Helper Functions ---

function Write-Log {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Message,
		[ValidateSet('VERBOSE', 'INFO', 'WARN', 'ERROR')]
		[string]$Level = 'INFO',
		[hashtable]$ColorMap = @{
			VERBOSE = 'DarkGray'
			INFO    = 'Green'
			WARN    = 'Yellow'
			ERROR   = 'Red'
		}
	)
	$FormattedMessage = ('{0} [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message)

	if ([Environment]::GetCommandLineArgs().Contains('-NonInteractive')) {
		[Console]::WriteLine($FormattedMessage)
	} else {
		Write-Host $FormattedMessage -ForegroundColor $ColorMap[$Level]
	}
}


function Resolve-UrlFinalFileName {
	<#
.SYNOPSIS
    Resolves a URL to its final destination and gets the filename from the path.
.DESCRIPTION
    Uses System.Net.HttpWebRequest to send a 'HEAD' request, which is
    more efficient as it doesn't download the file body. It follows all
    redirects and gets the filename from the ResponseUri.
.PARAMETER Url
    The URL to resolve.
.EXAMPLE
    Resolve-UrlFinalFileName -Url 'https://go.microsoft.com/fwlink/?linkid=2171764'

    # Output: Windows11InstallationAssistant.exe
.RETURNS
    [string] The filename from the final URL path.
#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		[string]$Url
	)

	$response = $null
	try {
		# Create the request
		$request = [System.Net.WebRequest]::Create($Url)
		$request.Method = 'HEAD'         # Efficient: only get headers
		$request.AllowAutoRedirect = $true # Automatically follow redirects

		Write-Verbose -Message ('Sending HEAD request to {0}' -f $Url)
		$response = $request.GetResponse()

		# The 'ResponseUri' property contains the final URL after all redirects
		$finalUri = $response.ResponseUri
		Write-Verbose -Message ('Final URL resolved to: {0}' -f $finalUri.AbsoluteUri)

		# Use .NET's Path class to reliably get the filename
		return [System.IO.Path]::GetFileName($finalUri.LocalPath)
	} catch {
		Write-Error -Message ('Failed to resolve URL ''{0}'': {1}' -f $Url, $_.Exception.Message)
	} finally {
		# Clean up the response
		if ($null -ne $response) {
			$response.Close()
		}
	}
}

#endregion

#=============================================================================================================================
#
# The function Test-Win11Readiness is substantially based on the HardwareReadiness.ps1 script from Microsoft
#
# Script Name:     HardwareReadiness.ps1
# Description:     This task would run a full hardware assessment test on the endpoint and provide a detailed output for the results.
#                  In case of failure, returns non zero error code along with error message.

# This script is not supported under any Microsoft standard support program or service and is distributed under the MIT license

# Copyright (C) 2021 Microsoft Corporation

# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software
# is furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
# WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#=============================================================================================================================

function Test-Win11Readiness {


	$exitCode = 0

	[int]$MinOSDiskSizeGB = 64
	[int]$MinMemoryGB = 4
	[Uint32]$MinClockSpeedMHz = 1000
	[Uint32]$MinLogicalCores = 2
	[Uint16]$RequiredAddressWidth = 64

	$PASS_STRING = "PASS"
	$FAIL_STRING = "FAIL"
	$FAILED_TO_RUN_STRING = "FAILED TO RUN"
	$UNDETERMINED_CAPS_STRING = "UNDETERMINED"
	$UNDETERMINED_STRING = "Undetermined"
	$CAPABLE_STRING = "Capable"
	$NOT_CAPABLE_STRING = "Not capable"
	$CAPABLE_CAPS_STRING = "CAPABLE"
	$NOT_CAPABLE_CAPS_STRING = "NOT CAPABLE"
	$STORAGE_STRING = "Storage"
	$OS_DISK_SIZE_STRING = "OSDiskSize"
	$MEMORY_STRING = "Memory"
	$SYSTEM_MEMORY_STRING = "System_Memory"
	$GB_UNIT_STRING = "GB"
	$TPM_STRING = "TPM"
	$TPM_VERSION_STRING = "TPMVersion"
	$PROCESSOR_STRING = "Processor"
	$SECUREBOOT_STRING = "SecureBoot"
	$I7_7820HQ_CPU_STRING = "i7-7820hq CPU"
	$OS_VERSION = "version"
	$OS_VERSION_STRING = "OsVersion"
	$OS_SECURITY_UPDATE_STRING = "LastSecurityUpdateInstalled"
	$OS_SECURITY_InstalledOn_String = "InstalledOn"


	# 0=name of check, 1=attribute checked, 2=value, 3=PASS/FAIL/UNDETERMINED
	$logFormat = '{0}: {1}={2} :: {3}; '

	# 0=name of check, 1=attribute checked, 2=value, 3=unit of the value, 4=PASS/FAIL/UNDETERMINED
	$logFormatWithUnit = '{0}: {1}={2}{3} :: {4}; '

	# 0=name of check.
	$logFormatReturnReason = '{0}, '

	# 0=exception.
	$logFormatException = '{0}; '

	# 0=name of check, 1= attribute checked and its value, 2=PASS/FAIL/UNDETERMINED
	$logFormatWithBlob = '{0}: {1} :: {2}; '

	# return returnCode is -1 when an exception is thrown. 1 if the value does not meet requirements. 0 if successful. -2 default, script didn't run.
	$outObject = @{ returnCode = -2; returnResult = $FAILED_TO_RUN_STRING; returnReason = ""; logging = "" }

	# NOT CAPABLE(1) state takes precedence over UNDETERMINED(-1) state
	function Private:UpdateReturnCode {
		param(
			[Parameter(Mandatory = $true)]
			[ValidateRange(-2, 1)]
			[int] $ReturnCode
		)

		switch ($ReturnCode) {

			0 {
				if ($outObject.returnCode -eq -2) {
					$outObject.returnCode = $ReturnCode
				}
			}
			1 {
				$outObject.returnCode = $ReturnCode
			}
			-1 {
				if ($outObject.returnCode -ne 1) {
					$outObject.returnCode = $ReturnCode
				}
			}
		}
	}

	# Check for Os Version Pre-Requisite

	try {
		# check if os is server or windows 7
		$productType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
		$installedOs = (Get-CimInstance win32_operatingsystem | Select-Object Caption).Caption

		if ($productType -ne 1) {
			$outObject.returnCode = 1
			$outObject.returnReason = $logFormatReturnReason -f 'OS ProductType'
			$outObject.logging += $logFormatWithBlob -f 'OS ProductType', "Installed OS '$installedOs' (ProductType=$productType) is not a Workstation", $FAIL_STRING
			return $outObject
		} elseif ($installedOs -imatch "Windows 7") {
			$outObject.returnCode = 1
			$outObject.returnReason = $logFormatReturnReason -f 'OS ProductType'
			$outObject.logging += $logFormatWithBlob -f 'OS ProductType', "Installed OS '$installedOs' is not supported", $FAIL_STRING
			return $outObject
		}
	} catch {
		$outObject.returnCode = -1
		$outObject.logging += $logFormatWithBlob -f 'OS ProductType', $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
		$outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
		return $outObject
	}

	$Source = @"
using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;

    public class CpuFamilyResult
    {
        public bool IsValid { get; set; }
        public string Message { get; set; }
    }

    public class CpuFamily
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort ProcessorArchitecture;
            ushort Reserved;
            public uint PageSize;
            public IntPtr MinimumApplicationAddress;
            public IntPtr MaximumApplicationAddress;
            public IntPtr ActiveProcessorMask;
            public uint NumberOfProcessors;
            public uint ProcessorType;
            public uint AllocationGranularity;
            public ushort ProcessorLevel;
            public ushort ProcessorRevision;
        }

        [DllImport("kernel32.dll")]
        internal static extern void GetNativeSystemInfo(ref SYSTEM_INFO lpSystemInfo);

        public enum ProcessorFeature : uint
        {
            ARM_SUPPORTED_INSTRUCTIONS = 34
        }

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool IsProcessorFeaturePresent(ProcessorFeature processorFeature);

        private const ushort PROCESSOR_ARCHITECTURE_X86 = 0;
        private const ushort PROCESSOR_ARCHITECTURE_ARM64 = 12;
        private const ushort PROCESSOR_ARCHITECTURE_X64 = 9;

        private const string INTEL_MANUFACTURER = "GenuineIntel";
        private const string AMD_MANUFACTURER = "AuthenticAMD";
        private const string QUALCOMM_MANUFACTURER = "Qualcomm Technologies Inc";

        public static CpuFamilyResult Validate(string manufacturer, ushort processorArchitecture)
        {
            CpuFamilyResult cpuFamilyResult = new CpuFamilyResult();

            if (string.IsNullOrWhiteSpace(manufacturer))
            {
                cpuFamilyResult.IsValid = false;
                cpuFamilyResult.Message = "Manufacturer is null or empty";
                return cpuFamilyResult;
            }

            string registryPath = "HKEY_LOCAL_MACHINE\\Hardware\\Description\\System\\CentralProcessor\\0";
            SYSTEM_INFO sysInfo = new SYSTEM_INFO();
            GetNativeSystemInfo(ref sysInfo);

            switch (processorArchitecture)
            {
                case PROCESSOR_ARCHITECTURE_ARM64:

                    if (manufacturer.Equals(QUALCOMM_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        bool isArmv81Supported = IsProcessorFeaturePresent(ProcessorFeature.ARM_SUPPORTED_INSTRUCTIONS);

                        if (!isArmv81Supported)
                        {
                            string registryName = "CP 4030";
                            long registryValue = (long)Registry.GetValue(registryPath, registryName, -1);
                            long atomicResult = (registryValue >> 20) & 0xF;

                            if (atomicResult >= 2)
                            {
                                isArmv81Supported = true;
                            }
                        }

                        cpuFamilyResult.IsValid = isArmv81Supported;
                        cpuFamilyResult.Message = isArmv81Supported ? "" : "Processor does not implement ARM v8.1 atomic instruction";
                    }
                    else
                    {
                        cpuFamilyResult.IsValid = false;
                        cpuFamilyResult.Message = "The processor isn't currently supported for Windows 11";
                    }

                    break;

                case PROCESSOR_ARCHITECTURE_X64:
                case PROCESSOR_ARCHITECTURE_X86:

                    int cpuFamily = sysInfo.ProcessorLevel;
                    int cpuModel = (sysInfo.ProcessorRevision >> 8) & 0xFF;
                    int cpuStepping = sysInfo.ProcessorRevision & 0xFF;

                    if (manufacturer.Equals(INTEL_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            cpuFamilyResult.IsValid = true;
                            cpuFamilyResult.Message = "";

                            if (cpuFamily >= 6 && cpuModel <= 95 && !(cpuFamily == 6 && cpuModel == 85))
                            {
                                cpuFamilyResult.IsValid = false;
                                cpuFamilyResult.Message = "";
                            }
                            else if (cpuFamily == 6 && (cpuModel == 142 || cpuModel == 158) && cpuStepping == 9)
                            {
                                string registryName = "Platform Specific Field 1";
                                int registryValue = (int)Registry.GetValue(registryPath, registryName, -1);

                                if ((cpuModel == 142 && registryValue != 16) || (cpuModel == 158 && registryValue != 8))
                                {
                                    cpuFamilyResult.IsValid = false;
                                }
                                cpuFamilyResult.Message = "PlatformId " + registryValue;
                            }
                        }
                        catch (Exception ex)
                        {
                            cpuFamilyResult.IsValid = false;
                            cpuFamilyResult.Message = "Exception:" + ex.GetType().Name;
                        }
                    }
                    else if (manufacturer.Equals(AMD_MANUFACTURER, StringComparison.OrdinalIgnoreCase))
                    {
                        cpuFamilyResult.IsValid = true;
                        cpuFamilyResult.Message = "";

                        if (cpuFamily < 23 || (cpuFamily == 23 && (cpuModel == 1 || cpuModel == 17)))
                        {
                            cpuFamilyResult.IsValid = false;
                        }
                    }
                    else
                    {
                        cpuFamilyResult.IsValid = false;
                        cpuFamilyResult.Message = "Unsupported Manufacturer: " + manufacturer + ", Architecture: " + processorArchitecture + ", CPUFamily: " + sysInfo.ProcessorLevel + ", ProcessorRevision: " + sysInfo.ProcessorRevision;
                    }

                    break;

                default:
                    cpuFamilyResult.IsValid = false;
                    cpuFamilyResult.Message = "Unsupported CPU category. Manufacturer: " + manufacturer + ", Architecture: " + processorArchitecture + ", CPUFamily: " + sysInfo.ProcessorLevel + ", ProcessorRevision: " + sysInfo.ProcessorRevision;
                    break;
            }
            return cpuFamilyResult;
        }
    }
"@

	# Storage - OS drive
	try {
		$osDrive = Get-CimInstance -Class Win32_OperatingSystem | Select-Object -Property SystemDrive
		$osDriveSize = Get-CimInstance -Class Win32_LogicalDisk -Filter "DeviceID='$($osDrive.SystemDrive)'" | Select-Object @{Name = "SizeGB"; Expression = { $_.Size / 1GB -as [int] } }
		$freeSpaceGB = (Get-CimInstance -Class Win32_LogicalDisk -Filter "DeviceID='$($osDrive.SystemDrive)'" | Select-Object @{Name = "FreeSpaceGB"; Expression = { $_.FreeSpace / 1GB -as [int] } }).FreeSpaceGB
		if ($null -eq $osDriveSize) {
			UpdateReturnCode -ReturnCode 1
			$outObject.returnReason += "Storage, "
			$outObject.logging += "Storage: Storage is null :: FAIL; "
		} elseif ($osDriveSize.SizeGB -lt $MinOSDiskSizeGB) {
			UpdateReturnCode -ReturnCode 1
			$outObject.returnReason += "Storage, "
			$outObject.logging += "Storage: OSDiskSize=$($osDriveSize.SizeGB)GB :: FAIL; "
		} else {
			$outObject.logging += "Storage: OSDiskSize=$($osDriveSize.SizeGB)GB :: PASS; "
			UpdateReturnCode -ReturnCode 0
		}
	} catch {
		UpdateReturnCode -ReturnCode -1
		$outObject.logging += "Storage: OSDiskSize=Undetermined :: UNDETERMINED; "
		$outObject.logging += "$($_.Exception.GetType().Name) $($_.Exception.Message); "
	}

	# Storage - Free Diskspace
	try {
		$osDrive = Get-CimInstance -Class Win32_OperatingSystem | Select-Object -Property SystemDrive
		$osDriveSize = Get-CimInstance -Class Win32_LogicalDisk -Filter "DeviceID='$($osDrive.SystemDrive)'" | Select-Object @{Name = "SizeGB"; Expression = { $_.Size / 1GB -as [int] } }
		$freeSpaceGB = (Get-CimInstance -Class Win32_LogicalDisk -Filter "DeviceID='$($osDrive.SystemDrive)'" | Select-Object @{Name = "FreeSpaceGB"; Expression = { $_.FreeSpace / 1GB -as [int] } }).FreeSpaceGB

		if ($null -eq $freeSpaceGB) {
			UpdateReturnCode -ReturnCode 1
			$outObject.returnReason += "Storage, "
			$outObject.logging += "Storage: Storage is null :: FAIL; "
		} elseif ($freeSpaceGB -lt $MinOSDiskSizeGB) {
			UpdateReturnCode -ReturnCode 1
			$outObject.returnReason += "Free Space, "
			$outObject.logging += "Free Space: Less than 64GB :: FAIL; "
		} else {
			$outObject.logging += "FreeSpace: FreeSpace=$($freeSpaceGB)GB :: PASS; "
			UpdateReturnCode -ReturnCode 0
		}
	} catch {
		UpdateReturnCode -ReturnCode -1
		$outObject.logging += "Storage: OSDiskSize=Undetermined :: UNDETERMINED; "
		$outObject.logging += "$($_.Exception.GetType().Name) $($_.Exception.Message); "
	}

	# Memory (bytes)
	try {
		$memory = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum | Select-Object @{Name = "SizeGB"; Expression = { $_.Sum / 1GB -as [int] } }

		if ($null -eq $memory) {
			UpdateReturnCode -ReturnCode 1
			$outObject.returnReason += $logFormatReturnReason -f $MEMORY_STRING
			$outObject.logging += $logFormatWithBlob -f $MEMORY_STRING, "Memory is null", $FAIL_STRING
			$exitCode = 1
		} elseif ($memory.SizeGB -lt $MinMemoryGB) {
			UpdateReturnCode -ReturnCode 1
			$outObject.returnReason += $logFormatReturnReason -f $MEMORY_STRING
			$outObject.logging += $logFormatWithUnit -f $MEMORY_STRING, $SYSTEM_MEMORY_STRING, ($memory.SizeGB), $GB_UNIT_STRING, $FAIL_STRING
			$exitCode = 1
		} else {
			$outObject.logging += $logFormatWithUnit -f $MEMORY_STRING, $SYSTEM_MEMORY_STRING, ($memory.SizeGB), $GB_UNIT_STRING, $PASS_STRING
			UpdateReturnCode -ReturnCode 0
		}
	} catch {
		UpdateReturnCode -ReturnCode -1
		$outObject.logging += $logFormat -f $MEMORY_STRING, $SYSTEM_MEMORY_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
		$outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
		$exitCode = 1
	}

	# TPM
	try {
		$tpm = Get-Tpm

		if ($null -eq $tpm) {
			UpdateReturnCode -ReturnCode 1
			$outObject.returnReason += $logFormatReturnReason -f $TPM_STRING
			$outObject.logging += $logFormatWithBlob -f $TPM_STRING, "TPM is null", $FAIL_STRING
			$exitCode = 1
		} elseif ($tpm.TpmPresent) {
			$tpmVersion = Get-CimInstance -Class Win32_Tpm -Namespace root\CIMV2\Security\MicrosoftTpm | Select-Object -Property SpecVersion

			if ($null -eq $tpmVersion.SpecVersion) {
				UpdateReturnCode -ReturnCode 1
				$outObject.returnReason += $logFormatReturnReason -f $TPM_STRING
				$outObject.logging += $logFormat -f $TPM_STRING, $TPM_VERSION_STRING, "null", $FAIL_STRING
				$exitCode = 1
			}

			$majorVersion = $tpmVersion.SpecVersion.Split(",")[0] -as [int]
			if ($majorVersion -lt 2) {
				UpdateReturnCode -ReturnCode 1
				$outObject.returnReason += $logFormatReturnReason -f $TPM_STRING
				$outObject.logging += $logFormat -f $TPM_STRING, $TPM_VERSION_STRING, ($tpmVersion.SpecVersion), $FAIL_STRING
				$exitCode = 1
			} else {
				$outObject.logging += $logFormat -f $TPM_STRING, $TPM_VERSION_STRING, ($tpmVersion.SpecVersion), $PASS_STRING
				UpdateReturnCode -ReturnCode 0
			}
		} else {
			if ($tpm.GetType().Name -eq "String") {
				UpdateReturnCode -ReturnCode -1
				$outObject.logging += $logFormat -f $TPM_STRING, $TPM_VERSION_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
				$outObject.logging += $logFormatException -f $tpm
			} else {
				UpdateReturnCode -ReturnCode 1
				$outObject.returnReason += $logFormatReturnReason -f $TPM_STRING
				$outObject.logging += $logFormat -f $TPM_STRING, $TPM_VERSION_STRING, ($tpm.TpmPresent), $FAIL_STRING
			}
			$exitCode = 1
		}
	} catch {
		UpdateReturnCode -ReturnCode -1
		$outObject.logging += $logFormat -f $TPM_STRING, $TPM_VERSION_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
		$outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
		$exitCode = 1
	}

	# CPU Details
	try {
		$cpuDetails = @(Get-CimInstance -Class Win32_Processor)[0]

		if ($null -eq $cpuDetails) {
			UpdateReturnCode -ReturnCode 1
			$exitCode = 1
			$outObject.returnReason += $logFormatReturnReason -f $PROCESSOR_STRING
			$outObject.logging += $logFormatWithBlob -f $PROCESSOR_STRING, "CpuDetails is null", $FAIL_STRING
		} else {
			$processorCheckFailed = $false

			# AddressWidth
			if ($null -eq $cpuDetails.AddressWidth -or $cpuDetails.AddressWidth -ne $RequiredAddressWidth) {
				UpdateReturnCode -ReturnCode 1
				$processorCheckFailed = $true
				$exitCode = 1
			}

			# ClockSpeed is in MHz
			if ($null -eq $cpuDetails.MaxClockSpeed -or $cpuDetails.MaxClockSpeed -le $MinClockSpeedMHz) {
				UpdateReturnCode -ReturnCode 1;
				$processorCheckFailed = $true
				$exitCode = 1
			}

			# Number of Logical Cores
			if ($null -eq $cpuDetails.NumberOfLogicalProcessors -or $cpuDetails.NumberOfLogicalProcessors -lt $MinLogicalCores) {
				UpdateReturnCode -ReturnCode 1
				$processorCheckFailed = $true
				$exitCode = 1
			}

			# CPU Family
			if (-not ([System.Management.Automation.PSTypeName]'CpuFamily').Type) {
				Add-Type -TypeDefinition $Source
			}
			$cpuFamilyResult = [CpuFamily]::Validate([String]$cpuDetails.Manufacturer, [uint16]$cpuDetails.Architecture)

			$cpuDetailsLog = "{`nAddressWidth=$($cpuDetails.AddressWidth); MaxClockSpeed=$($cpuDetails.MaxClockSpeed); NumberOfLogicalCores=$($cpuDetails.NumberOfLogicalProcessors); Manufacturer=$($cpuDetails.Manufacturer); Caption=$($cpuDetails.Caption); $($cpuFamilyResult.Message)}"

			if (!$cpuFamilyResult.IsValid) {
				UpdateReturnCode -ReturnCode 1
				$processorCheckFailed = $true
				$exitCode = 1
			}

			if ($processorCheckFailed) {
				$outObject.returnReason += $logFormatReturnReason -f $PROCESSOR_STRING
				$outObject.logging += $logFormatWithBlob -f $PROCESSOR_STRING, ($cpuDetailsLog), $FAIL_STRING
			} else {
				$outObject.logging += $logFormatWithBlob -f $PROCESSOR_STRING, ($cpuDetailsLog), $PASS_STRING
				UpdateReturnCode -ReturnCode 0
			}
		}
	} catch {
		UpdateReturnCode -ReturnCode -1
		$outObject.logging += $logFormat -f $PROCESSOR_STRING, $PROCESSOR_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
		$outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
		$exitCode = 1
	}

	# SecureBooot Capable
	try {
		$isSecureBootEnabled = Confirm-SecureBootUEFI
		$outObject.logging += $logFormatWithBlob -f $SECUREBOOT_STRING, $CAPABLE_STRING, $PASS_STRING
		UpdateReturnCode -ReturnCode 0

		# SecureBooot Enable
		if ($isSecureBootEnabled) {
			$outObject.logging += "Secure Boot is enabled :: PASS"
			UpdateReturnCode -ReturnCode 0
		} else {
			$outObject.logging += "Secure Boot is not enabled :: FAIL"
			UpdateReturnCode -ReturnCode 1
		}

	} catch [System.PlatformNotSupportedException] {
		# PlatformNotSupportedException "Cmdlet not supported on this platform." - SecureBoot is not supported or is non-UEFI computer.
		UpdateReturnCode -ReturnCode 1
		$outObject.returnReason += $logFormatReturnReason -f $SECUREBOOT_STRING
		$outObject.logging += $logFormatWithBlob -f $SECUREBOOT_STRING, $NOT_CAPABLE_STRING, $FAIL_STRING
		$exitCode = 1
	} catch [System.UnauthorizedAccessException] {
		UpdateReturnCode -ReturnCode -1
		$outObject.logging += $logFormatWithBlob -f $SECUREBOOT_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
		$outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
		$exitCode = 1
	} catch {
		UpdateReturnCode -ReturnCode -1
		$outObject.logging += $logFormatWithBlob -f $SECUREBOOT_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
		$outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
		$exitCode = 1
	}

	# i7-7820hq CPU
	try {
		$supportedDevices = @('surface studio 2', 'precision 5520')
		$systemInfo = @(Get-CimInstance -Class Win32_ComputerSystem)[0]

		if ($null -ne $cpuDetails) {
			if ($cpuDetails.Name -match 'i7-7820hq cpu @ 2.90ghz') {
				$modelOrSKUCheckLog = $systemInfo.Model.Trim()
				if ($supportedDevices -contains $modelOrSKUCheckLog) {
					$outObject.logging += $logFormatWithBlob -f $I7_7820HQ_CPU_STRING, $modelOrSKUCheckLog, $PASS_STRING
					$outObject.returnCode = 0
					$exitCode = 0
				}
			}
		}
	} catch {
		if ($outObject.returnCode -ne 0) {
			UpdateReturnCode -ReturnCode -1
			$outObject.logging += $logFormatWithBlob -f $I7_7820HQ_CPU_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
			$outObject.logging += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
			$exitCode = 1
		}
	}

	# Check OS Requirements
	#>Check if os version Windows 10 2004 or higher
	$osCheckLog = ""
	try {
		$targetVersion = [version]"10.0.19041.0"
		$os = Get-CimInstance -Class Win32_OperatingSystem
		$version = [version]$os.Version
		$osInfo = Get-ComputerInfo -Property 'OsName', 'OSDisplayVersion'
		if ($null -ne $os) {
			if ($version -ge $targetVersion) {
				$osCheckLog = $logFormat -f $OS_VERSION_STRING, $OS_VERSION, "$($osInfo.OsName) - $($osInfo.OSDisplayVersion)", $PASS_STRING
				UpdateReturnCode -ReturnCode 0
			} else {
				$osCheckLog = $logFormat -f $OS_VERSION_STRING, $OS_VERSION, "$($osInfo.OsName) - $($osInfo.OSDisplayVersion)", $FAIL_STRING
				UpdateReturnCode -ReturnCode 1
				$exitCode = 1
			}
		}

	} catch {
		UpdateReturnCode -ReturnCode -1
		$osCheckLog += $logFormatWithBlob -f $OS_VERSION_STRING, $UNDETERMINED_STRING, $UNDETERMINED_CAPS_STRING
		$osCheckLog += $logFormatException -f "$($_.Exception.GetType().Name) $($_.Exception.Message)"
		$exitCode = 1
	}

	return $outObject

}

#=============================================================================================================================
# MAIN SCRIPT EXECUTION
#=============================================================================================================================

Write-Log -Message 'Starting Windows 11 Upgrade Orchestration...' -Level INFO

# === 1. PREREQUISITES ===
# 1a. Check for Administrative Privileges
Write-Log -Message 'Checking for Administrator privileges...' -Level INFO
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
	Write-Log -Message 'This script must be run as Administrator. Please re-launch from an elevated PowerShell prompt.' -Level ERROR
	return # Stop execution
}
Write-Log -Message '  [PASS] Running as Administrator.' -Level INFO

# 1b. Create Log Directory
$UpgradeLogDir = 'C:\Temp\UpgradeLog'
Write-Log -Message ('Ensuring log directory exists at {0}...' -f $UpgradeLogDir) -Level INFO
try {
	if (-not (Test-Path -Path $UpgradeLogDir -PathType Container)) {
		New-Item -Path $UpgradeLogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
		Write-Log -Message '  [PASS] Created log directory.' -Level INFO
	} else {
		Write-Log -Message '  [PASS] Log directory already exists.' -Level INFO
	}
} catch {
	Write-Log -Message ('Failed to create log directory at {0}. Error: {1}' -f $UpgradeLogDir, $_.Exception.Message) -Level ERROR
	return
}

# 1c. Check for readiness
Write-Log -Message 'Running Windows 11 readiness check...' -Level INFO
if (-not $SkipReadinessCheck.IsPresent) {
	try {
		$r = Test-Win11Readiness -ErrorAction Stop
		if ($r.returnCode -ne 0) {
			Write-Log -Message ('Hardware readiness check failed with code {0}. {1}' -f $r.returnCode, $r.returnReason) -Level ERROR
			return
		}
	} catch {
		Write-Log -Message ('The readiness check function (Test-Win11Readiness) failed to run. Error: {0}' -f $_.Exception.Message) -Level ERROR
		return
	}
} else {
	Write-Log -Message '  [SKIP] -SkipReadinessCheck was specified. Skipping hardware readiness check.' -Level WARN
}

# 1d. Check for Windows SKU
Write-Log -Message 'Checking for Windows Operating System SKU' -Level INFO
if (-not $SkipSKUCheck.IsPresent) {
	try {
		if ((Get-CimInstance Win32_OperatingSystem).OperatingSystemSKU -in @(1..10)) {
			Write-Log -Message 'Operating System SKU not in Typical Range' -Level ERROR
			return
		}
	} catch {
		Write-Log -Message 'Checking Operating System SKU failed.' -Level ERROR
	}
} else {
	Write-Log -Message '  [SKIP] -SkipSKUCheck was specified. Skipping.' -Level WARN
}

# 1e. Check for WIndows ESU License
Write-Log -Message 'Checking for Windows 10 Extended Security Updates License' -Level INFO
if (-not $SkipESUCheck.IsPresent) {
	try {
		$licenseProduct = Get-CimInstance -ClassName SoftwareLicensingProduct -Property ("ID", "ApplicationId", "PartialProductKey", "LicenseIsAddon", "Description", "Name", "LicenseStatus", "VLActivationTypeEnabled") -Filter 'PartialProductKey <> null AND ApplicationId = "55c92734-d682-4d71-983e-d6ec3f16059f"' | Where-Object { ($_.Name -match 'ESU') -and ($_.LicenseStatus -eq 1) }
		if ($null -ne $licenseProduct) {
			Write-Log -Message ('Windows ESU License ID: {0}' -f $licenseProduct.ID) -Level ERROR
			return
		}
	} catch {
		Write-Log -Message 'Checking Operating System ESU failed.' -Level ERROR
	}
} else {
	Write-Log -Message '  [SKIP] -SkipESUCheck was specified. Skipping.' -Level WARN
}

# === 2. PREPARATION ===
$downloadUrl = 'https://go.microsoft.com/fwlink/?linkid=2171764'
$installerName = $null

# 2a. Resolve final filename
Write-Log -Message ('Resolving download filename from {0}...' -f $downloadUrl) -Level INFO
try {
	$installerName = Resolve-UrlFinalFileName -Url $downloadUrl -ErrorAction Stop
	if (-not $installerName) {
		Write-Log -Message 'Could not resolve the installer filename from the URL.' -Level ERROR
		return
	}
	$MachineTempDir = [System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')
	if ([string]::IsNullOrWhiteSpace($MachineTempDir) -or -not (Test-Path -Path $MachineTempDir)) {
		$MachineTempDir = [System.IO.Path]::GetTempPath()
	}
	$localInstallerPath = Join-Path -Path $MachineTempDir -ChildPath $installerName
	Write-Log -Message ('  [PASS] Resolved filename: {0}. Target path: {1}' -f $installerName, $localInstallerPath) -Level INFO
} catch {
	Write-Log -Message ('The filename resolver function (Resolve-UrlFinalFileName) failed. Error: {0}' -f $_.Exception.Message) -Level ERROR
	return
}

# 2b. Download the file
Write-Log -Message ('Downloading {0}...' -f $installerName) -Level INFO
$webClient = $null
try {
	# Use System.Net.WebClient for PowerShell 5.x compatibility
	$webClient = New-Object System.Net.WebClient
	$webClient.DownloadFile($downloadUrl, $localInstallerPath)
	Write-Log -Message '  [PASS] Download complete.' -Level INFO
} catch {
	Write-Log -Message ('Failed to download file. Error: {0}' -f $_.Exception.Message) -Level ERROR
	return
} finally {
	if ($webClient) { $webClient.Dispose() }
}

# 2c. Set file permissions
Write-Log -Message ('  Setting ''ReadAndExecute'' permissions for ''Everyone'' on ''{0}''...' -f $localInstallerPath) -Level INFO
try {
	$acl = Get-Acl -Path $localInstallerPath
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Authenticated Users', 'ReadAndExecute', 'Allow')
	$acl.AddAccessRule($rule)
	Set-Acl -Path $localInstallerPath -AclObject $acl -ErrorAction Stop
	Write-Log -Message '  Permissions set successfully.' -Level INFO
} catch {
	# Non-fatal error. Warn the user and continue.
	Write-Log -Message ('  Could not set file permissions. The script will still attempt to run the installer. Error: {0}' -f $_.Exception.Message) -Level WARN
}

# === 3. EXECUTION / SHORTCUT CREATION ===
Write-Log -Message 'Processing execution step...' -Level INFO

# Define arguments
$arguments = ('/Install /MinimizeToTaskBar /NoRestartUI /QuietInstall /SkipEULA /copylogs "{0}"' -f $UpgradeLogDir)

Write-Log -Message ('  Installer: {0}' -f $localInstallerPath) -Level INFO
Write-Log -Message ('  Arguments: {0}' -f $arguments) -Level INFO

if ($UpgradeNow.IsPresent) {
	Write-Log -Message '  Action: -UpgradeNow specified. Starting Windows 11 Installation Assistant (Quiet Mode)...' -Level INFO
	try {
		$process = Start-Process -FilePath $localInstallerPath -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop

		Write-Log -Message ('  [PASS] Upgrade process finished with Exit Code: {0}.' -f $process.ExitCode) -Level INFO

		if ($process.ExitCode -ne 0) {
			Write-Log -Message ('The installer exited with a non-zero code. Check logs in {0} for details.' -f $UpgradeLogDir) -Level WARN
		} else {
			Write-Log -Message 'Upgrade process completed successfully. A restart will be required.' -Level INFO
		}
	} catch {
		Write-Log -Message ('Failed to start the installer process. Error: {0}' -f $_.Exception.Message) -Level ERROR
		return
	}
} else {
	Write-Log -Message '  Action: -UpgradeNow not specified. Creating desktop shortcut...' -Level INFO
	$shortcutPath = 'C:\Users\Public\Desktop\Upgrade Windows.lnk'
	try {
		# Use WScript.Shell to create the shortcut
		$shell = New-Object -ComObject WScript.Shell
		$shortcut = $shell.CreateShortcut($shortcutPath)
		$shortcut.TargetPath = $localInstallerPath
		$shortcut.Arguments = $arguments
		$shortcut.Description = 'Start the Windows 11 Upgrade'
		# Use the installer's own icon (index 0)
		$shortcut.IconLocation = ('{0},0' -f $localInstallerPath)
		$shortcut.WorkingDirectory = [System.IO.Path]::GetDirectoryName($localInstallerPath)
		$shortcut.Save()

		Write-Log -Message ('  [PASS] Successfully created shortcut at {0}.' -f $shortcutPath) -Level INFO
		Write-Log -Message 'The script has downloaded the installer and created a public desktop shortcut.' -Level INFO
		Write-Log -Message 'Run the ''Upgrade Windows'' shortcut to begin the upgrade.' -Level INFO
	} catch {
		Write-Log -Message ('Failed to create shortcut. Error: {0}' -f $_.Exception.Message) -Level ERROR
		return
	}
}

Write-Log -Message 'Windows 11 Upgrade Orchestration Finished.' -Level INFO

