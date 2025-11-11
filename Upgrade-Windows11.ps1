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
Version:        1.2.20
Dependencies:   This script requires the following functions to be defined in the same scope:
                - Check-Win11Readiness
                - Resolve-UrlFinalFileName
Requirements:   Must be run with Administrator privileges.
.LINK
Based on the Microsoft HardwareReadiness script.
#>

[CmdletBinding()]
param(
	[switch]$UpgradeNow,
	[switch]$SkipReadinessCheck,
	[switch]$SkipSKUCheck
)

#region --- Helper Functions ---

function Write-Log {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Message,
		[ValidateSet('TRACE', 'INFO', 'WARN', 'ERROR')]
		[string]$Level = 'INFO'
	)
	$FormattedMessage = ('{0} [{1}] {2}' -f (Get-Date -Format 's'), $Level, $Message)

	if ([Environment]::GetCommandLineArgs().Contains('-NonInteractive')) {
		Write-Output $FormattedMessage
	} else {
		$ColorMap = @{
			TRACE = 'DarkGray'
			INFO  = 'Green'
			WARN  = 'Yellow'
			ERROR = 'Red'
		}
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
		$request = [System.Net.WebRequest]::CreateHttp($Url)
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
			# Write-Output "$("-"*18)`nStatus : Unsupported`n$("-"*18)`nDetails`n$("-"*10)"
			# Write-Output "Installed OS: '$($installedOs)' not Supported :: $FAIL_STRING"
			# exit 1
			return 0x0101
		} elseif ($installedOs -imatch "Windows 7") {
			# Write-Output "$("-"*18)`nStatus : Unsupported`n$("-"*18)`nDetails`n$("-"*10)"
			# Write-Output "Installed OS: '$($installedOs)' not Supported :: $FAIL_STRING"
			# exit 1
			return 0x0102
		}
	} catch {
		# Write-Output "$("-"*18)`nStatus : Unsupported`n$("-"*18)`nDetails`n$("-"*10)"
		# Write-Output "Unexpected Error Occurred: $($_.Exception.Message)"
		# exit 1
		return 0x0103
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
			Add-Type -TypeDefinition $Source
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
		$osInfo = Get-ComputerInfo | Select-Object OsName, OSDisplayVersion
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

	# switch ($outObject.returnCode) {

	# 	0 {
	# 		Write-Output "$("-"*18)`nStatus : Supported`n$("-"*18)`nDetails : HARDWARE`n$("-"*10)"
	# 		Write-Output (($outObject.logging).Split(";")).trim()
	# 		Write-Output "$("-"*18)`nDetails : OS`n$("-"*10)"
	# 		Write-Output (($osCheckLog).Split(";")).trim()


	# 	}
	# 	1 {
	# 		Write-Output "$("-"*20)`nStatus : Unsupported`n$("-"*20)`nDetails : HARDWARE`n$("-"*10)"
	# 		Write-Output (($outObject.logging).Split(";")).trim()
	# 		Write-Output "$("-"*18)`nDetails : OS`n$("-"*10)"
	# 		Write-Output (($osCheckLog).Split(";")).trim()
	# 	}
	# 	-1 {
	# 		Write-Output "$("-"*20)`nStatus : Unsupported`n$("-"*20)`nDetails :`n$("-"*10)"
	# 		Write-Output (($outObject.logging).Split(";")).trim()
	# 		Write-Output "$("-"*18)`nDetails : OS`n$("-"*10)"
	# 		Write-Output (($osCheckLog).Split(";")).trim()

	# 	}
	# 	-2 {
	# 		Write-Output "$("-"*20)`nStatus : Unsupported`n$("-"*20)`nDetails :`n$("-"*10)"
	# 		Write-Output (($outObject.logging).Split(";")).trim()
	# 	}
	# }

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
}else {
	Write-Log -Message '  [SKIP] -SkipSKUCheck was specified. Skipping.' -Level WARN
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
	$localInstallerPath = Join-Path -Path ([System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')) -ChildPath $installerName
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
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Everyone', 'ReadAndExecute', 'Allow')
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
$arguments = ('/Install /MinimizeToTaskBar /NoRestartUI /QuietInstall /SkipEULA /copylogs {0}' -f $UpgradeLogDir)

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

# SIG # Begin signature block
# MII+EQYJKoZIhvcNAQcCoII+AjCCPf4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDQTncvqLyIv1E+
# u7bj1Td/ThvloYQMpMIiZAGNMxkkHqCCItYwggXMMIIDtKADAgECAhBUmNLR1FsZ
# lUgTecgRwIeZMA0GCSqGSIb3DQEBDAUAMHcxCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jvc29mdCBJZGVu
# dGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAy
# MDAeFw0yMDA0MTYxODM2MTZaFw00NTA0MTYxODQ0NDBaMHcxCzAJBgNVBAYTAlVT
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jv
# c29mdCBJZGVudGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRo
# b3JpdHkgMjAyMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALORKgeD
# Bmf9np3gx8C3pOZCBH8Ppttf+9Va10Wg+3cL8IDzpm1aTXlT2KCGhFdFIMeiVPvH
# or+Kx24186IVxC9O40qFlkkN/76Z2BT2vCcH7kKbK/ULkgbk/WkTZaiRcvKYhOuD
# PQ7k13ESSCHLDe32R0m3m/nJxxe2hE//uKya13NnSYXjhr03QNAlhtTetcJtYmrV
# qXi8LW9J+eVsFBT9FMfTZRY33stuvF4pjf1imxUs1gXmuYkyM6Nix9fWUmcIxC70
# ViueC4fM7Ke0pqrrBc0ZV6U6CwQnHJFnni1iLS8evtrAIMsEGcoz+4m+mOJyoHI1
# vnnhnINv5G0Xb5DzPQCGdTiO0OBJmrvb0/gwytVXiGhNctO/bX9x2P29Da6SZEi3
# W295JrXNm5UhhNHvDzI9e1eM80UHTHzgXhgONXaLbZ7LNnSrBfjgc10yVpRnlyUK
# xjU9lJfnwUSLgP3B+PR0GeUw9gb7IVc+BhyLaxWGJ0l7gpPKWeh1R+g/OPTHU3mg
# trTiXFHvvV84wRPmeAyVWi7FQFkozA8kwOy6CXcjmTimthzax7ogttc32H83rwjj
# O3HbbnMbfZlysOSGM1l0tRYAe1BtxoYT2v3EOYI9JACaYNq6lMAFUSw0rFCZE4e7
# swWAsk0wAly4JoNdtGNz764jlU9gKL431VulAgMBAAGjVDBSMA4GA1UdDwEB/wQE
# AwIBhjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTIftJqhSobyhmYBAcnz1AQ
# T2ioojAQBgkrBgEEAYI3FQEEAwIBADANBgkqhkiG9w0BAQwFAAOCAgEAr2rd5hnn
# LZRDGU7L6VCVZKUDkQKL4jaAOxWiUsIWGbZqWl10QzD0m/9gdAmxIR6QFm3FJI9c
# Zohj9E/MffISTEAQiwGf2qnIrvKVG8+dBetJPnSgaFvlVixlHIJ+U9pW2UYXeZJF
# xBA2CFIpF8svpvJ+1Gkkih6PsHMNzBxKq7Kq7aeRYwFkIqgyuH4yKLNncy2RtNwx
# AQv3Rwqm8ddK7VZgxCwIo3tAsLx0J1KH1r6I3TeKiW5niB31yV2g/rarOoDXGpc8
# FzYiQR6sTdWD5jw4vU8w6VSp07YEwzJ2YbuwGMUrGLPAgNW3lbBeUU0i/OxYqujY
# lLSlLu2S3ucYfCFX3VVj979tzR/SpncocMfiWzpbCNJbTsgAlrPhgzavhgplXHT2
# 6ux6anSg8Evu75SjrFDyh+3XOjCDyft9V77l4/hByuVkrrOj7FjshZrM77nq81YY
# uVxzmq/FdxeDWds3GhhyVKVB0rYjdaNDmuV3fJZ5t0GNv+zcgKCf0Xd1WF81E+Al
# GmcLfc4l+gcK5GEh2NQc5QfGNpn0ltDGFf5Ozdeui53bFv0ExpK91IjmqaOqu/dk
# ODtfzAzQNb50GQOmxapMomE2gj4d8yu8l13bS3g7LfU772Aj6PXsCyM2la+YZr9T
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggb/MIIE56ADAgECAhMzAAXq/AUK
# 4yo3Eu1pAAAABer8MA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBBT0MgQ0EgMDIwHhcNMjUxMTAzMDEwMzU4WhcNMjUxMTA2
# MDEwMzU4WjB+MQswCQYDVQQGEwJVUzERMA8GA1UECBMITWljaGlnYW4xEjAQBgNV
# BAcTCUthbGFtYXpvbzEjMCEGA1UEChMaTnVXYXZlIFRlY2hub2xvZ3kgUGFydG5l
# cnMxIzAhBgNVBAMTGk51V2F2ZSBUZWNobm9sb2d5IFBhcnRuZXJzMIIBojANBgkq
# hkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAm84yyb2bqzfBUO+DZkX8oRnq/1eDaqS9
# AXQy0dL9h24zPEd3uY0DTaJ5rCy/nkq9mVmtraHKX9tACD79qcLU68BBitA5t4Sy
# VrzQge2zV/w8mCpXKMK3DNO8ziUwp1AST2JOLYNL4y7WA9QZXfVPG++gS1DBfEeK
# 5mMYhmuXtQamRYhutBMCoTmRAnDnOQEy/WJhcOlJuKWOUe3d/wme3XRU1XKHkaU6
# Dzap3VAmIJG46GLBPv6tTYiPzn59WrSNIRba3d0ok/7Hw2qKcop8ygYWCKjmqXUg
# EkJz80cwZujemI5uggjfSv9Ama+CQ0TAtnkCEfINYJ81WmHItf5juLpHLHFLgddt
# bXCCOjR1qPNmwjlKIrE7mLMpCuQYrAwT9yeK7E+QwvDi1hq7YMsXN8BtyjVQfc7i
# Bgqc9ifhF3QySeBzqFaVVbs0ryt0KIQBVhcUYqiHxtId/V98NCOizP2QjFwxWa+E
# +10GcYte/kRhvcMM12pBKbEtRiaNNFwDAgMBAAGjggIYMIICFDAMBgNVHRMBAf8E
# AjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3YQEABggrBgEF
# BQcDAwYaKwYBBAGCN2HukfNMg8bbxHSBjNbafbipvhswHQYDVR0OBBYEFCCxdxNw
# 2W5vpG/YzeAQsjD6+fjrMB8GA1UdIwQYMBaAFCRFmaF3kCp8w8qDsG5kFoQq+Cxn
# MGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEFPQyUyMENB
# JTIwMDIuY3JsMIGlBggrBgEFBQcBAQSBmDCBlTBkBggrBgEFBQcwAoZYaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBJRCUy
# MFZlcmlmaWVkJTIwQ1MlMjBBT0MlMjBDQSUyMDAyLmNydDAtBggrBgEFBQcwAYYh
# aHR0cDovL29uZW9jc3AubWljcm9zb2Z0LmNvbS9vY3NwMGYGA1UdIARfMF0wUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAEwDQYJKoZI
# hvcNAQEMBQADggIBAM+xLhObcm9wunmfD6jzk91AlPSHGDdbkw9E6RVWHQwzgXfV
# sWRP8w5EbXZA1+5gFfZzmeY1C4Eified4V2MntL9WGq8RWcy2nc7Jjmr+RbSS9n1
# TRx5IrS8rVzTWj9jfApSzmxH8K3qLKeWjOgehLpGbdBgS3YFjxmEwQBxENY8Usyn
# 3Xm3NBgFhJdr45QQMY/MosHJEmLtRxhp7Sv1auwIOiLNnzqu3NP8R4yWKblG7a2O
# oE2+u84kW3IS/R7IwGhgVgpTUsYLUeEo5/Yt3KK1v5KuNl7UxejVLEwU7Ud6uXnv
# F+O5DKlznOSWla5vN5id/THYFOmkvC+ePXCX4KKtJUkOn5hRHRZrgLaCg278pwPy
# YGSZ1NPqoxPmleo5BZaEXB3FQ1xD5aIi0B6NrNloHydnZVDA2BhrpKm2yT5bQMDB
# tqQ4KKtoZBK/6hMYVCi6b4CS5nwbvhEB/h+EoiBN/e0lVGHKdHsAzw2V4780Ax/m
# dGNc1RHI9kkv6wqoY5O8dFdgl72FEwFu2SgsLhNmUxkuBJo3PXSb+Z8+2ZuSivKB
# kks5sPhU65KCMsZEKru61m4sfgy+Smt/yTVwHDtuWDMLGfkEeRKO3olsc0m7swOw
# kNxk3MkdaavygHxXp8ctGPud0reoKDpln7QahbjtejSpFPQE0r8VOxesEhgGMIIG
# /zCCBOegAwIBAgITMwAF6vwFCuMqNxLtaQAAAAXq/DANBgkqhkiG9w0BAQwFADBa
# MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSsw
# KQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgQU9DIENBIDAyMB4XDTI1
# MTEwMzAxMDM1OFoXDTI1MTEwNjAxMDM1OFowfjELMAkGA1UEBhMCVVMxETAPBgNV
# BAgTCE1pY2hpZ2FuMRIwEAYDVQQHEwlLYWxhbWF6b28xIzAhBgNVBAoTGk51V2F2
# ZSBUZWNobm9sb2d5IFBhcnRuZXJzMSMwIQYDVQQDExpOdVdhdmUgVGVjaG5vbG9n
# eSBQYXJ0bmVyczCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAJvOMsm9
# m6s3wVDvg2ZF/KEZ6v9Xg2qkvQF0MtHS/YduMzxHd7mNA02ieawsv55KvZlZra2h
# yl/bQAg+/anC1OvAQYrQObeEsla80IHts1f8PJgqVyjCtwzTvM4lMKdQEk9iTi2D
# S+Mu1gPUGV31TxvvoEtQwXxHiuZjGIZrl7UGpkWIbrQTAqE5kQJw5zkBMv1iYXDp
# SbiljlHt3f8Jnt10VNVyh5GlOg82qd1QJiCRuOhiwT7+rU2Ij85+fVq0jSEW2t3d
# KJP+x8NqinKKfMoGFgio5ql1IBJCc/NHMGbo3piOboII30r/QJmvgkNEwLZ5AhHy
# DWCfNVphyLX+Y7i6RyxxS4HXbW1wgjo0dajzZsI5SiKxO5izKQrkGKwME/cniuxP
# kMLw4tYau2DLFzfAbco1UH3O4gYKnPYn4Rd0Mkngc6hWlVW7NK8rdCiEAVYXFGKo
# h8bSHf1ffDQjosz9kIxcMVmvhPtdBnGLXv5EYb3DDNdqQSmxLUYmjTRcAwIDAQAB
# o4ICGDCCAhQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwOwYDVR0lBDQw
# MgYKKwYBBAGCN2EBAAYIKwYBBQUHAwMGGisGAQQBgjdh7pHzTIPG28R0gYzW2n24
# qb4bMB0GA1UdDgQWBBQgsXcTcNlub6Rv2M3gELIw+vn46zAfBgNVHSMEGDAWgBQk
# RZmhd5AqfMPKg7BuZBaEKvgsZzBnBgNVHR8EYDBeMFygWqBYhlZodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBJRCUyMFZlcmlm
# aWVkJTIwQ1MlMjBBT0MlMjBDQSUyMDAyLmNybDCBpQYIKwYBBQUHAQEEgZgwgZUw
# ZAYIKwYBBQUHMAKGWGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwQU9DJTIwQ0ElMjAw
# Mi5jcnQwLQYIKwYBBQUHMAGGIWh0dHA6Ly9vbmVvY3NwLm1pY3Jvc29mdC5jb20v
# b2NzcDBmBgNVHSAEXzBdMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wCAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQDPsS4Tm3JvcLp5nw+o85Pd
# QJT0hxg3W5MPROkVVh0MM4F31bFkT/MORG12QNfuYBX2c5nmNQuBIn4nneFdjJ7S
# /VhqvEVnMtp3OyY5q/kW0kvZ9U0ceSK0vK1c01o/Y3wKUs5sR/Ct6iynlozoHoS6
# Rm3QYEt2BY8ZhMEAcRDWPFLMp915tzQYBYSXa+OUEDGPzKLByRJi7UcYae0r9Wrs
# CDoizZ86rtzT/EeMlim5Ru2tjqBNvrvOJFtyEv0eyMBoYFYKU1LGC1HhKOf2Ldyi
# tb+SrjZe1MXo1SxMFO1Herl57xfjuQypc5zklpWubzeYnf0x2BTppLwvnj1wl+Ci
# rSVJDp+YUR0Wa4C2goNu/KcD8mBkmdTT6qMT5pXqOQWWhFwdxUNcQ+WiItAejazZ
# aB8nZ2VQwNgYa6Sptsk+W0DAwbakOCiraGQSv+oTGFQoum+AkuZ8G74RAf4fhKIg
# Tf3tJVRhynR7AM8NleO/NAMf5nRjXNURyPZJL+sKqGOTvHRXYJe9hRMBbtkoLC4T
# ZlMZLgSaNz10m/mfPtmbkorygZJLObD4VOuSgjLGRCq7utZuLH4Mvkprf8k1cBw7
# blgzCxn5BHkSjt6JbHNJu7MDsJDcZNzJHWmr8oB8V6fHLRj7ndK3qCg6ZZ+0GoW4
# 7Xo0qRT0BNK/FTsXrBIYBjCCB1owggVCoAMCAQICEzMAAAAEllBL0tvuy4gAAAAA
# AAQwDQYJKoZIhvcNAQEMBQAwYzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjE0MDIGA1UEAxMrTWljcm9zb2Z0IElEIFZlcmlmaWVk
# IENvZGUgU2lnbmluZyBQQ0EgMjAyMTAeFw0yMTA0MTMxNzMxNTJaFw0yNjA0MTMx
# NzMxNTJaMFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBBT0MgQ0Eg
# MDIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDhzqDoM6JjpsA7AI9s
# GVAXa2OjdyRRm5pvlmisydGnis6bBkOJNsinMWRn+TyTiK8ElXXDn9v+jKQj55cC
# pprEx3IA7Qyh2cRbsid9D6tOTKQTMfFFsI2DooOxOdhz9h0vsgiImWLyTnW6locs
# vsJib1g1zRIVi+VoWPY7QeM73L81GZxY2NqZk6VGPFbZxaBSxR1rNIeBEJ6TztXZ
# sz/Xtv6jxZdRb3UimCBFqyaJnrlYQUdcpvKGbYtuEErplaZCgV4T4ZaspYIYr+r/
# hGJNow2Edda9a/7/8jnxS07FWLcNorV9DpgvIggYfMPgKa1ysaK/G6mr9yuse6cY
# 0Hv/9Ca6XZk/0dw6Zj9qm2BSfBP7bSD8DfuIN+65XDrJLYujT+Sn+Nv4ny8TgUyo
# iLDEYHIvjzY8xUELep381sVBrwyaPp6exT4cSq/1qv4BtwrC6ZtmokkqZCsZpI11
# Z+TY2h2BxY6aruPKFvHBk6OcuPT9vCexQ1w0B7T2/6qKjPJBB6zwDdRc9xFBvwb5
# zTJo7YgKJ9ZMrvJK7JQnzyTWa03bYI1+1uOK2IB5p+hn1WaGflF9v5L8rlqtW9Nw
# u6S3k91MNDGXnnsQgToD7pcUGl2yM7OQvN0SHsQuTw9U8yNB88KAq0nzhzXt93YL
# 36nEXWURBQVdj9i0Iv42az1xZQIDAQABo4ICDjCCAgowDgYDVR0PAQH/BAQDAgGG
# MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBQkRZmhd5AqfMPKg7BuZBaEKvgs
# ZzBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgw
# FoAU2UEpsA8PY2zvadf1zSmepEhqMOYwcAYDVR0fBGkwZzBloGOgYYZfaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwSUQlMjBW
# ZXJpZmllZCUyMENvZGUlMjBTaWduaW5nJTIwUENBJTIwMjAyMS5jcmwwga4GCCsG
# AQUFBwEBBIGhMIGeMG0GCCsGAQUFBzAChmFodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDb2Rl
# JTIwU2lnbmluZyUyMFBDQSUyMDIwMjEuY3J0MC0GCCsGAQUFBzABhiFodHRwOi8v
# b25lb2NzcC5taWNyb3NvZnQuY29tL29jc3AwDQYJKoZIhvcNAQEMBQADggIBAGct
# OF2Vsw0iiR0q3NJryKj6kQ73kJzdU7Jj+FCwghx0zKTaEk7Mu38zVZd9DISUOT9C
# 3IvNfrdN05vkn6c7y3SnPPCLtli8yI2oq8BA7nSww4mfdPeEI+mnE02GgYVXHPZT
# KJDhva86tywsr1M4QVdZtQwk5tH08zTBmwAEiG7iTpVUvEQN7QZJ5Bf9kTs8d9OD
# jgu5+3ggqpiae/UK6iyneCUVixV6AucxZlRnxS070XxAKICi4liEvk6UKSyANv29
# 78dCEsWd6V+Dp1C5sgWyoH0iUKidgoln8doxm9i0DvL0Q5ErhzGW9N60JcAdrKJJ
# cfS54T9P3bBUbRyy/lV1TKPrJWubba+UpgCRcg0q8M4Hz6ziH5OBKGVRrYAK7YVa
# fsnOVNJumTQgTxES5iaS7IT8FOST3dYMzHs/Auefgn7l+S9uONDTw57B+kyGHxK4
# 91AqqZnjQjhbZTIkowxNt63XokWKZKoMKGCcIHqXCWl7SB9uj3tTumult8EqnoHa
# TZ/tj5ONatBg3451w87JAB3EYY8HAlJokbeiF2SULGAAnlqcLF5iXtKNDkS5rpq2
# Mh5WE3Qp88sU+ljPkJBT4kLYfv3Hh387pg4VH1ph7nj8Ia6nt1FQh8tK/X+PQM9z
# oSV/djJbGWhaPzJ5jeQetkVoCVEzCEBfI9DesRf3MIIHnjCCBYagAwIBAgITMwAA
# AAeHozSje6WOHAAAAAAABzANBgkqhkiG9w0BAQwFADB3MQswCQYDVQQGEwJVUzEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMUgwRgYDVQQDEz9NaWNyb3Nv
# ZnQgSWRlbnRpdHkgVmVyaWZpY2F0aW9uIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9y
# aXR5IDIwMjAwHhcNMjEwNDAxMjAwNTIwWhcNMzYwNDAxMjAxNTIwWjBjMQswCQYD
# VQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTQwMgYDVQQD
# EytNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ29kZSBTaWduaW5nIFBDQSAyMDIxMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsvDArxmIKOLdVHpMSWxpCFUJ
# tFL/ekr4weslKPdnF3cpTeuV8veqtmKVgok2rO0D05BpyvUDCg1wdsoEtuxACEGc
# gHfjPF/nZsOkg7c0mV8hpMT/GvB4uhDvWXMIeQPsDgCzUGzTvoi76YDpxDOxhgf8
# JuXWJzBDoLrmtThX01CE1TCCvH2sZD/+Hz3RDwl2MsvDSdX5rJDYVuR3bjaj2Qfz
# ZFmwfccTKqMAHlrz4B7ac8g9zyxlTpkTuJGtFnLBGasoOnn5NyYlf0xF9/bjVRo4
# Gzg2Yc7KR7yhTVNiuTGH5h4eB9ajm1OCShIyhrKqgOkc4smz6obxO+HxKeJ9bYmP
# f6KLXVNLz8UaeARo0BatvJ82sLr2gqlFBdj1sYfqOf00Qm/3B4XGFPDK/H04kteZ
# EZsBRc3VT2d/iVd7OTLpSH9yCORV3oIZQB/Qr4nD4YT/lWkhVtw2v2s0TnRJubL/
# hFMIQa86rcaGMhNsJrhysLNNMeBhiMezU1s5zpusf54qlYu2v5sZ5zL0KvBDLHtL
# 8F9gn6jOy3v7Jm0bbBHjrW5yQW7S36ALAt03QDpwW1JG1Hxu/FUXJbBO2AwwVG4F
# re+ZQ5Od8ouwt59FpBxVOBGfN4vN2m3fZx1gqn52GvaiBz6ozorgIEjn+PhUXILh
# AV5Q/ZgCJ0u2+ldFGjcCAwEAAaOCAjUwggIxMA4GA1UdDwEB/wQEAwIBhjAQBgkr
# BgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU2UEpsA8PY2zvadf1zSmepEhqMOYwVAYD
# VR0gBE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAZBgkrBgEEAYI3FAIE
# DB4KAFMAdQBiAEMAQTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFMh+0mqF
# KhvKGZgEByfPUBBPaKiiMIGEBgNVHR8EfTB7MHmgd6B1hnNodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBJZGVudGl0eSUyMFZl
# cmlmaWNhdGlvbiUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIw
# MjAuY3JsMIHDBggrBgEFBQcBAQSBtjCBszCBgQYIKwYBBQUHMAKGdWh0dHA6Ly93
# d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwSWRlbnRp
# dHklMjBWZXJpZmljYXRpb24lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3Jp
# dHklMjAyMDIwLmNydDAtBggrBgEFBQcwAYYhaHR0cDovL29uZW9jc3AubWljcm9z
# b2Z0LmNvbS9vY3NwMA0GCSqGSIb3DQEBDAUAA4ICAQB/JSqe/tSr6t1mCttXI0y6
# XmyQ41uGWzl9xw+WYhvOL47BV09Dgfnm/tU4ieeZ7NAR5bguorTCNr58HOcA1tcs
# HQqt0wJsdClsu8bpQD9e/al+lUgTUJEV80Xhco7xdgRrehbyhUf4pkeAhBEjABvI
# UpD2LKPho5Z4DPCT5/0TlK02nlPwUbv9URREhVYCtsDM+31OFU3fDV8BmQXv5hT2
# RurVsJHZgP4y26dJDVF+3pcbtvh7R6NEDuYHYihfmE2HdQRq5jRvLE1Eb59PYwIS
# FCX2DaLZ+zpU4bX0I16ntKq4poGOFaaKtjIA1vRElItaOKcwtc04CBrXSfyL2Op6
# mvNIxTk4OaswIkTXbFL81ZKGD+24uMCwo/pLNhn7VHLfnxlMVzHQVL+bHa9KhTyz
# wdG/L6uderJQn0cGpLQMStUuNDArxW2wF16QGZ1NtBWgKA8Kqv48M8HfFqNifN6+
# zt6J0GwzvU8g0rYGgTZR8zDEIJfeZxwWDHpSxB5FJ1VVU1LIAtB7o9PXbjXzGifa
# IMYTzU4YKt4vMNwwBmetQDHhdAtTPplOXrnI9SI6HeTtjDD3iUN/7ygbahmYOHk7
# VB7fwT4ze+ErCbMh6gHV1UuXPiLciloNxH6K4aMfZN1oLVk6YFeIJEokuPgNPa6E
# nTiOL60cPqfny+Fq8UiuZzGCGpEwghqNAgEBMHEwWjELMAkGA1UEBhMCVVMxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjErMCkGA1UEAxMiTWljcm9zb2Z0
# IElEIFZlcmlmaWVkIENTIEFPQyBDQSAwMgITMwAF6vwFCuMqNxLtaQAAAAXq/DAN
# BglghkgBZQMEAgEFAKBeMBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMC8GCSqGSIb3DQEJBDEiBCDCAQSesd9gKy2J1FTnNHnLuH0O
# Wq9e/wl9Z15Y1LFp+DANBgkqhkiG9w0BAQEFAASCAYAAXjr/JQqnLhXFvXxjir3F
# bxVdBrKRTsIVEjeYp+E1xoA1dysJF+4af7yOOIBw8zx6IIOEyMN8o/ht6TVIdKCh
# Owa2pe46D0puU85XOlPdmjbNLAb8Sr5YLTl8BR4yygKOsjUNauQVRLrWKxcCTyGj
# MS4xTP7Ic0rdt+20iU9z1PtSh7SUj9iNTunDuPiwo88Kh8atNAT3oaj5LPy5tPzL
# 8XyMO1bntFsGGOcKkb2v/sH5FAElkUB7gqsv4pv61GaxWDJ9brWSjODq5Timf79s
# 3RUdebA7lLV62CxevYHkJE/QXtS7dATOVygCOx4tcOHqrB5Or0M4E85oSsOY0lU8
# 1ex0jjpphzSiHD1QWoXIsWu0prGCx4uNnQNhcsLwh6twZyJaTpkihvLgWgXVDZhu
# fTNi1qEqPB4IlPTJahR3ZPdQIlKWxjOOzjOeDmbDfwILM3qXrWFFWRX+eKRuQJ9r
# RcSCeMTkwR20YFPeprVq0DpGvI44VJnOe0td+daMtcChghgRMIIYDQYKKwYBBAGC
# NwMDATGCF/0wghf5BgkqhkiG9w0BBwKgghfqMIIX5gIBAzEPMA0GCWCGSAFlAwQC
# AQUAMIIBYgYLKoZIhvcNAQkQAQSgggFRBIIBTTCCAUkCAQEGCisGAQQBhFkKAwEw
# MTANBglghkgBZQMEAgEFAAQguRvBC3cC4I73eqCxKjgEKr3ha7oTvo1TMANc1Z22
# 9y4CBmkBUllDbhgTMjAyNTExMDMyMDQ5MzguODgzWjAEgAIB9KCB4aSB3jCB2zEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1Mg
# RVNOOkE1MDAtMDVFMC1EOTQ3MTUwMwYDVQQDEyxNaWNyb3NvZnQgUHVibGljIFJT
# QSBUaW1lIFN0YW1waW5nIEF1dGhvcml0eaCCDyEwggeCMIIFaqADAgECAhMzAAAA
# BeXPD/9mLsmHAAAAAAAFMA0GCSqGSIb3DQEBDAUAMHcxCzAJBgNVBAYTAlVTMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xSDBGBgNVBAMTP01pY3Jvc29m
# dCBJZGVudGl0eSBWZXJpZmljYXRpb24gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3Jp
# dHkgMjAyMDAeFw0yMDExMTkyMDMyMzFaFw0zNTExMTkyMDQyMzFaMGExCzAJBgNV
# BAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMT
# KU1pY3Jvc29mdCBQdWJsaWMgUlNBIFRpbWVzdGFtcGluZyBDQSAyMDIwMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnnznUmP94MWfBX1jtQYioxwe1+eX
# M9ETBb1lRkd3kcFdcG9/sqtDlwxKoVIcaqDb+omFio5DHC4RBcbyQHjXCwMk/l3T
# OYtgoBjxnG/eViS4sOx8y4gSq8Zg49REAf5huXhIkQRKe3Qxs8Sgp02KHAznEa/S
# sah8nWo5hJM1xznkRsFPu6rfDHeZeG1Wa1wISvlkpOQooTULFm809Z0ZYlQ8Lp7i
# 5F9YciFlyAKwn6yjN/kR4fkquUWfGmMopNq/B8U/pdoZkZZQbxNlqJOiBGgCWpx6
# 9uKqKhTPVi3gVErnc/qi+dR8A2MiAz0kN0nh7SqINGbmw5OIRC0EsZ31WF3Uxp3G
# gZwetEKxLms73KG/Z+MkeuaVDQQheangOEMGJ4pQZH55ngI0Tdy1bi69INBV5Kn2
# HVJo9XxRYR/JPGAaM6xGl57Ei95HUw9NV/uC3yFjrhc087qLJQawSC3xzY/EXzsT
# 4I7sDbxOmM2rl4uKK6eEpurRduOQ2hTkmG1hSuWYBunFGNv21Kt4N20AKmbeuSnG
# nsBCd2cjRKG79+TX+sTehawOoxfeOO/jR7wo3liwkGdzPJYHgnJ54UxbckF914Aq
# HOiEV7xTnD1a69w/UTxwjEugpIPMIIE67SFZ2PMo27xjlLAHWW3l1CEAFjLNHd3E
# Q79PUr8FUXetXr0CAwEAAaOCAhswggIXMA4GA1UdDwEB/wQEAwIBhjAQBgkrBgEE
# AYI3FQEEAwIBADAdBgNVHQ4EFgQUa2koOjUvSGNAz3vYr0npPtk92yEwVAYDVR0g
# BE0wSzBJBgRVHSAAMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEF
# BQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFMh+0mqFKhvKGZgEByfPUBBPaKiiMIGEBgNVHR8EfTB7MHmg
# d6B1hnNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3Nv
# ZnQlMjBJZGVudGl0eSUyMFZlcmlmaWNhdGlvbiUyMFJvb3QlMjBDZXJ0aWZpY2F0
# ZSUyMEF1dGhvcml0eSUyMDIwMjAuY3JsMIGUBggrBgEFBQcBAQSBhzCBhDCBgQYI
# KwYBBQUHMAKGdWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMv
# TWljcm9zb2Z0JTIwSWRlbnRpdHklMjBWZXJpZmljYXRpb24lMjBSb290JTIwQ2Vy
# dGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDIwLmNydDANBgkqhkiG9w0BAQwFAAOC
# AgEAX4h2x35ttVoVdedMeGj6TuHYRJklFaW4sTQ5r+k77iB79cSLNe+GzRjv4pVj
# JviceW6AF6ycWoEYR0LYhaa0ozJLU5Yi+LCmcrdovkl53DNt4EXs87KDogYb9eGE
# ndSpZ5ZM74LNvVzY0/nPISHz0Xva71QjD4h+8z2XMOZzY7YQ0Psw+etyNZ1Cesuf
# U211rLslLKsO8F2aBs2cIo1k+aHOhrw9xw6JCWONNboZ497mwYW5EfN0W3zL5s3a
# d4Xtm7yFM7Ujrhc0aqy3xL7D5FR2J7x9cLWMq7eb0oYioXhqV2tgFqbKHeDick+P
# 8tHYIFovIP7YG4ZkJWag1H91KlELGWi3SLv10o4KGag42pswjybTi4toQcC/irAo
# dDW8HNtX+cbz0sMptFJK+KObAnDFHEsukxD+7jFfEV9Hh/+CSxKRsmnuiovCWIOb
# +H7DRon9TlxydiFhvu88o0w35JkNbJxTk4MhF/KgaXn0GxdH8elEa2Imq45gaa8D
# +mTm8LWVydt4ytxYP/bqjN49D9NZ81coE6aQWm88TwIf4R4YZbOpMKN0CyejaPNN
# 41LGXHeCUMYmBx3PkP8ADHD1J2Cr/6tjuOOCztfp+o9Nc+ZoIAkpUcA/X2gSMkgH
# APUvIdtoSAHEUKiBhI6JQivRepyvWcl+JYbYbBh7pmgAXVswggeXMIIFf6ADAgEC
# AhMzAAAAVn6PnVgIjulgAAAAAABWMA0GCSqGSIb3DQEBDAUAMGExCzAJBgNVBAYT
# AlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1p
# Y3Jvc29mdCBQdWJsaWMgUlNBIFRpbWVzdGFtcGluZyBDQSAyMDIwMB4XDTI1MTAy
# MzIwNDY1MVoXDTI2MTAyMjIwNDY1MVowgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJh
# dGlvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpBNTAwLTA1RTAtRDk0NzE1
# MDMGA1UEAxMsTWljcm9zb2Z0IFB1YmxpYyBSU0EgVGltZSBTdGFtcGluZyBBdXRo
# b3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0pZ+b+6XTbv93
# xGVvwyf+DRBS+8upjZWzLe0jxTa0VKylNmiZk4PcEdPwuRH5GuEwmBvVWMAoU3Kx
# or1wtJeJ88ZIgGs8KCz0/jLbiWskSatXpDnPgGaoyEg+tmES9mdakJLgc7uNhJ6L
# +fGYLv/USv6XkuDc+ZLFvx3YhVwBHFLDUHibEHpcjSeR6X3BrV1hvbB8amh+toWb
# Fk7FP142G3gsfREFJW55trpk2mNL/SC1+buqIiLI/qno9HNNNsydWqwedX93+tbT
# MfH5D5A1nnBSoqZNkkH2FTznf7alfmsN8rfa41j39YE4CbNuqCkR1CRuIxq9QzJQ
# NKGbJwi+Ad1CdLbTuxOPwz6Qkve051qE+4+ozCxoIKB1/DBDHQ71Mp7sVK9sARiz
# UCeV0KX8ocZkI5W9Q2qPIvXQkt7T/4YP3/KepcZYWlc6Nq6e9n9wpE6GM3gzl7rH
# HRvaaKpw+KLj+KLZmF4pqWUkRPsIqWkVKGzfDKDoX9+iNDFC8+dtYPg3LHqWGNaP
# CagtzHrDUVIK1q8sKXLfcEtFKVNTiopTFprx3tg3sSqmf1c7RJjS6Y68oVetYfuv
# GX72JqJyK12dNOSwCdGO96R0pPeWDuVEx+Z9lTy9c2I3RRgnNP0SOqNGbS43+HSh
# fE+E189ip4VvI9cYbHNphTPrPHepNwIDAQABo4IByzCCAccwHQYDVR0OBBYEFL62
# M/K7q1n+HkazIu/LPUf4U0haMB8GA1UdIwQYMBaAFGtpKDo1L0hjQM972K9J6T7Z
# PdshMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY3JsL01pY3Jvc29mdCUyMFB1YmxpYyUyMFJTQSUyMFRpbWVzdGFtcGlu
# ZyUyMENBJTIwMjAyMC5jcmwweQYIKwYBBQUHAQEEbTBrMGkGCCsGAQUFBzAChl1o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUy
# MFB1YmxpYyUyMFJTQSUyMFRpbWVzdGFtcGluZyUyMENBJTIwMjAyMC5jcnQwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMC
# B4AwZgYDVR0gBF8wXTBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRt
# MAgGBmeBDAEEAjANBgkqhkiG9w0BAQwFAAOCAgEADgOoBcSw7bqP8trsWCf9CJ+K
# 3zG5l6Spnnv5h76wf+FFNsQSMZitmCyrBH+VRR8oIWltkXyaxpk9Ak5HhhhQRTxf
# KMuufxjWMJKajGH2Xu1aJKhz8kUHDfnokCbMYbF4EDYRZLFG5OvUC5l7qdho3z/C
# 0WSIdyzyAxp3FcGzoPFWHK7lieEs9CR+6YqbeUV+3ATumJ5Xt/WWySaWCwLoB5IY
# LMY9lSAK9wflO/9B73PtsgiZIPdK7OE4jBo/54pBNh/rtOJ/IkqRZBJ0Z9MDopy7
# jWTwsHqg8r4wuTWNvHErnA+otIvrbGMrThIFccQlISewW3TPFaTE/+WB6PUPGpSe
# atgR2TG/MpIcgCoVZJm6X/mEj68nG8U+Gw1AESThxK6UOQlClx1WL+CZ/+YcU5iE
# MGOxrXmzgv7awGKXddX9PxGJHrpDzFi9MtFbF3Z1Wys6gLCexThYh6ILQmKcK/VY
# scSHtDLOv1FKviQoktZ2k1guGCOSiNOYSQCMU7vvi3fEHt6du8gXQY6xXX3GcJTO
# r0QYrK3SAy5qmEqU2Mn5pOmNYxkMaj4Y4qyen3ceZ+2aXRLKncX34zfL7LpYkZRm
# ghkmrbbuMOOMSd22lSuH0F091Uh9UkP8C7zVHOHTlQcCK+itDc6zw8QsciCI531N
# bNt2CYbNwgu3911VARExggdDMIIHPwIBATB4MGExCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBQ
# dWJsaWMgUlNBIFRpbWVzdGFtcGluZyBDQSAyMDIwAhMzAAAAVn6PnVgIjulgAAAA
# AABWMA0GCWCGSAFlAwQCAQUAoIIEnDARBgsqhkiG9w0BCRACDzECBQAwGgYJKoZI
# hvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yNTExMDMyMDQ5
# MzhaMC8GCSqGSIb3DQEJBDEiBCBRzdZgregQL86HveFX18WaYn11H6PDsoGogaMh
# R+eKzDCBuQYLKoZIhvcNAQkQAi8xgakwgaYwgaMwgaAEILYMMyVNpOPwlXeJODle
# el7gJIfrTXjdn5f2jk0GAwyoMHwwZaRjMGExCzAJBgNVBAYTAlVTMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBQdWJs
# aWMgUlNBIFRpbWVzdGFtcGluZyBDQSAyMDIwAhMzAAAAVn6PnVgIjulgAAAAAABW
# MIIDXgYLKoZIhvcNAQkQAhIxggNNMIIDSaGCA0UwggNBMIICKQIBATCCAQmhgeGk
# gd4wgdsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGll
# bGQgVFNTIEVTTjpBNTAwLTA1RTAtRDk0NzE1MDMGA1UEAxMsTWljcm9zb2Z0IFB1
# YmxpYyBSU0EgVGltZSBTdGFtcGluZyBBdXRob3JpdHmiIwoBATAHBgUrDgMCGgMV
# AP9z9ykVKpBZgF5eCDJEnZlu9gQRoGcwZaRjMGExCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBQ
# dWJsaWMgUlNBIFRpbWVzdGFtcGluZyBDQSAyMDIwMA0GCSqGSIb3DQEBCwUAAgUA
# 7LMREjAiGA8yMDI1MTEwMzExMzEzMFoYDzIwMjUxMTA0MTEzMTMwWjB0MDoGCisG
# AQQBhFkKBAExLDAqMAoCBQDssxESAgEAMAcCAQACAgKbMAcCAQACAhIxMAoCBQDs
# tGKSAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMH
# oSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEBAE1sYqWKuNiv4dFU5QRk
# I26UvYrjrMpINhy7MV3cUXBaKwgnEtqcXxCU+ZXo/mo9FYg9TXp9uhetv/C+s3i1
# Q4HZ6dFsOAuLzSMijgJ2Ds8X/92pM7mbF3/Wn/J2ZMU9L8XdTPMuykgduu8Rl6El
# QqxIssD3NjxfeGyJHXqLaJHhKgCwM9f8VzCnjgUy/GuUfZYpyxblw9IbGAnWSXzI
# y1JVX/cxFeByN/2pXT4KOdgAjLxkZyfDkSxl0JFP5hN16QTBOJEgRHNLeqsLiAAg
# +LD1vgA43gyfQXJ0zNLYI47Ucd6PoDjo2WUZV9Rs/hpaDf82KxTY0dOHPgAuRj5K
# dTgwDQYJKoZIhvcNAQEBBQAEggIAHm4HhteadRUr57MbszhIsz0gR00kTrS6dDK2
# RnUpxKRI+whs5JBxf+q8fZE6TQXnlWYEVhtTb15NOaVUufLR3ep1cPzy6tSWiwYJ
# m5IE/DsFPn9xBVG/b5u38U2N88DHm3e7KhsOwZe/1tZ8mrbfa001ZtBycTGs9eth
# ndQdLHKuEzx1PY3FHDnHbae0Gyr/JH51VSmQGoAB0ez6dDdxrZ4x7yzpvyf4/iin
# ekLFxH5y8IgAFDcqXiFwcDPdBAhinVR5+cYRKRc1doFuMAJd8RL8lxxcYMHE3GXm
# 9OtfFG2vZJZXVv6QaF19iMWPqWC2XE+v+LjeWwebmRYEcCrCTnii5uWx+uQrtLfH
# xkgAl/5Bbj6e/H7Mx6N7k+XkEE4xP59GOuXYlJZ1i/gI+7BYfbJTfLthjeGKaoEs
# 8ufbtuNEsnMqeBZeKmAURLMoISzeCTK6bnOxvFg0jDZ/LJuOPRSyOSOTX5ofgzgL
# bhg560+P6Vy+ZN7SqTzMdVA2B1sLcodddgxGCVxmt03bFV0xAxPOBxCPWn8TJTXC
# YxcgBQdwCkJuIk6q2zzoSYF2LvDZj+gDo6BpmI0rraFVdOx1Bt0RMrASOShl72V7
# Mo4idZVjyb/qKxxgu4wBNQDF45dw9o0rUlwtNSRAgEQMM314XlZNG4WHYD6p0qMu
# k1SUi64=
# SIG # End signature block
