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
	[switch]$SkipSKUCheck,
	[switch]$SkipESUCheck
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

# 1e. Check for WIndows ESU License
Write-Log -Message 'Checking for Windows 10 Extended Security Updates License' -Level INFO
if (-not $SkipESUCheck.IsPresent) {
	try {
		$licenseProduct = Get-CimInstance -ClassName SoftwareLicensingProduct -Property ("ID", "ApplicationId", "PartialProductKey", "LicenseIsAddon", "Description", "Name", "LicenseStatus", "VLActivationTypeEnabled") -Filter 'PartialProductKey <> null AND ApplicationId = "55c92734-d682-4d71-983e-d6ec3f16059f"' | Where-Object {($_.Name -match 'ESU') -and ($_.LicenseStatus -eq 1)}
		if ($null -ne $licenseProduct) {
			Write-Log -Message ('Windows ESU License ID: {0}' -f $licenseProduct.ID) -Level ERROR
			return
		}
	}catch {
		Write-Log -Message 'Checking Operating System ESU failed.' -Level ERROR
	}
}else {
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
# MII+EAYJKoZIhvcNAQcCoII+ATCCPf0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD2HG0bcx3bisjt
# G0fj+XPwnZlWGSM1HVBsYmN+YfMmmqCCItYwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggb/MIIE56ADAgECAhMzAAUvYh2y
# dChwW3PTAAAABS9iMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBFT0MgQ0EgMDIwHhcNMjUxMTEzMDA0MDIwWhcNMjUxMTE2
# MDA0MDIwWjB+MQswCQYDVQQGEwJVUzERMA8GA1UECBMITWljaGlnYW4xEjAQBgNV
# BAcTCUthbGFtYXpvbzEjMCEGA1UEChMaTnVXYXZlIFRlY2hub2xvZ3kgUGFydG5l
# cnMxIzAhBgNVBAMTGk51V2F2ZSBUZWNobm9sb2d5IFBhcnRuZXJzMIIBojANBgkq
# hkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAngFkEenGnprCTjyPoyMuo+XqOxb1fhXs
# 4JBFKO+qPVMLmibcfrX7Ck3tQ0NJW8JxG9KzflgiERx+E8oQfCr/ZCgDU1y7J66G
# IiAOiWNAJjTdwoJiBU7CdS5iORxZnH5aKzDOsBtz4sIcxz2Yb2rhJg/4dRN2j3Hy
# 1bjjkb1ccpK1CyGpo63pi8fgHxW5TQLyZldNjb21dm4T6QEkJxYXgIjSx3tibDiU
# E9e7yTFliwAZpiS8m1l1urrUIbxxLrvOAfUKTE8nlmpNjOk5YK2kgByJbPeMKJ77
# hZpuIM8dUEDtlcinAHjj24hie7tWCo82rgaVDE3cd9jfGAM3tbMjtILhz9KDqZ7h
# h+C7H14f9klJ1qTTdHGma3EBS187iQQu0EzFBPyiBOn97wvEVzqCAuS7e2I0Z5dj
# OhLmwFnG7yycJSnIqndakevtlkb3ZB2qKpjttAR23EqktG6AiFUY+a5qK3ZPhvn9
# mpSGy/DbxurQyBOKYGg8v/CU4mOpA933AgMBAAGjggIYMIICFDAMBgNVHRMBAf8E
# AjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3YQEABggrBgEF
# BQcDAwYaKwYBBAGCN2HukfNMg8bbxHSBjNbafbipvhswHQYDVR0OBBYEFFJq1WVu
# 9VZWGyzWkBLMgUMN9j8KMB8GA1UdIwQYMBaAFGWfUc6FaH8vikWIqt2nMbseDQBe
# MGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEVPQyUyMENB
# JTIwMDIuY3JsMIGlBggrBgEFBQcBAQSBmDCBlTBkBggrBgEFBQcwAoZYaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBJRCUy
# MFZlcmlmaWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDAyLmNydDAtBggrBgEFBQcwAYYh
# aHR0cDovL29uZW9jc3AubWljcm9zb2Z0LmNvbS9vY3NwMGYGA1UdIARfMF0wUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAEwDQYJKoZI
# hvcNAQEMBQADggIBABCNGaZ1kWeN9U5OaODhHOVxUML02SyZZoC/O0+cCNojfaj7
# rh95yANXCOFwVtuOuoZeCSv44kdVAbmaiO3iI26yj52dy6R52KFOXqovoYH62R6s
# u72zOkdfKB2V+Nj+8rkTW4h4nC/ZsgPTBf3rnhMSX2AK34jdSeL7dbmDv5QRuZtF
# ITaQzJtUEVpVJDBggPALivy/Qx8dg/pj4oNgR7c3tjKAXqEbIIHhn9Wi5nme3WaJ
# Ye2Y0Yq1DgsbKZTmfHA6LjlwSasOzPF52vagoiWaAyDz75pG2HSQQV0RSAB6B+uO
# 2kdXcyB1iSnTYYS0l9hDE5qzfzcTX9iGivHyxNjDAFY0Oz/5gyzi/CWpgrrKwrvH
# sP+/u/f4tVl4x39gTurkGcigmLIxqYwdpxiRik0u6SIu+2IHxJ9Fv2z+HGLE4awH
# v7YN5HQqOzAF8lfvHhaUJEiqyF0Yz0iTfwh+lMv8L26c6FW0v6ViX2x0QAxrgKZU
# GPM13DPAzrgDr4jSxHRZlM1lo7nXffHNNpnkvn/nEV6RjjLdJye8U0t6V4bKRtrg
# J+P3303Jwbb1J8gnpTfqsfm5/WV89SFKLIkhTOOLogvQgQKg6csTrPTAjIoRacTk
# FREL+y0KZ12CL2A4eMe7SuL2d/wGjjdCN/s9QVap4gxdsqazeLuaa/j80AmcMIIG
# /zCCBOegAwIBAgITMwAFL2IdsnQocFtz0wAAAAUvYjANBgkqhkiG9w0BAQwFADBa
# MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSsw
# KQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgRU9DIENBIDAyMB4XDTI1
# MTExMzAwNDAyMFoXDTI1MTExNjAwNDAyMFowfjELMAkGA1UEBhMCVVMxETAPBgNV
# BAgTCE1pY2hpZ2FuMRIwEAYDVQQHEwlLYWxhbWF6b28xIzAhBgNVBAoTGk51V2F2
# ZSBUZWNobm9sb2d5IFBhcnRuZXJzMSMwIQYDVQQDExpOdVdhdmUgVGVjaG5vbG9n
# eSBQYXJ0bmVyczCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAJ4BZBHp
# xp6awk48j6MjLqPl6jsW9X4V7OCQRSjvqj1TC5om3H61+wpN7UNDSVvCcRvSs35Y
# IhEcfhPKEHwq/2QoA1NcuyeuhiIgDoljQCY03cKCYgVOwnUuYjkcWZx+WiswzrAb
# c+LCHMc9mG9q4SYP+HUTdo9x8tW445G9XHKStQshqaOt6YvH4B8VuU0C8mZXTY29
# tXZuE+kBJCcWF4CI0sd7Ymw4lBPXu8kxZYsAGaYkvJtZdbq61CG8cS67zgH1CkxP
# J5ZqTYzpOWCtpIAciWz3jCie+4WabiDPHVBA7ZXIpwB449uIYnu7VgqPNq4GlQxN
# 3HfY3xgDN7WzI7SC4c/Sg6me4Yfgux9eH/ZJSdak03RxpmtxAUtfO4kELtBMxQT8
# ogTp/e8LxFc6ggLku3tiNGeXYzoS5sBZxu8snCUpyKp3WpHr7ZZG92QdqiqY7bQE
# dtxKpLRugIhVGPmuait2T4b5/ZqUhsvw28bq0MgTimBoPL/wlOJjqQPd9wIDAQAB
# o4ICGDCCAhQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwOwYDVR0lBDQw
# MgYKKwYBBAGCN2EBAAYIKwYBBQUHAwMGGisGAQQBgjdh7pHzTIPG28R0gYzW2n24
# qb4bMB0GA1UdDgQWBBRSatVlbvVWVhss1pASzIFDDfY/CjAfBgNVHSMEGDAWgBRl
# n1HOhWh/L4pFiKrdpzG7Hg0AXjBnBgNVHR8EYDBeMFygWqBYhlZodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBJRCUyMFZlcmlm
# aWVkJTIwQ1MlMjBFT0MlMjBDQSUyMDAyLmNybDCBpQYIKwYBBQUHAQEEgZgwgZUw
# ZAYIKwYBBQUHMAKGWGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwRU9DJTIwQ0ElMjAw
# Mi5jcnQwLQYIKwYBBQUHMAGGIWh0dHA6Ly9vbmVvY3NwLm1pY3Jvc29mdC5jb20v
# b2NzcDBmBgNVHSAEXzBdMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wCAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQAQjRmmdZFnjfVOTmjg4Rzl
# cVDC9NksmWaAvztPnAjaI32o+64fecgDVwjhcFbbjrqGXgkr+OJHVQG5mojt4iNu
# so+dncukedihTl6qL6GB+tkerLu9szpHXygdlfjY/vK5E1uIeJwv2bID0wX9654T
# El9gCt+I3Uni+3W5g7+UEbmbRSE2kMybVBFaVSQwYIDwC4r8v0MfHYP6Y+KDYEe3
# N7YygF6hGyCB4Z/VouZ5nt1miWHtmNGKtQ4LGymU5nxwOi45cEmrDszxedr2oKIl
# mgMg8++aRth0kEFdEUgAegfrjtpHV3MgdYkp02GEtJfYQxOas383E1/Yhorx8sTY
# wwBWNDs/+YMs4vwlqYK6ysK7x7D/v7v3+LVZeMd/YE7q5BnIoJiyMamMHacYkYpN
# LukiLvtiB8SfRb9s/hxixOGsB7+2DeR0KjswBfJX7x4WlCRIqshdGM9Ik38IfpTL
# /C9unOhVtL+lYl9sdEAMa4CmVBjzNdwzwM64A6+I0sR0WZTNZaO5133xzTaZ5L5/
# 5xFekY4y3ScnvFNLeleGykba4Cfj999NycG29SfIJ6U36rH5uf1lfPUhSiyJIUzj
# i6IL0IECoOnLE6z0wIyKEWnE5BURC/stCmddgi9gOHjHu0ri9nf8Bo43Qjf7PUFW
# qeIMXbKms3i7mmv4/NAJnDCCB1owggVCoAMCAQICEzMAAAAF+3pcMhNh310AAAAA
# AAUwDQYJKoZIhvcNAQEMBQAwYzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjE0MDIGA1UEAxMrTWljcm9zb2Z0IElEIFZlcmlmaWVk
# IENvZGUgU2lnbmluZyBQQ0EgMjAyMTAeFw0yMTA0MTMxNzMxNTNaFw0yNjA0MTMx
# NzMxNTNaMFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBFT0MgQ0Eg
# MDIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDSGpl8PzKQpMDoINta
# +yGYGkOgF/su/XfZFW5KpXBA7doAsuS5GedMihGYwajR8gxCu3BHpQcHTrF2o6QB
# +oHp7G5tdMe7jj524dQJ0TieCMQsFDKW4y5I6cdoR294hu3fU6EwRf/idCSmHj4C
# HR5HgfaxNGtUqYquU6hCWGJrvdCDZ0eiK1xfW5PW9bcqem30y3voftkdss2ykxku
# RYFpsoyXoF1pZldik8Z1L6pjzSANo0K8WrR3XRQy7vEd6wipelMNPdDcB47FLKVJ
# Nz/vg/eiD2Pc656YQVq4XMvnm3Uy+lp0SFCYPy4UzEW/+Jk6PC9x1jXOFqdUsvKm
# XPXf83NKhTdCOE92oAaFEjCH9gPOjeMJ1UmBZBGtbzc/epYUWTE2IwTaI7gi5iCP
# tHCx4bC/sj1zE7JoeKEox1P016hKOlI3NWcooZxgy050y0oWqhXsKKbabzgaYhhl
# MGitH8+j2LCVqxNgoWkZmp1YrJick7YVXygyZaQgrWJqAsuAS3plpHSuT/WNRiyz
# JOJGpavzhCzdcv9XkpQES1QRB9D/hG2cjT24UVQgYllX2YP/E5SSxah0asJBJ6bo
# fLbrXEwkAepOoy4MqDCLzGT+Z+WvvKFc8vvdI5Qua7UCq7gjsal7pDA1bZO1AHEz
# e+1JOZ09bqsrnLSAQPnVGOzIrQIDAQABo4ICDjCCAgowDgYDVR0PAQH/BAQDAgGG
# MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRln1HOhWh/L4pFiKrdpzG7Hg0A
# XjBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgw
# FoAU2UEpsA8PY2zvadf1zSmepEhqMOYwcAYDVR0fBGkwZzBloGOgYYZfaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwSUQlMjBW
# ZXJpZmllZCUyMENvZGUlMjBTaWduaW5nJTIwUENBJTIwMjAyMS5jcmwwga4GCCsG
# AQUFBwEBBIGhMIGeMG0GCCsGAQUFBzAChmFodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDb2Rl
# JTIwU2lnbmluZyUyMFBDQSUyMDIwMjEuY3J0MC0GCCsGAQUFBzABhiFodHRwOi8v
# b25lb2NzcC5taWNyb3NvZnQuY29tL29jc3AwDQYJKoZIhvcNAQEMBQADggIBAEVJ
# YNR3TxfiDkfO9V+sHVKJXymTpc8dP2M+QKa9T+68HOZlECNiTaAphHelehK1Elon
# +WGMLkOr/ZHs/VhFkcINjIrTO9JEx0TphC2AaOax2HMPScJLqFVVyB+Y1Cxw8nVY
# fFu8bkRCBhDRkQPUU3Qw49DNZ7XNsflVrR1LG2eh0FVGOfINgSbuw0Ry8kdMbd5f
# MDJ3TQTkoMKwSXjPk7Sa9erBofY9LTbTQTo/haovCCz82ZS7n4BrwvD/YSfZWQhb
# s+SKvhSfWMbr62P96G6qAXJQ88KHqRue+TjxuKyL/M+MBWSPuoSuvt9JggILMniz
# hhQ1VUeB2gWfbFtbtl8FPdAD3N+Gr27gTFdutUPmvFdJMURSDaDNCr0kfGx0fIx9
# wIosVA5c4NLNxh4ukJ36voZygMFOjI90pxyMLqYCrr7+GIwOem8pQgenJgTNZR5q
# 23Ipe0x/5Csl5D6fLmMEv7Gp0448TPd2Duqfz+imtStRsYsG/19abXx9Zd0C/U8K
# 0sv9pwwu0ejJ5JUwpBioMdvdCbS5D41DRgTiRTFJBr5b9wLNgAjfa43Sdv0zgyvW
# mPhslmJ02QzgnJip7OiEgvFiSAdtuglAhKtBaublFh3KEoGmm0n0kmfRnrcuN2fO
# U5TGOWwBtCKvZabP84kTvTcFseZBlHDM/HW+7tLnMIIHnjCCBYagAwIBAgITMwAA
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
# nTiOL60cPqfny+Fq8UiuZzGCGpAwghqMAgEBMHEwWjELMAkGA1UEBhMCVVMxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjErMCkGA1UEAxMiTWljcm9zb2Z0
# IElEIFZlcmlmaWVkIENTIEVPQyBDQSAwMgITMwAFL2IdsnQocFtz0wAAAAUvYjAN
# BglghkgBZQMEAgEFAKBeMBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMC8GCSqGSIb3DQEJBDEiBCDzDC1BXWrGPjTsK0kn6W754zRj
# fvWnp7quf9WOP4LEizANBgkqhkiG9w0BAQEFAASCAYBgtVMI125fGc73yyu3oG7f
# 8pbfsdOPvqxsxGWG9it62CmJlnLagQPX7GP/r42Gg2oe7oQ5DO7HTI9krD8WHFGk
# tYJYbM40kEgte6f0XJi5ibsaPasIC57qS6P/D39doUUpuuTgbsIWe4ema/fPXQ4O
# 1rftWuD+H/HxExfGEFiTr/HOZCXfEKvSQE6aSvGejTuzo6AlC6jrWRcEpRBbwr1p
# Wc6jtdsAE7ymlxsnGAvVR0vB1fJyQHGYvqIhr4UYf3BiXEfCFcej7ffxyLhGADlp
# ZL7FP8Mc3U5PcrgMFWxMSbpBw3aKXuogX3QAEcfySB/Iv/SMbsHpXC633GGhiJX6
# XvLvKbTkn3O0nhmLfV50Xf70ulhadps2ekSyXFsGrqSMycc8rkRxyAghbzwVfoiE
# yNOEiO7/iQcIwEbzNTaecpWnkSSNB3wMwnruVsAfuOBE59o1IZqrLKgme+n4OPiK
# AqUih7pHaitSJOhSG3raDiolJv08QvouRZCbCfW18guhghgQMIIYDAYKKwYBBAGC
# NwMDATGCF/wwghf4BgkqhkiG9w0BBwKgghfpMIIX5QIBAzEPMA0GCWCGSAFlAwQC
# AQUAMIIBYQYLKoZIhvcNAQkQAQSgggFQBIIBTDCCAUgCAQEGCisGAQQBhFkKAwEw
# MTANBglghkgBZQMEAgEFAAQgheprSQgRmjVr+xVwDTxlGeTcHHkp9E5XVevOCe4P
# go4CBmkF5BgsmxgSMjAyNTExMTMxOTEwMjQuNTJaMASAAgH0oIHhpIHeMIHbMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNy
# b3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBF
# U046N0QwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNB
# IFRpbWUgU3RhbXBpbmcgQXV0aG9yaXR5oIIPITCCB4IwggVqoAMCAQICEzMAAAAF
# 5c8P/2YuyYcAAAAAAAUwDQYJKoZIhvcNAQEMBQAwdzELMAkGA1UEBhMCVVMxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjFIMEYGA1UEAxM/TWljcm9zb2Z0
# IElkZW50aXR5IFZlcmlmaWNhdGlvbiBSb290IENlcnRpZmljYXRlIEF1dGhvcml0
# eSAyMDIwMB4XDTIwMTExOTIwMzIzMVoXDTM1MTExOTIwNDIzMVowYTELMAkGA1UE
# BhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
# TWljcm9zb2Z0IFB1YmxpYyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjAwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCefOdSY/3gxZ8FfWO1BiKjHB7X55cz
# 0RMFvWVGR3eRwV1wb3+yq0OXDEqhUhxqoNv6iYWKjkMcLhEFxvJAeNcLAyT+XdM5
# i2CgGPGcb95WJLiw7HzLiBKrxmDj1EQB/mG5eEiRBEp7dDGzxKCnTYocDOcRr9Kx
# qHydajmEkzXHOeRGwU+7qt8Md5l4bVZrXAhK+WSk5CihNQsWbzT1nRliVDwunuLk
# X1hyIWXIArCfrKM3+RHh+Sq5RZ8aYyik2r8HxT+l2hmRllBvE2Wok6IEaAJanHr2
# 4qoqFM9WLeBUSudz+qL51HwDYyIDPSQ3SeHtKog0ZubDk4hELQSxnfVYXdTGncaB
# nB60QrEuazvcob9n4yR65pUNBCF5qeA4QwYnilBkfnmeAjRN3LVuLr0g0FXkqfYd
# Umj1fFFhH8k8YBozrEaXnsSL3kdTD01X+4LfIWOuFzTzuoslBrBILfHNj8RfOxPg
# juwNvE6YzauXi4orp4Sm6tF245DaFOSYbWFK5ZgG6cUY2/bUq3g3bQAqZt65Kcae
# wEJ3ZyNEobv35Nf6xN6FrA6jF9447+NHvCjeWLCQZ3M8lgeCcnnhTFtyQX3XgCoc
# 6IRXvFOcPVrr3D9RPHCMS6Ckg8wggTrtIVnY8yjbvGOUsAdZbeXUIQAWMs0d3cRD
# v09SvwVRd61evQIDAQABo4ICGzCCAhcwDgYDVR0PAQH/BAQDAgGGMBAGCSsGAQQB
# gjcVAQQDAgEAMB0GA1UdDgQWBBRraSg6NS9IY0DPe9ivSek+2T3bITBUBgNVHSAE
# TTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMA8GA1UdEwEB/wQFMAMBAf8w
# HwYDVR0jBBgwFoAUyH7SaoUqG8oZmAQHJ89QEE9oqKIwgYQGA1UdHwR9MHsweaB3
# oHWGc2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29m
# dCUyMElkZW50aXR5JTIwVmVyaWZpY2F0aW9uJTIwUm9vdCUyMENlcnRpZmljYXRl
# JTIwQXV0aG9yaXR5JTIwMjAyMC5jcmwwgZQGCCsGAQUFBwEBBIGHMIGEMIGBBggr
# BgEFBQcwAoZ1aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9N
# aWNyb3NvZnQlMjBJZGVudGl0eSUyMFZlcmlmaWNhdGlvbiUyMFJvb3QlMjBDZXJ0
# aWZpY2F0ZSUyMEF1dGhvcml0eSUyMDIwMjAuY3J0MA0GCSqGSIb3DQEBDAUAA4IC
# AQBfiHbHfm21WhV150x4aPpO4dhEmSUVpbixNDmv6TvuIHv1xIs174bNGO/ilWMm
# +Jx5boAXrJxagRhHQtiFprSjMktTliL4sKZyt2i+SXncM23gRezzsoOiBhv14YSd
# 1Klnlkzvgs29XNjT+c8hIfPRe9rvVCMPiH7zPZcw5nNjthDQ+zD563I1nUJ6y59T
# bXWsuyUsqw7wXZoGzZwijWT5oc6GvD3HDokJY401uhnj3ubBhbkR83RbfMvmzdp3
# he2bvIUztSOuFzRqrLfEvsPkVHYnvH1wtYyrt5vShiKheGpXa2AWpsod4OJyT4/y
# 0dggWi8g/tgbhmQlZqDUf3UqUQsZaLdIu/XSjgoZqDjamzCPJtOLi2hBwL+KsCh0
# Nbwc21f5xvPSwym0Ukr4o5sCcMUcSy6TEP7uMV8RX0eH/4JLEpGyae6Ki8JYg5v4
# fsNGif1OXHJ2IWG+7zyjTDfkmQ1snFOTgyEX8qBpefQbF0fx6URrYiarjmBprwP6
# ZObwtZXJ23jK3Fg/9uqM3j0P01nzVygTppBabzxPAh/hHhhls6kwo3QLJ6No803j
# UsZcd4JQxiYHHc+Q/wAMcPUnYKv/q2O444LO1+n6j01z5mggCSlRwD9faBIySAcA
# 9S8h22hIAcRQqIGEjolCK9F6nK9ZyX4lhthsGHumaABdWzCCB5cwggV/oAMCAQIC
# EzMAAABV2d1pJij5+OIAAAAAAFUwDQYJKoZIhvcNAQEMBQAwYTELMAkGA1UEBhMC
# VVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWlj
# cm9zb2Z0IFB1YmxpYyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjAwHhcNMjUxMDIz
# MjA0NjQ5WhcNMjYxMDIyMjA0NjQ5WjCB2zELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0
# aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjdEMDAtMDVFMC1EOTQ3MTUw
# MwYDVQQDEyxNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lIFN0YW1waW5nIEF1dGhv
# cml0eTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL25H5IeWUiz9DAl
# Fmn2sPymaFWbvYkMfK+ScIWb3a1IvOlIwghUDjY0Gp6yMRhfYURiGS0GedIB6ywv
# uH6VBCX3+bdOFcAclgtv21jrpOjZmk4fSaT2Q3BszUfeUJa8o3xI7ZfoMY9dszTx
# HQAz6ZVX87fHGEVhQcfxW33IdPJOj/ae419qtYxT21MVmCfsTshgtWioQxmOW/vM
# C9/b+qgtBxSMf798vm3qfmhF6KCvFaHlivrM32hY16PGE3L0PFC+LM7vRxU7mTb+
# r76CeybvqOWk4+dbKYftPhV1t/E5S/6wwXeYmu/Y7JC7Tnh2w45G5Y4pcM3oHMb/
# YuPRdOWa0v+RC2QgmNVWqjuxDiylWscXQDuaMtb29AcdGUVV9ZsRY2M2sthAtOdZ
# OshiR5ufMtaHtiCkWv0jNfgUxrHurxzYuUNneWZ6EfQDgFAw8CSCKkSOK2c9jEop
# 4ddVq10xvbqxdrqMneVXvvIcXrPQAXj9j2ECpV2EwMb3Wnmpw00P78JpzPsk3Fs6
# 1ZvOGd/F1RcOBu6f2TWdp7HL7+rq7tgHr13MldbfIWu4lpoYYE1gTQa1Yrg5XN4j
# 7zs9klT2z3qocmPzV8DWQgIHNh+aTs7bujMEMQyI7Xt1zPxZCgcR6H0tmmzU/9Bx
# vsWbRalCQ2sYGyWupTdc4e7KY7kPAgMBAAGjggHLMIIBxzAdBgNVHQ4EFgQUVgRf
# EG3cCAPwyL+pyRbKwdesZbYwHwYDVR0jBBgwFoAUa2koOjUvSGNAz3vYr0npPtk9
# 2yEwbAYDVR0fBGUwYzBhoF+gXYZbaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jcmwvTWljcm9zb2Z0JTIwUHVibGljJTIwUlNBJTIwVGltZXN0YW1waW5n
# JTIwQ0ElMjAyMDIwLmNybDB5BggrBgEFBQcBAQRtMGswaQYIKwYBBQUHMAKGXWh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIw
# UHVibGljJTIwUlNBJTIwVGltZXN0YW1waW5nJTIwQ0ElMjAyMDIwLmNydDAMBgNV
# HRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIH
# gDBmBgNVHSAEXzBdMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0w
# CAYGZ4EMAQQCMA0GCSqGSIb3DQEBDAUAA4ICAQBSHuGSVHvalCnFnlsqXIQefH1x
# P2SFr9g+Vz+f5P7QeywjfQb5jUlSmd1XnJUDPe/MHxL7r3TEElL+mNtG6CDPAytS
# tSFPXD9tTBtBMYh8Wqo64pH9qm361yIqeBH979mzWCkMQsTd0nM6dUl9B+7qiti+
# ToXwxIl39eYqLuYYfhD2mqqePXMzUKSQzkf73yYIVHP6nLJQz4aAmaWcfG9jg78s
# BkDV8KpW7JgktuLhphJEN1B+SVHjenPdcmrFXIUu/K4jK5ukfWaQIjuaXzSjBlNj
# C5tQN6adPfA3GxUwHPeR4ekL5If/9vBf13tmzBW+gy+0sNGTveb9IL9GU8iX8Uvy
# wsX62nhCCPRUhTigDBKdczRUrNrntBhowbfchBDFML8avRMRc9Gmc2JvIryX336S
# FQ51//q1UU2HMSJEMhWLJSIWJVhfUowsOa+PampIzETYfFvTu2mqKJUlWZXkGYxr
# dCvCczJcqeoadpW1ul6kcdnDh228SQ8ZhDc6IRlM4iNd5SNoNgX+aom3wuGyjUaS
# aPZWxPB1G2NKiYhPLt0lPHg0Gskj1zhISY8UQkMMDr3o2JgRuT+wnJEDQUp55ddv
# hSkSoD6I9DL/s+TjIY/c9jLaW5xywJHqdKHUApRMsghv7kebSua1upmR+TquelFk
# tDSOjVdSRkuya4uoxTGCB0Mwggc/AgEBMHgwYTELMAkGA1UEBhMCVVMxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1
# YmxpYyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjACEzMAAABV2d1pJij5+OIAAAAA
# AFUwDQYJYIZIAWUDBAIBBQCgggScMBEGCyqGSIb3DQEJEAIPMQIFADAaBgkqhkiG
# 9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI1MTExMzE5MTAy
# NFowLwYJKoZIhvcNAQkEMSIEIHl6Nb1WVv5mgPUCdqYEaqMsZwkB+C4V7UgKp5/6
# 1HKWMIG5BgsqhkiG9w0BCRACLzGBqTCBpjCBozCBoAQg2Lk8l2SGYru/ff7+D2qr
# JnkswcYdK6pGKu7GGGr4/s0wfDBlpGMwYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1Ymxp
# YyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjACEzMAAABV2d1pJij5+OIAAAAAAFUw
# ggNeBgsqhkiG9w0BCRACEjGCA00wggNJoYIDRTCCA0EwggIpAgEBMIIBCaGB4aSB
# 3jCB2zELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UE
# CxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVs
# ZCBUU1MgRVNOOjdEMDAtMDVFMC1EOTQ3MTUwMwYDVQQDEyxNaWNyb3NvZnQgUHVi
# bGljIFJTQSBUaW1lIFN0YW1waW5nIEF1dGhvcml0eaIjCgEBMAcGBSsOAwIaAxUA
# HTtUAYJlv7bgWVeRBo4X7FeHDeqgZzBlpGMwYTELMAkGA1UEBhMCVVMxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1
# YmxpYyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjAwDQYJKoZIhvcNAQELBQACBQDs
# wDSDMCIYDzIwMjUxMTEzMTA0MjExWhgPMjAyNTExMTQxMDQyMTFaMHQwOgYKKwYB
# BAGEWQoEATEsMCowCgIFAOzANIMCAQAwBwIBAAICLsYwBwIBAAICEzkwCgIFAOzB
# hgMCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAweh
# IKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEATahP/WAAwIuPQqtaPuk7
# 65ezBGuoXq1WO3kbIhCxs5NNNJpCC8lVbWnbHDBciwQnrECN9U+MbeNnw0bTuizE
# TpA1qkhIdTuPe/HYU7cFnPG4xxGjwVo8M8415soRTQsiBMz4Pve4snCU3vQYaK+I
# eeUGhpbzkkjMIY3B2PEnvXM/pFISNnRuTGwxl5pagEJ9a4C0s8s3fSwlDXe3pTne
# 3Bj84Bb+RnUcNI/Jzy+LUfqETVKbz2pEhDuV8I6NJYxsVDucl5eenCZYexPvstrS
# QrnSxxpuk5BoVsQi5s30S3dPYLgH6CemsHZ7eiokF94HwplZNNKJtIHM9V43kcZL
# tjANBgkqhkiG9w0BAQEFAASCAgC7TlQF7wy4m1LS8k8DgWMAfKbRNKvA3s3D/EYy
# T568oHud9DpZaVXZ//4X/cqns2mTGD/CJK88dFmRSSbjAwOtSx8BrFmf3Rtw3Wab
# yitCQvW/j9XfMJfsVyE/I0K36toAccUPuIHL+rSbTg9luahyreihKbPKJxE271Fg
# +RXqDpkZiwLa2cpUDqYcqn//KG+HqL+8+c61FyVxHMhwcf//hKqd9abAUVcOTfRW
# cVD4IAKn1lFcYUNJnEjbLDoqYRRZ4VCo/H+oT+nNwO6aL0feBucnrQJgtC18+vYI
# H4/y58d9ghSlKM2nkG6qmg30t/HqfyhWpuiTRRBJwtmafs/CjgTd10JBosz8DoNe
# NFKX5EZNVa9CdrVC9gPlhLh5eemZKP3d1WAxywsbR9tx/eWUd0v6xoBAVFCxq/Bz
# nlbBy/uNIXkhA5gwuc2ztaLJIAxHEpRQxZSSqTyYGLzOtYeOhRuVxioupRdaI+CC
# fbUb4nK6js8PSTtpM/G7aBhl69+xT6AOavEX3AYqcSACKVPayniKMk/CDYoEIzqG
# DSAbR632DVPqCPw2agiGTkeGiwijrKu6MaxO6AP5rHgQFU+tOuyO1w+rftmwfiY3
# hNEVdQaQ8pUXsiszbgy8Rl7F7BhSUWra/SOB/uKp5b0nu7UEhNPXO5X9F+FdAibE
# xSkFYA==
# SIG # End signature block
