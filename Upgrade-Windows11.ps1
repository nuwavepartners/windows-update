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
Version:        1.2.16
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
	[switch]$SkipReadinessCheck
)


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
			return 11
		} elseif ($installedOs -imatch "Windows 7") {
			# Write-Output "$("-"*18)`nStatus : Unsupported`n$("-"*18)`nDetails`n$("-"*10)"
			# Write-Output "Installed OS: '$($installedOs)' not Supported :: $FAIL_STRING"
			# exit 1
			return 12
		}
	} catch {
		# Write-Output "$("-"*18)`nStatus : Unsupported`n$("-"*18)`nDetails`n$("-"*10)"
		# Write-Output "Unexpected Error Occurred: $($_.Exception.Message)"
		# exit 1
		return 13
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

	return $outObject.returnCode

}

#=============================================================================================================================
# MAIN FUNCTION: Upgrade-Windows11
#=============================================================================================================================

Write-Host "Starting Windows 11 Upgrade Orchestration..." -ForegroundColor Cyan

# === 1. PREREQUISITES ===
# 1a. Check for Administrative Privileges
Write-Host "[1/6] Checking for Administrator privileges..."
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
	Write-Error "This script must be run as Administrator. Please re-launch from an elevated PowerShell prompt."
	return # Stop execution
}
Write-Host "  [PASS] Running as Administrator."

# 1b. Create Log Directory
$UpgradeLogDir = 'C:\Temp\UpgradeLog'
Write-Host "[2/6] Ensuring log directory exists at $UpgradeLogDir..."
try {
	if (-not (Test-Path -Path $UpgradeLogDir -PathType Container)) {
		New-Item -Path $UpgradeLogDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
		Write-Host "  [PASS] Created log directory."
	} else {
		Write-Host "  [PASS] Log directory already exists."
	}
} catch {
	Write-Error "Failed to create log directory at $UpgradeLogDir. Error: $($_.Exception.Message)"
	return
}

# 1c. Check for readiness
Write-Host "[3/6] Running Windows 11 readiness check..."
if (-not $SkipReadinessCheck.IsPresent) {
	try {
		$readinessCode = Test-Win11Readiness -ErrorAction Stop
		if ($readinessCode -ne 0) {
			Write-Error "Hardware readiness check failed with code $readinessCode. Machine is not ready for upgrade."
			exit $readinessCode
  		}
	} catch {
		Write-Error "The readiness check function (Test-Win11Readiness) failed to run. Error: $($_.Exception.Message)"
		return
	}
} else {
	Write-Host "  [SKIP] -SkipReadinessCheck was specified. Skipping hardware readiness check." -ForegroundColor Yellow
}

# === 2. PREPARATION ===
$downloadUrl = 'https://go.microsoft.com/fwlink/?linkid=2171764'
$installerName = $null

# 2a. Resolve final filename
Write-Host "[4/6] Resolving download filename from $downloadUrl..."
try {
	$installerName = Resolve-UrlFinalFileName -Url $downloadUrl -ErrorAction Stop
	if (-not $installerName) {
		Write-Error "Could not resolve the installer filename from the URL."
		return
	}
	$localInstallerPath = Join-Path -Path ([System.Environment]::GetEnvironmentVariable('TEMP', 'Machine')) -ChildPath $installerName
	Write-Host "  [PASS] Resolved filename: $installerName. Target path: $localInstallerPath"
} catch {
	Write-Error "The filename resolver function (Resolve-UrlFinalFileName) failed. Error: $($_.Exception.Message)"
	return
}

# 2b. Download the file
Write-Host "[5/6] Downloading $installerName..."
$webClient = $null
try {
	# Use System.Net.WebClient for PowerShell 5.x compatibility
	$webClient = New-Object System.Net.WebClient
	$webClient.DownloadFile($downloadUrl, $localInstallerPath)
	Write-Host "  [PASS] Download complete."
} catch {
	Write-Error "Failed to download file. Error: $($_.Exception.Message)"
	return
} finally {
	if ($webClient) { $webClient.Dispose() }
}

# 2c. Set file permissions
Write-Host "  Setting 'ReadAndExecute' permissions for 'Everyone' on '$localInstallerPath'..."
try {
	$acl = Get-Acl -Path $localInstallerPath
	$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('Everyone', 'ReadAndExecute', 'Allow')
	$acl.AddAccessRule($rule)
	Set-Acl -Path $localInstallerPath -AclObject $acl -ErrorAction Stop
	Write-Host "  Permissions set successfully." -ForegroundColor Green
} catch {
	# Non-fatal error. Warn the user and continue.
	Write-Warning "  Could not set file permissions. The script will still attempt to run the installer. Error: $($_.Exception.Message)"
}

# === 3. EXECUTION / SHORTCUT CREATION ===
Write-Host "[6/6] Processing execution step..."

# Define arguments
$arguments = "/Install /MinimizeToTaskBar /NoRestartUI /QuietInstall /SkipEULA /copylogs $UpgradeLogDir"

Write-Host "  Installer: $localInstallerPath"
Write-Host "  Arguments: $arguments"

if ($UpgradeNow.IsPresent) {
	Write-Host "  Action: -UpgradeNow specified. Starting Windows 11 Installation Assistant (Quiet Mode)..."
	try {
		$process = Start-Process -FilePath $localInstallerPath -ArgumentList $arguments -Wait -PassThru -ErrorAction Stop

		Write-Host "  [PASS] Upgrade process finished with Exit Code: $($process.ExitCode)."

		if ($process.ExitCode -ne 0) {
			Write-Warning "The installer exited with a non-zero code. Check logs in $UpgradeLogDir for details."
		} else {
			Write-Host "Upgrade process completed successfully. A restart will be required." -ForegroundColor Green
		}
	} catch {
		Write-Error "Failed to start the installer process. Error: $($_.Exception.Message)"
		return
	}
} else {
	Write-Host "  Action: -UpgradeNow not specified. Creating desktop shortcut..."
	$shortcutPath = 'C:\Users\Public\Desktop\Upgrade Windows.lnk'
	try {
		# Use WScript.Shell to create the shortcut
		$shell = New-Object -ComObject WScript.Shell
		$shortcut = $shell.CreateShortcut($shortcutPath)
		$shortcut.TargetPath = $localInstallerPath
		$shortcut.Arguments = $arguments
		$shortcut.Description = "Start the Windows 11 Upgrade"
		# Use the installer's own icon (index 0)
		$shortcut.IconLocation = "$localInstallerPath,0"
		$shortcut.WorkingDirectory = [System.IO.Path]::GetDirectoryName($localInstallerPath)
		$shortcut.Save()

		Write-Host "  [PASS] Successfully created shortcut at $shortcutPath."
		Write-Host "The script has downloaded the installer and created a public desktop shortcut." -ForegroundColor Green
		Write-Host "Run the 'Upgrade Windows' shortcut to begin the upgrade."
	} catch {
		Write-Error "Failed to create shortcut. Error: $($_.Exception.Message)"
		return
	}
}

Write-Host "Windows 11 Upgrade Orchestration Finished." -ForegroundColor Cyan


# SIG # Begin signature block
# MII+EwYJKoZIhvcNAQcCoII+BDCCPgACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDnXlCl5TzuNBGK
# 33rer0oMbQq8CMJ+9H0dPShZ9qy1IaCCItYwggXMMIIDtKADAgECAhBUmNLR1FsZ
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
# 03u4aUoqlmZpxJTG9F9urJh4iIAGXKKy7aIwggb/MIIE56ADAgECAhMzAAYAmvlb
# /or4eroCAAAABgCaMA0GCSqGSIb3DQEBDAUAMFoxCzAJBgNVBAYTAlVTMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJ
# RCBWZXJpZmllZCBDUyBBT0MgQ0EgMDEwHhcNMjUxMDMwMDExNjU4WhcNMjUxMTAy
# MDExNjU4WjB+MQswCQYDVQQGEwJVUzERMA8GA1UECBMITWljaGlnYW4xEjAQBgNV
# BAcTCUthbGFtYXpvbzEjMCEGA1UEChMaTnVXYXZlIFRlY2hub2xvZ3kgUGFydG5l
# cnMxIzAhBgNVBAMTGk51V2F2ZSBUZWNobm9sb2d5IFBhcnRuZXJzMIIBojANBgkq
# hkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAiN/JQlUpT6i3WI9kK9osydwf4pJRhvDh
# ehSNJ/HNvfEVYtxrh9HTsRBIBRoqPJu9RjY7Nn/CNmlZBF9u9XdOjROONWaqO9HJ
# D6exMyPAOj/RP5DRVAfBkD/ZlEvMTXZTaYMM3ZYeW6dsw6oSm+S3Y6eVkNyJ+4Wy
# ZR1OrhoqMxF861IdMfDEv3R8/cFxdsrKrg9nkdEmm12w1R5Jg9Q95kLVOPR88u/w
# Ki2fPdUwPWbIGXQ0DwKAX/XS11uV4xD6m1a99JVKMNS53A3Eie4a3mGOOoZ4B5ts
# gsr0KUM43cKWAhcQ31Fy5swZYfeoYMuSiWvaNgHFOe17HZUGYRHy1LTD4UAz5CDI
# mLW4lR30M+Sh9zeJcB8BfF9K8BGAcivw8PZOCjW6omlqcXVRtAbGt+fMybnoLbut
# a+QvOzOGquFSw5aHFQ/5erTxXccGP07RWajSFHiQedaHshhabiQCLwcW5pY4mcEO
# KhYe27wzFYjB7MO7AU3MweQOZ165oYZxAgMBAAGjggIYMIICFDAMBgNVHRMBAf8E
# AjAAMA4GA1UdDwEB/wQEAwIHgDA7BgNVHSUENDAyBgorBgEEAYI3YQEABggrBgEF
# BQcDAwYaKwYBBAGCN2HukfNMg8bbxHSBjNbafbipvhswHQYDVR0OBBYEFGdcePHG
# 9zDx3qGWwFWGcaLOMXjcMB8GA1UdIwQYMBaAFOiDxDPX3J8MnHaaCqbU34emXlju
# MGcGA1UdHwRgMF4wXKBaoFiGVmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvY3JsL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDUyUyMEFPQyUyMENB
# JTIwMDEuY3JsMIGlBggrBgEFBQcBAQSBmDCBlTBkBggrBgEFBQcwAoZYaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBJRCUy
# MFZlcmlmaWVkJTIwQ1MlMjBBT0MlMjBDQSUyMDAxLmNydDAtBggrBgEFBQcwAYYh
# aHR0cDovL29uZW9jc3AubWljcm9zb2Z0LmNvbS9vY3NwMGYGA1UdIARfMF0wUQYM
# KwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAIBgZngQwBBAEwDQYJKoZI
# hvcNAQEMBQADggIBAEGnbRfDNWRV7McKOz6AeEo+YKpnfjcO1KcdbTLLdy0rvc1B
# yOPsELAAJqqAdQ8bS+xj3gxTHSqyRdFaZ29ZSUndeLqIxozmIsroYZk4nCBpkYLD
# nCRFPCF92yVKdCGBVNGeed5aGERB8K9cEEG3LYAgRtSbGJfGDxfGFEWHH6Afcoeb
# o5rTlw/wsfgQ+LGs6XFcVRypwok2F0mm5xLlVSzJ9CDxykLhZsKFYYvz07jSI5ge
# BWMsA+sAO14MVsWlLEOlebmXhwmJiA+3PwEV3Y1nrcMIXoSHCcqazWi7EJbLyqvz
# JOhYyGOocYAoMSamDK4ju12HVoYo8X4vL6AQZFuDT/KJEUYMUGwI+53vFqljZ+mK
# KVZYiX+MLUS+dRPIihyCoBS9XfFG1whH+Ix8R6GRcly2bLGSy/fJq6eIiYozoZQ3
# 8PAjVNg4cySajFckHMfHT/Mz3zH8AjX5PBALY8JsMENq83SeuJCi6+ztVYmr+MQu
# YmfdhJk5C3LIGsrOlxW5FNPO3wD/Eopj2abVuFtZd4vWhDR5razwXUD6mAze8UUu
# L3TpFHm/xC4A3NCDKW7tDGYYNxDjHLVupu032IUbKqavi+3o1aiZYPkniZS9LWGd
# VSYQNjt3azHd3On3b9yiEEf8NjjBCO3vjHaB/rA89f5D4k2CN+5jqMDEHBkPMIIG
# /zCCBOegAwIBAgITMwAGAJr5W/6K+Hq6AgAAAAYAmjANBgkqhkiG9w0BAQwFADBa
# MQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSsw
# KQYDVQQDEyJNaWNyb3NvZnQgSUQgVmVyaWZpZWQgQ1MgQU9DIENBIDAxMB4XDTI1
# MTAzMDAxMTY1OFoXDTI1MTEwMjAxMTY1OFowfjELMAkGA1UEBhMCVVMxETAPBgNV
# BAgTCE1pY2hpZ2FuMRIwEAYDVQQHEwlLYWxhbWF6b28xIzAhBgNVBAoTGk51V2F2
# ZSBUZWNobm9sb2d5IFBhcnRuZXJzMSMwIQYDVQQDExpOdVdhdmUgVGVjaG5vbG9n
# eSBQYXJ0bmVyczCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAIjfyUJV
# KU+ot1iPZCvaLMncH+KSUYbw4XoUjSfxzb3xFWLca4fR07EQSAUaKjybvUY2OzZ/
# wjZpWQRfbvV3To0TjjVmqjvRyQ+nsTMjwDo/0T+Q0VQHwZA/2ZRLzE12U2mDDN2W
# HlunbMOqEpvkt2OnlZDcifuFsmUdTq4aKjMRfOtSHTHwxL90fP3BcXbKyq4PZ5HR
# JptdsNUeSYPUPeZC1Tj0fPLv8Cotnz3VMD1myBl0NA8CgF/10tdbleMQ+ptWvfSV
# SjDUudwNxInuGt5hjjqGeAebbILK9ClDON3ClgIXEN9RcubMGWH3qGDLkolr2jYB
# xTntex2VBmER8tS0w+FAM+QgyJi1uJUd9DPkofc3iXAfAXxfSvARgHIr8PD2Tgo1
# uqJpanF1UbQGxrfnzMm56C27rWvkLzszhqrhUsOWhxUP+Xq08V3HBj9O0Vmo0hR4
# kHnWh7IYWm4kAi8HFuaWOJnBDioWHtu8MxWIwezDuwFNzMHkDmdeuaGGcQIDAQAB
# o4ICGDCCAhQwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwOwYDVR0lBDQw
# MgYKKwYBBAGCN2EBAAYIKwYBBQUHAwMGGisGAQQBgjdh7pHzTIPG28R0gYzW2n24
# qb4bMB0GA1UdDgQWBBRnXHjxxvcw8d6hlsBVhnGizjF43DAfBgNVHSMEGDAWgBTo
# g8Qz19yfDJx2mgqm1N+Hpl5Y7jBnBgNVHR8EYDBeMFygWqBYhlZodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBJRCUyMFZlcmlm
# aWVkJTIwQ1MlMjBBT0MlMjBDQSUyMDAxLmNybDCBpQYIKwYBBQUHAQEEgZgwgZUw
# ZAYIKwYBBQUHMAKGWGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2Vy
# dHMvTWljcm9zb2Z0JTIwSUQlMjBWZXJpZmllZCUyMENTJTIwQU9DJTIwQ0ElMjAw
# MS5jcnQwLQYIKwYBBQUHMAGGIWh0dHA6Ly9vbmVvY3NwLm1pY3Jvc29mdC5jb20v
# b2NzcDBmBgNVHSAEXzBdMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNo
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5o
# dG0wCAYGZ4EMAQQBMA0GCSqGSIb3DQEBDAUAA4ICAQBBp20XwzVkVezHCjs+gHhK
# PmCqZ343DtSnHW0yy3ctK73NQcjj7BCwACaqgHUPG0vsY94MUx0qskXRWmdvWUlJ
# 3Xi6iMaM5iLK6GGZOJwgaZGCw5wkRTwhfdslSnQhgVTRnnneWhhEQfCvXBBBty2A
# IEbUmxiXxg8XxhRFhx+gH3KHm6Oa05cP8LH4EPixrOlxXFUcqcKJNhdJpucS5VUs
# yfQg8cpC4WbChWGL89O40iOYHgVjLAPrADteDFbFpSxDpXm5l4cJiYgPtz8BFd2N
# Z63DCF6EhwnKms1ouxCWy8qr8yToWMhjqHGAKDEmpgyuI7tdh1aGKPF+Ly+gEGRb
# g0/yiRFGDFBsCPud7xapY2fpiilWWIl/jC1EvnUTyIocgqAUvV3xRtcIR/iMfEeh
# kXJctmyxksv3yauniImKM6GUN/DwI1TYOHMkmoxXJBzHx0/zM98x/AI1+TwQC2PC
# bDBDavN0nriQouvs7VWJq/jELmJn3YSZOQtyyBrKzpcVuRTTzt8A/xKKY9mm1bhb
# WXeL1oQ0ea2s8F1A+pgM3vFFLi906RR5v8QuANzQgylu7QxmGDcQ4xy1bqbtN9iF
# Gyqmr4vt6NWomWD5J4mUvS1hnVUmEDY7d2sx3dzp92/cohBH/DY4wQjt74x2gf6w
# PPX+Q+JNgjfuY6jAxBwZDzCCB1owggVCoAMCAQICEzMAAAAHN4xbodlbjNQAAAAA
# AAcwDQYJKoZIhvcNAQEMBQAwYzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjE0MDIGA1UEAxMrTWljcm9zb2Z0IElEIFZlcmlmaWVk
# IENvZGUgU2lnbmluZyBQQ0EgMjAyMTAeFw0yMTA0MTMxNzMxNTRaFw0yNjA0MTMx
# NzMxNTRaMFoxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKzApBgNVBAMTIk1pY3Jvc29mdCBJRCBWZXJpZmllZCBDUyBBT0MgQ0Eg
# MDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC398ADKAfFuj6PEDTi
# E0jxvP4Spta9K711GABrCMJlq7VjnghBqXkCuklaLxwiPRYD6anCLHyJNGC6r0kQ
# tm9MyjZnVToC0TVOfea+rebLBn1J7FV36s85Ov651roZWDAsDzQuFF/zYC+tLDGZ
# mkIf+VpPTx2fv4a3RxdhU0ok5GbWFKsCOMNCJnUmKr9KqIOgc3o8aZPmFcqzbYTv
# 0x4VZgHjLRSU2pbRnYs825ryTStsRF2I1L6dM//GwRJlSetubJdloe9zIQpgrzlY
# HPdKvoS3xWVt2J3+mMGlwcj4fK2hpQAYTqtJaqaHv9oRl4MNSTP24wo4ZqwiBid6
# dSTkTRvZT/9tCoO/ep2GP1QlhYAM1gL/eLeLFxbVUQtpT7BOpdPEsAV6UKL+VEdK
# NpaKkN4T9NsFvTNMKIudz2eY6Nk8qW60w2Gj3XDGjiK1wmgiTZs+i3234BX5TA1o
# NEhtwRpBoHJyX2lxjBaZ/RsnggWf8KZgxUbV6QIHEHLJE2QWQea4xctfo8xdy94T
# jqMyv2zILczwkdF11HjNWN38XEGdLkc6ujemDpK24Q+yGunsj8qTVxMbzI5aXxqp
# /o4l4BXIbiXIn1X5nEKViZpTnK+0pgqTUUsGcQF8NbD5QDNBXS9wunoBXHYVzyfS
# +mjK52vdLBmZyQm7PtH5Lv0HMwIDAQABo4ICDjCCAgowDgYDVR0PAQH/BAQDAgGG
# MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTog8Qz19yfDJx2mgqm1N+Hpl5Y
# 7jBUBgNVHSAETTBLMEkGBFUdIAAwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgw
# FoAU2UEpsA8PY2zvadf1zSmepEhqMOYwcAYDVR0fBGkwZzBloGOgYYZfaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwSUQlMjBW
# ZXJpZmllZCUyMENvZGUlMjBTaWduaW5nJTIwUENBJTIwMjAyMS5jcmwwga4GCCsG
# AQUFBwEBBIGhMIGeMG0GCCsGAQUFBzAChmFodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMElEJTIwVmVyaWZpZWQlMjBDb2Rl
# JTIwU2lnbmluZyUyMFBDQSUyMDIwMjEuY3J0MC0GCCsGAQUFBzABhiFodHRwOi8v
# b25lb2NzcC5taWNyb3NvZnQuY29tL29jc3AwDQYJKoZIhvcNAQEMBQADggIBAHf+
# 60si2TAtOng1+H32+tulKwvw3A8iPb5MGdkYvcLx61MZiz4dlTE0b6s15lr5HO72
# gRwBkkOIaMRbK3Mxq8PoGKHecRYWwhbhoaHiAHif+lE955WsriLUsbuMneQ8tGE0
# 4dmItRC2asXhXojG1QWO8GeKNpn2gjGxJJA/yIcyM/3amNCscEVYcYNuSbH7I7oh
# qfdA3diZt197DNK+dCYpuSJOJsmBwnUvRNnsHCawO+b7RdGw858WCfOEtWpl0TJb
# DDXRt+U54EqqRvdJoI1BPPyeyFpRmGvFVTmo2BiNpoNBCb4/ZISkEXtGiUQLeWWV
# +4vgA4YK2g1085avH28FlNcBV1MTavQgOTz7nLWQsZMsrOY0WfqRUJzkF10zvGgN
# ZDhpSgJFdywF5GGxyWTuRVc/7MkY85fCNQlufPYq32IX/wHoUM7huUa4auiAynJe
# S7AILZnhdx/IyM8OGplgA8YZNQg0y0Vtq7lG0YbUM5YT150JqG248wOAHJ8+LG+H
# LeyfvNQeAgL9iw5MzFW4xCL9uBqZ6aj9U0pmuxlpLSfOY7EqmD2oN5+Pl8n2Agdd
# ynYXQ4dxXB7cqcRdrySrMwN+tGX/DAqs1IWfenuDRvjgB3U40OZa3rUwtC8Xngsb
# raLp9+FMJ6gVP1n2ltSjaDGXJMWDsGbR+A6WdF8YMIIHnjCCBYagAwIBAgITMwAA
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
# nTiOL60cPqfny+Fq8UiuZzGCGpMwghqPAgEBMHEwWjELMAkGA1UEBhMCVVMxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjErMCkGA1UEAxMiTWljcm9zb2Z0
# IElEIFZlcmlmaWVkIENTIEFPQyBDQSAwMQITMwAGAJr5W/6K+Hq6AgAAAAYAmjAN
# BglghkgBZQMEAgEFAKBeMBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEM
# BgorBgEEAYI3AgEEMC8GCSqGSIb3DQEJBDEiBCDGxh9EWjlOhqQyepVA5Va2hJbe
# ZpU8dvm6uSPrMMEPMjANBgkqhkiG9w0BAQEFAASCAYAjraQBZDbUDIYMhnR2qMKS
# irLvD0qeOTkDx98N3NEKzkZBnqojxoGIU/jDctLQp5c+AxT+jbsNMUEiWzl16T74
# mxbyUw4fVOPqGW4EoMtcRO2KeIZJslte6xUY9WPjWOa0UGVOviz6f9g/whCNPFF2
# 3qWRc/7ZauHouUhJTB9FFDptjUXOtqiJqsEhMD477mXCgUByv9CXAHP+wxguJTuG
# K71X8a34PQK074jbEEBfw+4C4+kuQOAm6UyUB+s7PHoh3Wg+6bjyr8y2Z8kBf7OQ
# 39nYoMNA+Nmo26rG6Bp6TcBqVomQVuRNHvTdsYaiT73blmF35cFzSi9QDSNQZ2dP
# ktmxJxJUmYU56+6AjEpSX2V+21FJ0MZF1BvSZ5vn07ig8+3hNQVbCb+IaxMdQzqq
# 9a7DGp0TuOMWuL9Em2VxnfK2YsmH2xAf0zKOrxTvGokwf9BKeFGI3uLL5VUOx5NN
# shIhhNJ41fksUC7eRZ1nrYpK1FueAyBtQrdg5zI2KXyhghgTMIIYDwYKKwYBBAGC
# NwMDATGCF/8wghf7BgkqhkiG9w0BBwKgghfsMIIX6AIBAzEPMA0GCWCGSAFlAwQC
# AQUAMIIBYQYLKoZIhvcNAQkQAQSgggFQBIIBTDCCAUgCAQEGCisGAQQBhFkKAwEw
# MTANBglghkgBZQMEAgEFAAQgfV53uKozby8rEGKOsiQyH5j3QBLQby/Pv5NOHlrq
# 6jUCBmkBFLGK0RgSMjAyNTEwMzAxNTIyMDkuNzZaMASAAgH0oIHhpIHeMIHbMQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNy
# b3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hpZWxkIFRTUyBF
# U046NzgwMC0wNUUwLUQ5NDcxNTAzBgNVBAMTLE1pY3Jvc29mdCBQdWJsaWMgUlNB
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
# EzMAAABXJNOV4KLpyTEAAAAAAFcwDQYJKoZIhvcNAQEMBQAwYTELMAkGA1UEBhMC
# VVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWlj
# cm9zb2Z0IFB1YmxpYyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjAwHhcNMjUxMDIz
# MjA0NjUzWhcNMjYxMDIyMjA0NjUzWjCB2zELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0
# aW9uczEnMCUGA1UECxMeblNoaWVsZCBUU1MgRVNOOjc4MDAtMDVFMC1EOTQ3MTUw
# MwYDVQQDEyxNaWNyb3NvZnQgUHVibGljIFJTQSBUaW1lIFN0YW1waW5nIEF1dGhv
# cml0eTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALFspQqTCH24syS2
# NZD1ztnJl9h0Vr0WwJnikmeXse/4wspnVexGqfiHNoqkbVg5CinuYC+iVfNMLZ+Q
# tqhySz8VGBSjRt1JB5ACNtTKAjfmFp4U/Cv2Lj4m+vuve9I3W3hSiImTFsHeYZ6V
# /Sd43rXrhHV26fw3xQSteSbg9yTs1rhdrLkAj4KmI0D5P4KavtygirVyUW10gkif
# WLSE1NiB8Jn3RO5dj32deeMNONaaPnw3k49ICTs3Ffyb+ekNDPsNfYwCqPyOTxM6
# y1dSD0J5j+KK9V+EWyV5PDjV8jjn1zsStlS6TcYJJStcgHs2xT9rs6ooWl5FtYfR
# kCxhDShEp3s8IHUWizTWmLZvAE/6WR2Cd+ZmVapGXTCHJKUByZPxdX0i8gynirR+
# EwuHHNxEilDICLatO2WZu+CQrH4Zq0NYo1TQ4tUpZ/kAWpoAu1r4mW5EJ3HkEavQ
# 2PuoQDcDq2rAGVIla9pD7o9Yxwzl81BuDvUEyu9D/6F0qmQDdaE791HxfCUxpgMY
# PpdWTzs+dDGPehwQ8P92yP8ARjby5Ony1Z68RjeQebpxf5WL441myFHcgT1UJzzi
# l7tPEkR22NfTNR6Fl+jzWb/r80nqlXllhynSowtxo1Y22xqYviS24smikUsBKqOP
# bSS77uvXEO3VrG5LGouE1EZ1Y9pjAgMBAAGjggHLMIIBxzAdBgNVHQ4EFgQUjoPJ
# Xi01DgIJSGfm416Yg+0SkqcwHwYDVR0jBBgwFoAUa2koOjUvSGNAz3vYr0npPtk9
# 2yEwbAYDVR0fBGUwYzBhoF+gXYZbaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aW9wcy9jcmwvTWljcm9zb2Z0JTIwUHVibGljJTIwUlNBJTIwVGltZXN0YW1waW5n
# JTIwQ0ElMjAyMDIwLmNybDB5BggrBgEFBQcBAQRtMGswaQYIKwYBBQUHMAKGXWh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIw
# UHVibGljJTIwUlNBJTIwVGltZXN0YW1waW5nJTIwQ0ElMjAyMDIwLmNydDAMBgNV
# HRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4GA1UdDwEB/wQEAwIH
# gDBmBgNVHSAEXzBdMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0w
# CAYGZ4EMAQQCMA0GCSqGSIb3DQEBDAUAA4ICAQBydcB2POmZOUlAQz2NuXf7vWCV
# WmjWu9bsY1+HMjv1yeLjxDQkjsJEU5zaIDy8Uw9BYN8+ExX/9k/9CBUsXbVlbU44
# c65/liyJ83kWsFIUwhVazwSShFlbIZviIO/5weyWyTfPPpbSJgWy+ZE9UrQS3xul
# JLAHA2zUkMMPdAlF4RrngcZZ0r45AF9aIYjdestWwdrNK70MfArHqZdgrgXn03w6
# zBs1v7czceWGitg/DlsHqk1mXBpSTuGI2TSPN3E60IIXx5f/AFzh4/HFi98BBZbU
# ELNsXkWAG9ynZ5e6CFiil1mgWCWOT90D7Igvg0zKe3o3WCk629/en94K/sC/zLOf
# 2d7yFmTySb9fKjcONH1Db3kZ8MzEJ8fHTNmxrl10Gecuz/Gl0+ByTKN+PambZ+F0
# MIlBPww6fvjFC9JII73fw3qO169+9TxTz2G+E26GYY1dcffsAhw6DqTQgbflbl1O
# /MrSXSs0NSb9nBD9RfR/f8Ei7DA1L1jBO7vZhhJTjw2TzFa/ALgRLi3W00hHWi8L
# GQaZc8SwXIMYWfwrN9MgYbhN0Iak9WA2dqWuekXsTwNkmrD3E6E+oCYCehNOgZmd
# s0Ezb1jo7OV0Kh22Ll3KHg3MHtlGguxAzhg/BpixPS4qrULLkAjO7+yNsUfrD2U9
# gMf/OR4yJDPtzM0ytTGCB0YwggdCAgEBMHgwYTELMAkGA1UEBhMCVVMxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1
# YmxpYyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjACEzMAAABXJNOV4KLpyTEAAAAA
# AFcwDQYJYIZIAWUDBAIBBQCgggSfMBEGCyqGSIb3DQEJEAIPMQIFADAaBgkqhkiG
# 9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI1MTAzMDE1MjIw
# OVowLwYJKoZIhvcNAQkEMSIEIP3TkFiF14WXAnX32XcT6ImksNiXUmWehE5cFrfc
# SIh6MIG5BgsqhkiG9w0BCRACLzGBqTCBpjCBozCBoAQg9TyfZLUFbkxliGyizuH9
# VVDpVFNvQEQhKQ2ZhUx421IwfDBlpGMwYTELMAkGA1UEBhMCVVMxHjAcBgNVBAoT
# FU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1Ymxp
# YyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjACEzMAAABXJNOV4KLpyTEAAAAAAFcw
# ggNhBgsqhkiG9w0BCRACEjGCA1AwggNMoYIDSDCCA0QwggIsAgEBMIIBCaGB4aSB
# 3jCB2zELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UE
# CxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVs
# ZCBUU1MgRVNOOjc4MDAtMDVFMC1EOTQ3MTUwMwYDVQQDEyxNaWNyb3NvZnQgUHVi
# bGljIFJTQSBUaW1lIFN0YW1waW5nIEF1dGhvcml0eaIjCgEBMAcGBSsOAwIaAxUA
# /S8xOZxCUQFBNkrN8Wiij1x5y8OgZzBlpGMwYTELMAkGA1UEBhMCVVMxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFB1
# YmxpYyBSU0EgVGltZXN0YW1waW5nIENBIDIwMjAwDQYJKoZIhvcNAQELBQACBQDs
# rY1yMCIYDzIwMjUxMDMwMDcwODM0WhgPMjAyNTEwMzEwNzA4MzRaMHcwPQYKKwYB
# BAGEWQoEATEvMC0wCgIFAOytjXICAQAwCgIBAAICAjMCAf8wBwIBAAICEj4wCgIF
# AOyu3vICAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQAC
# AwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQsFAAOCAQEATAkF+IMRQHvlr8K9
# 3HlphP251jFCedkjeqBesoVYdnhxwYut5zKCSoWtpQjLF7I8J4yewPhvYcpOinxF
# 8Xdie6XdeZsBzp2uqVQIwLd/WbX19dEjsQFzejacFD9fKJGcck9ZRkbNv/Od0Omo
# DOk6lVHJkSg9UvLOKEOtwDDysZR7zJr8vqk++8tE4XBgohp8JP9o6HJ7WKywk4xX
# 5HRom11D7hszRI4pI9S8uGdKhB5TQgOm6g3I6VzCggPJ+7vqE4x4IU8UN5hNIXk2
# DBpqO9HUOLmMo9c/jJ5t9ls+kaN3cVVWDm3Dh/u1x1qlYolSoYLsE+1EsI0dhz2T
# /XILTTANBgkqhkiG9w0BAQEFAASCAgAJvQzu0FCTY/ttR4NA1Cr5UXaTZu2+Pp/s
# s+qgCA6wElJLAfwkworC+nizdn5IqVxtRNI90eYMcYWE3QTG6EcqSSuQvf3/W4zn
# gtri/Rn5CPZ5w49rVURphsMEh9keKQwm8MHgDEtyjIgn40t51qNbWMgm/Cr+xm7f
# bYlDpDti+LIvycNU8OoXfBnd2RZqICjFHypbWNRe6zdbFlLm+eB04XpadCn4d/o6
# az8qQmDn0T9KQbAHIsUsbGskmsnEVOZKyfi8W2M5gyC438QUoK1dAbDYotawWQ66
# u15+ld247r0QDOydLhYYzlATfSKSwFDya45PbMzwfK632rwH8Mo9SRGZ582Bd692
# 8lofB6Hc9/nWdqQIdoDmwF/VWNChWgawa+NnfryF5UCwEvsQDQUKztDpGzbjgtiR
# 0CRFvK0Qqn/6GkUTzkW7JkjavgO1ycD9TEUauHjFZw5CGlh5SbBdpFlMY1RPHYho
# 0mhWmiP374vx/NCHa4LNKCnTbi1yx/STdBbko74/Tl94/ZPqC15WJOc5wgq7xPfa
# STxoosKEqc1reGyByCJ1sKga6WC1EndIzgLLc6Kh8i1fSqGQ+otjG72yWPVn9EBH
# xErQbL4lLrbWRVCC9nmv+SFE5cVnv3WmqIfvFjeQ/JF92BdoL1zWuI6/v2pr2tTv
# Q/NH9N/KNw==
# SIG # End signature block
