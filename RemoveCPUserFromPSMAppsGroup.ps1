###########################################################################
#
# NAME: SAM TO UPN
#
# AUTHOR:  Mike Brook<mike.brook@cyberark.com>
#
# COMMENT: 
# Script pull a list of all existing human users from the vault (Assuming SAM format) and after manual adjustment will rename to UPN format in the vault.
#
#
###########################################################################
[CmdletBinding()]
param(
    [Parameter(Mandatory = $False)]
    [ValidateSet("cyberark")]
    [string]$AuthType = "cyberark",
    [Parameter(Mandatory = $true, HelpMessage = "Specify a User that has Privilege Cloud Administrative permissions.")]
    [PSCredential]$Credentials,
    [Parameter(Mandatory = $true, HelpMessage = "Enter your Portal URL (eg; 'https://mycybrlab.privilegecloud.cyberark.com')")]
    $PVWAURL
)

$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
$global:LOG_FILE_PATH = "$ScriptLocation\_SAMToUPN.log"
[int]$scriptVersion = 1

## Force Output to be UTF8 (for OS with different languages)
$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding

#region Log functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================
Function Write-LogMessage
{
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [Bool]$WriteLog = $true,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )
    Try
    {
        If ([string]::IsNullOrEmpty($LogFile) -and $WriteLog)
        {
            $LogFile = Join-Path -Path $ENV:Temp -ChildPath "$((Get-Date).ToShortDateString().Replace('/','_')).log"
            Write-Host "No log file path inputted, created a temporary file at: '$LogFile'"
        }
        If ($Header -and $WriteLog)
        {
            "=======================================" | Out-File -Append -FilePath $LogFile 
            Write-Host "=======================================" -ForegroundColor Magenta
        }
        ElseIf ($SubHeader -and $WriteLog)
        { 
            "------------------------------------" | Out-File -Append -FilePath $LogFile 
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }
        if ([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
        $msgToWrite = ""
        $maskingPattern = '(?:(?:["\s\/\\](secret|NewCredentials|credentials|answer)(?!s))\s{0,}["\:= ]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()\-_\=\+\\\/\|\,\;\:\.\[\]\{\}]+))'
        $maskingResult = $Msg | Select-String $maskingPattern -AllMatches
        if ($maskingResult.Matches.Count -gt 0)
        {
            foreach ($item in $maskingResult.Matches)
            {
                if ($item.Success)
                {
                    if ($item.Groups[2].Value -NotMatch '^(,| |;)$')
                    {
                        $Msg = $Msg.Replace($item.Groups[2].Value, "****")
                    }
                }
            }
        }
        switch ($type)
        {
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } 
            { 
                If ($_ -eq "Info")
                {
                    Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) { "Magenta" } Else { "Gray" })
                }
                $msgToWrite = "[INFO]`t$Msg"
                break
            }
            "Success"
            { 
                Write-Host $MSG.ToString() -ForegroundColor darkGreen
                $msgToWrite = "[SUCCESS]`t$Msg"
                break
            }
            "Warning"
            {
                Write-Host $MSG.ToString() -ForegroundColor Yellow
                $msgToWrite = "[WARNING]`t$Msg"
                break
            }
            "Error"
            {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite = "[ERROR]`t$Msg"
                break
            }
            "Debug"
            { 
                if ($InDebug -or $InVerbose)
                {
                    Write-Debug $MSG
                    $msgToWrite = "[DEBUG]`t$Msg"
                }
                break
            }
            "Verbose"
            { 
                if ($InVerbose)
                {
                    Write-Verbose -Msg $MSG
                    $msgToWrite = "[VERBOSE]`t$Msg"
                }
                break
            }
        }

        If ($WriteLog) 
        { 
            If (![string]::IsNullOrEmpty($msgToWrite))
            {				
                "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t$msgToWrite" | Out-File -Append -FilePath $LogFile
            }
        }
        If ($Footer -and $WriteLog)
        { 
            "=======================================" | Out-File -Append -FilePath $LogFile 
            Write-Host "=======================================" -ForegroundColor Magenta
        }
    }
    catch
    {
        Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
    }
}

Function Join-ExceptionMessage { param([Exception]$e)
    $msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
    while ($e.InnerException) { $e = $e.InnerException; $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message }
    return $msg
}

Function Collect-ExceptionMessage { param([Exception]$e)
    $msg = "Source: {0}; Message: {1}" -f $e.Source, $e.Message
    while ($e.InnerException) { $e = $e.InnerException; $msg += "`n`tSource: {0}; Message: {1}" -f $e.Source, $e.Message }
    return $msg
}
#endregion

#region REST Logon
Function IgnoreCertErrors()
{
    if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
        $certCallback = @"
			using System;
			using System.Net;
			using System.Net.Security;
			using System.Security.Cryptography.X509Certificates;
			public class ServerCertificateValidationCallback
			{
				public static void Ignore()
				{
					if(ServicePointManager.ServerCertificateValidationCallback ==null)
					{
						ServicePointManager.ServerCertificateValidationCallback += 
							delegate
							(
								Object obj, 
								X509Certificate certificate, 
								X509Chain chain, 
								SslPolicyErrors errors
							)
							{
								return true;
							};
					}
				}
			}
"@
        Add-Type $certCallback
    }
    [ServerCertificateValidationCallback]::Ignore()
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

Function Get-LogonHeader
{
    param([Parameter(Mandatory = $true)][PSCredential]$Credentials)
    $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password } | ConvertTo-Json -Compress
    try {
        $logonToken = Invoke-RestMethod -Method Post -Uri $URL_PVWALogon -Body $logonBody -ContentType "application/json" -TimeoutSec 2700
        $logonBody = ""
    } catch {
        Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.ErrorDetails.Message)"))
    }
    if ([string]::IsNullOrEmpty($logonToken)) { Throw "Get-LogonHeader: Logon Token is Empty - Cannot login" }
    if ($logonToken.PSObject.Properties.Name -contains "CyberArkLogonResult") { @{Authorization = $($logonToken.CyberArkLogonResult) } } else { @{Authorization = $logonToken } }
}

Function Invoke-Logon
{ 
    try {
        IgnoreCertErrors
        Write-LogMessage -type Info -MSG "START Logging in to PVWA."  
        $script:s_pvwaLogonHeader = Get-LogonHeader -Credentials $Credentials
        if ($s_pvwaLogonHeader.Keys -contains "Authorization") { Write-LogMessage -type Info -MSG "FINISH Logging in to PVWA." }
    } catch {
        Throw $(New-Object System.Exception ("Error logging on to PVWA", $_.Exception))
    }
}

Function Invoke-Logoff
{
    try {
        Write-LogMessage -type Info -Msg "Logoff Session..."
        Invoke-RestMethod -Method Post -Uri $URL_PVWALogoff -Headers $s_pvwaLogonHeader -ContentType "application/json" | Out-Null
    } catch {
        Throw $(New-Object System.Exception ("Error logging off from PVWA", $_.Exception))
    }
}
#endregion

Function Set-PVWAURL
{
    [CmdletBinding()]
    param ([Parameter(Mandatory = $False)][ValidateSet("cyberark", "ldap")][string]$AuthType = "cyberark")
    $script:URL_PVWA = "https://" + ([System.Uri]$PVWAurl).Host
    $global:subdomain = ([System.Uri]$PVWAurl).Host.Split(".")[0]
    $URL_PVWAPasswordVault = $URL_PVWA + "/passwordVault"
    $URL_PVWAAPI = $URL_PVWAPasswordVault + "/api"
    $URL_PVWAAuthentication = $URL_PVWAAPI + "/auth"
    $script:URL_PVWALogon = $URL_PVWAAuthentication + "/$AuthType/Logon"
    $script:URL_PVWALogoff = $URL_PVWAAuthentication + "/Logoff"
    Write-LogMessage -type debug -Msg "Logon URL will be: '$URL_PVWALogon'"
    $script:URL_Users = $URL_PVWAAPI + "/Users"
    $script:URL_Accounts = $URL_PVWAAPI + "/Accounts"
    $script:URL_AccountVerify = $URL_Accounts + "/{0}/Verify"
    $script:URL_UsersGroups = $URL_PVWAAPI + "/UserGroups"
    $script:URL_Safes = $URL_PVWAAPI + "/Safes"
    $script:URL_SafeFind = $URL_PVWAPasswordVault + "/WebServices/PIMServices.svc/Safes?query={0}"
    $script:URL_SafeAddMembers = $URL_Safes + "/{0}/Members"
    $script:URL_SafesUnderPlatform = $URL_PVWAAPI + "/Platforms/{0}/Safes"
    $script:URL_SystemHealthComponent = $URL_PVWAAPI + "/ComponentsMonitoringDetails/{0}"
    $script:URL_UserSetGroup = $URL_UsersGroups + "/{0}/Members"
    $script:URL_UserDelGroup = $URL_UsersGroups + "/{0}/Members/{1}"
    $script:URL_UserExtendedDetails = $URL_Users + "/{0}"
    $script:URL_PlatformVerify = $URL_PVWAAPI + "/Platforms/{0}"
    $script:URL_PlatformImport = $URL_PVWAAPI + "/Platforms/Import"
    $script:URL_PlatformsFindAll = $URL_PVWAAPI+"/platforms/targets"
    $script:URL_ConnectionComponentVerify = $URL_PVWAAPI + "/ConnectionComponents/{0}"
    $script:URL_ConnectionComponentImport = $URL_PVWAAPI + "/ConnectionComponents/Import"
    $script:URL_PlatformUpdatePSM = $URL_PVWAAPI+"/Platforms/Targets/{0}/PrivilegedSessionManagement"
    $script:URL_GetAllPSMs = $URL_PVWAAPI + "/PSM/Servers"
    $script:URL_SystemHealthComponent = $URL_PVWAAPI + "/ComponentsMonitoringDetails/{0}"
    $script:URL_DomainDirectories = $URL_PVWAAPI + "/Configuration/LDAP/Directories"
    $script:URL_VaultMappings = $URL_PVWAAPI + "/Configuration/LDAP/Directories/{0}/mappings"
    $script:URL_VaultVersion = $URL_PVWAPasswordVault + "/WebServices/PIMServices.svc/Server"
}

Function Get-Choice
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)] $Title,
        [Parameter(Mandatory = $true, Position = 1)][String[]] $Options,
        [Parameter(Position = 2)] $DefaultChoice = -1
    )
    if ($DefaultChoice -ne -1 -and ($DefaultChoice -gt $Options.Count -or $DefaultChoice -lt 1)) { Write-Warning "DefaultChoice needs to be a value between 1 and $($Options.Count) or -1 (for none)"; exit }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $script:result = ""
    $form = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
    $form.BackColor = [Drawing.Color]::White
    $form.TopMost = $True
    $form.Text = $Title
    $form.ControlBox = $False
    $form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
    $minFormWidth = 300
    $formHeight = 44
    $minButtonWidth = 100
    $buttonHeight = 23
    $buttonY = 12
    $spacing = 10
    $buttonWidth = [Windows.Forms.TextRenderer]::MeasureText((($Options | Sort-Object Length)[-1]), $form.Font).Width + 1
    $buttonWidth = [Math]::Max($minButtonWidth, $buttonWidth)
    $formWidth = [Windows.Forms.TextRenderer]::MeasureText($Title, $form.Font).Width
    $spaceWidth = ($options.Count + 1) * $spacing
    $formWidth = ($formWidth, $minFormWidth, ($buttonWidth * $Options.Count + $spaceWidth) | Measure-Object -Maximum).Maximum
    $form.ClientSize = New-Object System.Drawing.Size($formWidth, $formHeight)
    $index = 0
    foreach ($option in $Options)
    {
        Set-Variable "button$index" -Value (New-Object System.Windows.Forms.Button)
        $temp = Get-Variable "button$index" -ValueOnly
        $temp.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
        $temp.UseVisualStyleBackColor = $True
        $temp.Text = $option
        $buttonX = ($index + 1) * $spacing + $index * $buttonWidth
        $temp.Add_Click({ $script:result = $this.Text; $form.Close() })
        $temp.Location = New-Object System.Drawing.Point($buttonX, $buttonY)
        $form.Controls.Add($temp)
        $index++
    }
    $shownString = '$this.Activate();'
    if ($DefaultChoice -ne -1) { $shownString += '(Get-Variable "button$($DefaultChoice-1)" -ValueOnly).Focus()' }
    $shownSB = [ScriptBlock]::Create($shownString)
    $form.Add_Shown($shownSB)
    [void]$form.ShowDialog()
    return $result
}

# --- New helpers for reliable deletion & verification ---

function Get-GroupMembers {
    param([Parameter(Mandatory)][string]$GroupId)
    Invoke-RestMethod -Uri "$($URL_UsersGroups)/$GroupId/" -Method Get -Headers $s_pvwaLogonHeader -ErrorAction Stop
}

function Test-UserInGroup {
    param(
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][string]$Username
    )
    $grp = Get-GroupMembers -GroupId $GroupId
    return ($grp.members | Where-Object { $_.username -eq $Username }).Count -gt 0
}

function Remove-UserFromGroupByUsername {
    param(
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][string]$Username
    )

    $escapedUser = [uri]::EscapeDataString($Username)
    $delUri = "$($URL_UsersGroups)/$GroupId/Members/$escapedUser"
    if ($Username -match '[@\.]') { $delUri += '/' }   # trailing slash rule for '.' / '@'

    try {
        Invoke-RestMethod -Uri $delUri -Method Delete -Headers $s_pvwaLogonHeader -TimeoutSec 30 -ErrorAction Stop | Out-Null
        return [pscustomobject]@{ username=$Username; removed=$true; note='DELETE 2xx/204' }
    }
    catch {
        $status = $null
        try { $status = $_.Exception.Response.StatusCode.value__ } catch {}
        # Verify current state; 504/50x might still have removed the member server-side
        Start-Sleep -Milliseconds 250
        $stillThere = $true
        try { $stillThere = Test-UserInGroup -GroupId $GroupId -Username $Username } catch { $stillThere = $true }
        if (-not $stillThere) {
            return [pscustomobject]@{ username=$Username; removed=$true; note="DELETE HTTP $status; confirmed removed" }
        } else {
            return [pscustomobject]@{ username=$Username; removed=$false; note="DELETE HTTP $status; member still present"; error=$_.Exception.Message }
        }
    }
}

# ------------------------------------------------------------
# Script Begins Here

#Cleanup log file if it gets too big
if (Test-Path $LOG_FILE_PATH) {
    if (Get-ChildItem $LOG_FILE_PATH -File | Where-Object { $_.Length -gt 400KB }) {
        Write-LogMessage -type Info -MSG "Log file is getting too big, deleting it."
        Remove-Item $LOG_FILE_PATH -Force
    }
}

Set-PVWAURL -AuthType cyberark
Invoke-Logon

$getPSMGroup = Invoke-RestMethod -Uri "$($URL_UsersGroups)?filter=groupName eq PSMAppUsers&includeMembers eq true" -Method Get -Headers $s_pvwaLogonHeader -ErrorVariable pvwaERR
write-host "Group ID: $($getPSMGroup.value.id)"

$getPSMGroupMembers = Invoke-RestMethod -Uri "$($URL_UsersGroups)/$($getPSMGroup.value.id)/" -Method Get -Headers $s_pvwaLogonHeader -ErrorVariable pvwaERR

# Exclude PSMApp_* members
$filterMembers = $getPSMGroupMembers.members | Where-Object { $_.username -notlike "PSMApp_*" }

# Show table now to keep order
$filterMembers |
  Sort-Object username |
  Format-Table username, id -AutoSize |
  Out-Host

Write-Host ("Found total of {0} non PSM users in group {1}" -f @($filterMembers).Count, $getPSMGroup.value.groupName) -ForegroundColor Yellow

if (@($filterMembers).Count -gt 0) {
    # Prompt to delete
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes','Delete all listed users from the group'
    $no  = New-Object System.Management.Automation.Host.ChoiceDescription '&No','Do not delete'
    $choice = $Host.UI.PromptForChoice(
        'Confirm deletion',
        ("Delete these {0} users from group '{1}'?" -f @($filterMembers).Count, $getPSMGroup.value.groupName),
        ([System.Management.Automation.Host.ChoiceDescription[]]@($yes,$no)),
        1 # default = No
    )

    if ($choice -eq 0) {
        $total = @($filterMembers).Count
        $idx = 0
        $results = foreach ($member in @($filterMembers)) {
            $idx++
            Write-Progress -Activity 'Removing users from group' -Status $member.username -PercentComplete ([int](($idx * 100) / $total))
            Remove-UserFromGroupByUsername -GroupId $getPSMGroup.value.id -Username $member.username
        }
        Write-Progress -Activity 'Removing users from group' -Completed

        $success = @($results | Where-Object { $_.removed }).Count
        $fail    = @($results | Where-Object { -not $_.removed })

        Write-Host "Done. Removed $success user(s). Failures: $(@($fail).Count)." -ForegroundColor Green
        if ($fail) { $fail | Format-Table username, note, error -AutoSize | Out-Host }
    }
    else {
        Write-Host 'Deletion canceled.' -ForegroundColor Yellow
    }
}

Invoke-Logoff
