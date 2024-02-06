Function Get-IdentityHeader {
    <#
    .SYNOPSIS
        Function to get Identity Header to enable running scripts using the token parameter. This will allow running the rest of the scripts in the directory for Identity Shared Services - Shared Services customers (ISPSS) (Privilege Cloud).
        Token created using Identity documentation https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/WebServices/ISP-Auth-APIs.htm

    .DESCRIPTION
        This function starts by requesting authentication into identity APIs. Once the process starts there can be multiple challenges that need to be responded with multiple options.
        Each option is then being decided by the user. Once authentication is complete we get a token for the user to use for APIs within the ISPSS platform.

    .PARAMETER IdentityTenantURL
        The URL of the tenant. you can find it if you go to Identity Admin Portal > Settings > Customization > Tenant URL.

    .Parameter IdentityUserName
        The Username that will log into the system. It just needs the username, we will ask for PW, Push etc when doing the authentication.

    .Parameter PCloudSubdomain
        The Subdomain assigned to the privileged cloud environment.

    .Parameter psPASFormat
        Use this switch to output the token in a format that PSPas can consume directly.
    
    .Parameter UPCreds
        Use this switch to output the token in a format that PSPas can consume directly.

    #>
    [CmdletBinding(DefaultParameterSetName = 'IdentityUserName')]
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = "Identity Tenant URL")]
        [string]$IdentityTenantURL,
        [Parameter(
            ParameterSetName = "IdentityUserName",
            Mandatory = $true,
            HelpMessage = "User to authenticate into the platform")]
        [string]$IdentityUserName,
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Identity Tenant ID")]
        [string]$IdentityTenantId,
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Output header in a format for use with psPAS")]
        [switch]$psPASFormat,
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Subdomain of the privileged cloud environment")]
        [Parameter(
            ParameterSetName = 'psPASFormat',
            Mandatory = $true,
            HelpMessage = "Subdomain of the privileged cloud environment")]
        [string]$PCloudSubdomain,
        [Parameter(
            ParameterSetName = 'UPCreds',
            Mandatory = $true,
            HelpMessage = "Credentials to pass if option is UP")]
        [pscredential]$UPCreds

    )
    $ScriptFullPath = Get-Location
    $LOG_FILE_PATH = "$ScriptFullPath\IdentityAuth.log"

    $InDebug = $PSBoundParameters.Debug.IsPresent
    $InVerbose = $PSBoundParameters.Verbose.IsPresent

    #Platform Identity API

    if ($IdentityTenantURL -match "https://") {
        $IdaptiveBasePlatformURL = $IdentityTenantURL
    } Else {
        $IdaptiveBasePlatformURL = "https://$IdentityTenantURL"
    }

    $PCloudTenantAPIURL = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/"

    Write-LogMessage -type "Verbose" -MSG "URL used : $($IdaptiveBasePlatformURL|ConvertTo-Json -Depth 9)"

    #Creating URLs

    $IdaptiveBasePlatformSecURL = "$IdaptiveBasePlatformURL/Security"
    $startPlatformAPIAuth = "$IdaptiveBasePlatformSecURL/StartAuthentication"
    $startPlatformAPIAdvancedAuth = "$IdaptiveBasePlatformSecURL/AdvanceAuthentication"
    $LogoffPlatform = "$IdaptiveBasePlatformSecURL/logout"

    #Creating the username/password variables
    if ('UPCreds' -eq $PSCmdlet.ParameterSetName) {
        $InUPCreds = $true
        $IdentityUserName = $UPCreds.UserName
    }
    $startPlatformAPIBody = @{TenantId = $IdentityTenantId; User = $IdentityUserName ; Version = "1.0" } | ConvertTo-Json -Compress -Depth 9
    Write-LogMessage -type "Verbose" -MSG "URL body : $($startPlatformAPIBody|ConvertTo-Json -Depth 9)"
    $IdaptiveResponse = Invoke-RestMethod -SessionVariable session -Uri $startPlatformAPIAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIBody -TimeoutSec 30
    Write-LogMessage -type "Verbose" -MSG "IdaptiveResponse : $($IdaptiveResponse|ConvertTo-Json -Depth 9)"

    # We can use the following to give info to the customer $IdaptiveResponse.Result.Challenges.mechanisms

    $SessionId = $($IdaptiveResponse.Result.SessionId)
    Write-LogMessage -type "Verbose" -MSG "SessionId : $($SessionId |ConvertTo-Json -Depth 9)"

    IF (![string]::IsNullOrEmpty($IdaptiveResponse.Result.IdpRedirectUrl)) {
        IF ([string]::IsNullOrEmpty($PCloudSubdomain)) {
            $PCloudSubdomain = Read-Host -Prompt "The Privilege Cloud Subdomain is required when using SAML. Please enter it"
        }
        $OriginalProgressPreference = $Global:ProgressPreference
        $Global:ProgressPreference = 'SilentlyContinue'
        IF (Test-NetConnection -InformationLevel Quiet -Port 443 "$PCloudSubdomain.privilegecloud.cyberark.cloud") {
            $PCloudTenantAPIURL = "https://$PCloudSubdomain.privilegecloud.cyberark.cloud/PasswordVault/"
            $Global:ProgressPreference = $OriginalProgressPreference
        } else {
            $Global:ProgressPreference = $OriginalProgressPreference
            Write-LogMessage -type Error -MSG "Error during subdomain validation: Unable to contact https://$PCloudSubdomain.privilegecloud.cyberark.cloud"
            exit
        }
        $AnswerToResponse = Invoke-SAMLLogon $IdaptiveResponse
    } else {
        $AnswerToResponse = Invoke-Challenge $IdaptiveResponse
    }

    If ($AnswerToResponse.success) {
        #Creating Header
        If (!$psPASFormat) {
            $IdentityHeaders = @{Authorization = "Bearer $($AnswerToResponse.Result.Token)" }
            $IdentityHeaders.Add("X-IDAP-NATIVE-CLIENT", "true")
        } else {
            $ExternalVersion = Get-PCloudExternalVersion -PCloudTenantAPIURL $PCloudTenantAPIURL -Token $AnswerToResponse.Result.Token
            $header = New-Object System.Collections.Generic.Dictionary"[String,string]"
            $header.add("Authorization", "Bearer $($AnswerToResponse.Result.Token)")
            $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $session.Headers = $header
            $IdentityHeaders = [PSCustomObject]@{
                User            = $IdentityUserName
                BaseURI         = $PCloudTenantAPIURL
                ExternalVersion = $ExternalVersion
                WebSession      = $session
            }
            $IdentityHeaders.PSObject.TypeNames.Insert(0, 'psPAS.CyberArk.Vault.Session')
        }
        Write-LogMessage -type "Verbose" -MSG "IdentityHeaders - $($IdentityHeaders |ConvertTo-Json)"
        Write-LogMessage -type "Info" -MSG "Identity Token Set Successfully"
        return $identityHeaders
    } else {
        Write-LogMessage -type "Verbose" -MSG "identityHeaders: $($AnswerToResponse|ConvertTo-Json)"
        Write-LogMessage -type Error -MSG "Error during logon : $($AnswerToResponse.Message)"
    }
}

Function Invoke-Challenge {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $true)]
        [array]$IdaptiveResponse
    )

    $j = 1
    ForEach ($challenge in $IdaptiveResponse.Result.Challenges) {
        #reseting variables
        $Mechanism = $null
        $MechanismId = $null
        $Action = $null
        $startPlatformAPIAdvancedAuthBody = $null
        $ChallengeCount = 0
        $ChallengeCount = $challenge.mechanisms.count

        Write-LogMessage -type "Info" -MSG "Challenge $($j):"
        #Multi mechanisms option response
        If ($ChallengeCount -gt 1) {
            Write-LogMessage -type "Info" -MSG "There are $ChallengeCount options to choose from."
            $mechanisms = $challenge.mechanisms
            #Displaying the two options for MFA at this challenge part
            $i = 1
            ForEach ($mechanismsOption in $mechanisms) {
                $mechanismsName = $mechanismsOption.Name
                $MechanismsMechChosen = $mechanismsOption.PromptMechChosen
                Write-LogMessage -type "Info" -MSG "$i - is $mechanismsName - $MechanismsMechChosen"
                $i = $i + 1
            }
            #Requesting to know which option the user wants to use
            $Option = $Null
            While ($Option -gt $ChallengeCount -or $Option -lt 1 -or $Option -eq $Null) {
                $Option = Read-Host "Please enter the option number you want to use. from 1-$ChallengeCount"
                Try {
                    $Option = [Int]$Option
                } Catch {
                    Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
                }
            }
            #Getting the mechanism
            $Mechanism = $challenge.mechanisms[$Option - 1] #This is an array so number-1 means the actual position
            #Completing step of authentication
            $AnswerToResponse = Invoke-AdvancedAuthBody -SessionId $SessionId -Mechanism $Mechanism -IdentityTenantId $IdentityTenantId
            Write-LogMessage -type "Verbose" -MSG "AnswerToResponce - $($AnswerToResponse |ConvertTo-Json)"
        }
        #One mechanism
        Else {
            $Mechanism = $challenge.mechanisms
            $MechanismName = $Mechanism.Name
            $MechanismPrmpt = $Mechanism.PromptMechChosen
            Write-LogMessage -type "Info" -MSG "$MechanismName - $MechanismPrmpt"
            $AnswerToResponse = Invoke-AdvancedAuthBody -SessionId $SessionId -Mechanism $Mechanism -IdentityTenantId $IdentityTenantId
            Write-LogMessage -type "Verbose" -MSG "AnswerToResponce - $($AnswerToResponse |ConvertTo-Json)"
        }
        #Need Better logic here to make sure that we are done with all the challenges correctly and got next challenge.
        $j = + 1 #incrementing the challenge number
    }

    Return $AnswerToResponse



}

#Runs an advanceAuth API. It will wait in the loop if needed
Function Invoke-AdvancedAuthBody {
    [CmdletBinding()]
    Param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = "Session ID of the mechanism")]
        [string]$SessionId,
        [Parameter(
            Mandatory = $true,
            HelpMessage = "Mechanism of Authentication")]
        $Mechanism,
        [Parameter(
            Mandatory = $false,
            HelpMessage = "Tenant ID")]
        [String]$IdentityTenantId
    )
    $MaskList = @("UP")
    $MechanismId = $Mechanism.MechanismId
    #need to do this if/elseif as a function so we do not double code here.
    If ($Mechanism.AnswerType -eq "StartTextOob") {
        #We got two options here 1 text and one Push notification. We will need to do the while statement in this option.
        $Action = "StartOOB"
        $startPlatformAPIAdvancedAuthBody = @{TenantID = $IdentityTenantId; SessionId = $SessionId; MechanismId = $MechanismId; Action = $Action; } | ConvertTo-Json -Compress
        Write-LogMessage -type "Verbose" -MSG "startPlatformAPIAdvancedAuthBody: $($startPlatformAPIAdvancedAuthBody|ConvertTo-Json -Depth 9)"
        Write-LogMessage -type "Info" -MSG "Waiting for Push to be pressed"
    } ElseIf ($Mechanism.AnswerType -eq "Text") {
        $Action = "Answer"
        IF (($Mechanism.Name -eq "UP") -and ($InUPCreds)) {
            Write-Host "Responding with stored credentials"
            $answer = $UPCreds.Password
        } else {
            $Answer = Read-Host "Please enter the answer from the challenge type" -AsSecureString
        }
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Answer)
        $startPlatformAPIAdvancedAuthBody = @{TenantID = $IdentityTenantId; SessionId = $SessionId; MechanismId = $MechanismId; Action = $Action; Answer = ([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)) } | ConvertTo-Json -Compress
        If ($Mechanism.Name -in $MaskList) {
            Write-LogMessage -type "Verbose" -MSG "startPlatformAPIAdvancedAuthBody: $($startPlatformAPIAdvancedAuthBody|ConvertTo-Json -Depth 9))" -maskAnswer
        } Else {
            Write-LogMessage -type "Verbose" -MSG "startPlatformAPIAdvancedAuthBody: $($startPlatformAPIAdvancedAuthBody|ConvertTo-Json -Depth 9))"
        }
    }
    #Rest API
    Try {
        $AnswerToResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIAdvancedAuthBody -TimeoutSec 30
        Write-LogMessage -type "Verbose" -MSG "AnswerToResponse: $($AnswerToResponse|ConvertTo-Json)"
    } Catch {
        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
    }
    while ($AnswerToResponse.Result.Summary -eq "OobPending") {
        Start-Sleep -Seconds 2
        $pollBody = @{TenantID = $IdentityTenantId; SessionId = $SessionId; MechanismId = $MechanismId; Action = "Poll"; } | ConvertTo-Json -Compress
        Write-LogMessage -type "Verbose" -MSG "pollBody: $($pollBody|ConvertTo-Json)"
        $AnswerToResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $pollBody -TimeoutSec 30
        Write-LogMessage -type "Verbose" -MSG "AnswerToResponse: $($AnswerToResponse|ConvertTo-Json)"
        Write-LogMessage -type "Info" -MSG "$($AnswerToResponse.Result.Summary)"
    }
    $AnswerToResponse
}

function Get-PCloudExternalVersion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $PCloudTenantApiUrl,
        [Parameter(Mandatory = $true)]
        $Token
    )

    $ExternalVersion = "12.6.0"
    try {
        $Headers = @{
            Authorization = "Bearer $Token"
        }
        $Response = Invoke-RestMethod -Method GET -Uri "$PCloudTenantApiUrl/WebServices/PIMServices.svc/Server" -Headers $Headers -ContentType 'application/json'
        $ExternalVersion = $Response.ExternalVersion
    } catch {
        Write-LogMessage -Type Error -MSG $_.ErrorDetails.Message
    }

    $ExternalVersion
}

Function Write-LogMessage {
    <#
    .SYNOPSIS
        Method to log a message on screen and in a log file

    .DESCRIPTION
        Logging The input Message to the Screen and the Log File.
        The Message Type is presented in colours on the screen based on the type

    .PARAMETER LogFile
        The Log File to write to. By default using the LOG_FILE_PATH
    .PARAMETER MSG
        The message to log
    .PARAMETER Header
        Adding a header line before the message
    .PARAMETER SubHeader
        Adding a Sub header line before the message
    .PARAMETER Footer
        Adding a footer line after the message
    .PARAMETER Type
        The type of the message to log (Info, Warning, Error, Debug)
    #>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$Early,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose", "Success", "LogOnly")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH,
        [Parameter(Mandatory = $false)]
        [Switch]$maskAnswer
    )
    Try {
        If ($Header) {
            "=======================================" | Out-File -Append -FilePath $LogFile
            Write-Host "=======================================" -ForegroundColor Magenta
        } ElseIf ($SubHeader) {
            "------------------------------------" | Out-File -Append -FilePath $LogFile
            Write-Host "------------------------------------" -ForegroundColor Magenta
        }

        $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
        if ($InDebug -or $InVerbose) {
            $writeToFile = $true
        } Else {
            $writeToFile = $false
        }
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg)) {
            $Msg = "N/A"
        }
        If ($maskAnswer) {
            $Msg -match '(?:\\"Answer\\":\\")(?<Mask>.*?)(?:\\")' | Out-Null
            $Msg = $Msg.Replace($Matches.Mask, "<Value Masked>")
        }
        # Check the message type
        switch ($type) {
            { ($_ -eq "Info") -or ($_ -eq "LogOnly") } {
                If ($_ -eq "Info") {
                    Write-Host $MSG.ToString() -ForegroundColor $(If ($Header -or $SubHeader) {
                            "magenta"
                        } Elseif ($Early) {
                            "DarkGray"
                        } Else {
                            "White"
                        })
                }
                $msgToWrite += "[INFO]`t$Msg"
            }
            "Success" {
                Write-Host $MSG.ToString() -ForegroundColor Green
                $msgToWrite += "[SUCCESS]`t$Msg"
            }
            "Warning" {
                Write-Host $MSG.ToString() -ForegroundColor Yellow
                $msgToWrite += "[WARNING]`t$Msg"
            }
            "Error" {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite += "[ERROR]`t$Msg"
            }
            "Debug" {
                if ($InDebug -or $InVerbose) {
                    $writeToFile = $true
                    Write-Debug $MSG
                    $msgToWrite += "[DEBUG]`t$Msg"
                } else {
                    $writeToFile = $False
                }
            }
            "Verbose" {
                if ($InVerbose) {
                    $writeToFile = $true
                    Write-Verbose -Msg $MSG
                    $msgToWrite += "[VERBOSE]`t$Msg"
                } else {
                    $writeToFile = $False
                }
            }
        }

        If ($writeToFile) {
            $msgToWrite | Out-File -Append -FilePath $LogFile
        }
        If ($Footer) {
            "=======================================" | Out-File -Append -FilePath $LogFile
            Write-Host "=======================================" -ForegroundColor Magenta
        }
    } catch {
        Throw $(New-Object System.Exception ("Cannot write message"), $_.Exception)
    }
}

function Invoke-SAMLLogon {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Array] $IdaptiveResponse
    )

    Begin {

        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Web

        #Special thanks to Shay Tevet for his assistance on this section
        $source = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace Cookies
{
    public static class getter
    {
       [DllImport("wininet.dll", CharSet=CharSet.None, ExactSpelling=false, SetLastError=true)]
        public static extern bool InternetGetCookieEx(string url, string cookieName, StringBuilder cookieData, ref int size, int dwFlags, IntPtr lpReserved);

	public static string GetUriCookieContainer(String uri)
        {
            string str;
            try
            {
                int num = 131072;
                StringBuilder stringBuilder = new StringBuilder(num);
                if (!InternetGetCookieEx(uri, null, stringBuilder, ref num, 8192, IntPtr.Zero))
                {
                        str = null;
                        return str;
                }
                str = (!stringBuilder.ToString().Contains("idToken-") ? "Error" : stringBuilder.ToString().Split(new string[] { "idToken-" }, StringSplitOptions.None)[1].Split(new char[] { ';' })[0].Split(new char[] { '=' })[1]);
            }
            catch
            {
                str = "Error";
            }
            return str;
        }
    }
}
"@

        $compilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
        $compilerParameters.CompilerOptions = "/unsafe"

        Add-Type -TypeDefinition $source -Language CSharp -CompilerParameters $compilerParameters

        $PCloudURL = "https://$PCloudSubdomain.cyberark.cloud"
        $PCloudPortalURL = "$PCloudURL/privilegecloud/"
        $logonURL = "$IdaptiveBasePlatformURL/login?redirectUrl=https%3A%2F%2F$PCloudSubdomain.cyberark.cloud%2Fprivilegecloud&username=$IdentityUserName&iwa=false&iwaSsl=false"

    }

    Process {
        $DocComp = {

            if ($web.Url.AbsoluteUri -like "*/privilegecloud" -and $web.document.Cookie -like "*loggedIn-*") {
                $Global:Auth = [cookies.getter]::GetUriCookieContainer("$PCloudURL").ToString()
                $form.Close()
            }
        }


        # create window for embedded browser
        $form = New-Object Windows.Forms.Form
        $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
        $form.Width = 640
        $form.Height = 700
        $form.showIcon = $false
        $form.TopMost = $false
        $form.Text = "SAML Based Authentication"

        $web = New-Object Windows.Forms.WebBrowser
        $web.Size = $form.ClientSize
        $web.Anchor = "Left,Top,Right,Bottom"
        $web.ScriptErrorsSuppressed = $false
        $web.AllowWebBrowserDrop = $false
        $web.IsWebBrowserContextMenuEnabled = $true
        $web.Add_DocumentCompleted($DocComp)
        $form.Controls.Add($web)

        $web.Navigate(("$logonURL"))

        # show browser window, waits for window to close
        if ([system.windows.forms.application]::run($form) -ne "OK") {

            if ($null -ne $auth) {
                [PSCustomObject]$Return = @{
                    Success = $true
                    Result  = @{
                        Token = $auth
                    }
                }
                return $Return
                $form.Close()
            } Else {
                throw "Unable to get auth token"
            }
        }

        End {
            $form.Dispose()
        }
    }
}
# SIG # Begin signature block
# MIIqRQYJKoZIhvcNAQcCoIIqNjCCKjICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAodkmIWY+eEw3p
# y2xgmK6fVpfZlrfbRIYHK/ijYuJboaCCGFcwggROMIIDNqADAgECAg0B7l8Wnf+X
# NStkZdZqMA0GCSqGSIb3DQEBCwUAMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBH
# bG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9i
# YWxTaWduIFJvb3QgQ0EwHhcNMTgwOTE5MDAwMDAwWhcNMjgwMTI4MTIwMDAwWjBM
# MSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xv
# YmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8RgJDx7KKnQRf
# JMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsTgHeMCOFJ0mpi
# Lx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmmKPZpO/bLyCiR
# 5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zdQQ4gOsC0p6Hp
# sk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZXriX7613t2Sa
# er9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaOCASIwggEeMA4GA1Ud
# DwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSP8Et/qC5FJK5N
# UPpjmove4t0bvDAfBgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzA9Bggr
# BgEFBQcBAQQxMC8wLQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL3Jvb3RyMTAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLmdsb2JhbHNp
# Z24uY29tL3Jvb3QuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIB
# FiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG
# 9w0BAQsFAAOCAQEAI3Dpz+K+9VmulEJvxEMzqs0/OrlkF/JiBktI8UCIBheh/qvR
# XzzGM/Lzjt0fHT7MGmCZggusx/x+mocqpX0PplfurDtqhdbevUBj+K2myIiwEvz2
# Qd8PCZceOOpTn74F9D7q059QEna+CYvCC0h9Hi5R9o1T06sfQBuKju19+095VnBf
# DNOOG7OncA03K5eVq9rgEmscQM7Fx37twmJY7HftcyLCivWGQ4it6hNu/dj+Qi+5
# fV6tGO+UkMo9J6smlJl1x8vTe/fKTNOvUSGSW4R9K58VP3TLUeiegw4WbxvnRs4j
# vfnkoovSOWuqeRyRLOJhJC2OKkhwkMQexejgcDCCBaIwggSKoAMCAQICEHgDGEJF
# cIpBz28BuO60qVQwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2ln
# biBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkds
# b2JhbFNpZ24wHhcNMjAwNzI4MDAwMDAwWhcNMjkwMzE4MDAwMDAwWjBTMQswCQYD
# VQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEpMCcGA1UEAxMgR2xv
# YmFsU2lnbiBDb2RlIFNpZ25pbmcgUm9vdCBSNDUwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC2LcUw3Xroq5A9A3KwOkuZFmGy5f+lZx03HOV+7JODqoT1
# o0ObmEWKuGNXXZsAiAQl6fhokkuC2EvJSgPzqH9qj4phJ72hRND99T8iwqNPkY2z
# BbIogpFd+1mIBQuXBsKY+CynMyTuUDpBzPCgsHsdTdKoWDiW6d/5G5G7ixAs0sdD
# HaIJdKGAr3vmMwoMWWuOvPSrWpd7f65V+4TwgP6ETNfiur3EdaFvvWEQdESymAfi
# dKv/aNxsJj7pH+XgBIetMNMMjQN8VbgWcFwkeCAl62dniKu6TjSYa3AR3jjK1L6h
# wJzh3x4CAdg74WdDhLbP/HS3L4Sjv7oJNz1nbLFFXBlhq0GD9awd63cNRkdzzr+9
# lZXtnSuIEP76WOinV+Gzz6ha6QclmxLEnoByPZPcjJTfO0TmJoD80sMD8IwM0kXW
# LuePmJ7mBO5Cbmd+QhZxYucE+WDGZKG2nIEhTivGbWiUhsaZdHNnMXqR8tSMeW58
# prt+Rm9NxYUSK8+aIkQIqIU3zgdhVwYXEiTAxDFzoZg1V0d+EDpF2S2kUZCYqaAH
# N8RlGqocaxZ396eX7D8ZMJlvMfvqQLLn0sT6ydDwUHZ0WfqNbRcyvvjpfgP054d1
# mtRKkSyFAxMCK0KA8olqNs/ITKDOnvjLja0Wp9Pe1ZsYp8aSOvGCY/EuDiRk3wID
# AQABo4IBdzCCAXMwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMD
# MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFB8Av0aACvx4ObeltEPZVlC7zpY7
# MB8GA1UdIwQYMBaAFI/wS3+oLkUkrk1Q+mOai97i3Ru8MHoGCCsGAQUFBwEBBG4w
# bDAtBggrBgEFBQcwAYYhaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vcm9vdHIz
# MDsGCCsGAQUFBzAChi9odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2Vy
# dC9yb290LXIzLmNydDA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2Jh
# bHNpZ24uY29tL3Jvb3QtcjMuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsG
# AQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAN
# BgkqhkiG9w0BAQwFAAOCAQEArPfMFYsweagdCyiIGQnXHH/+hr17WjNuDWcOe2LZ
# 4RhcsL0TXR0jrjlQdjeqRP1fASNZhlZMzK28ZBMUMKQgqOA/6Jxy3H7z2Awjuqgt
# qjz27J+HMQdl9TmnUYJ14fIvl/bR4WWWg2T+oR1R+7Ukm/XSd2m8hSxc+lh30a6n
# sQvi1ne7qbQ0SqlvPfTzDZVd5vl6RbAlFzEu2/cPaOaDH6n35dSdmIzTYUsvwyh+
# et6TDrR9oAptksS0Zj99p1jurPfswwgBqzj8ChypxZeyiMgJAhn2XJoa8U1sMNSz
# BqsAYEgNeKvPF62Sk2Igd3VsvcgytNxN69nfwZCWKb3BfzCCBugwggTQoAMCAQIC
# EHe9DgW3WQu2HUdhUx4/de0wDQYJKoZIhvcNAQELBQAwUzELMAkGA1UEBhMCQkUx
# GTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2JhbFNpZ24g
# Q29kZSBTaWduaW5nIFJvb3QgUjQ1MB4XDTIwMDcyODAwMDAwMFoXDTMwMDcyODAw
# MDAwMFowXDELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MjAwBgNVBAMTKUdsb2JhbFNpZ24gR0NDIFI0NSBFViBDb2RlU2lnbmluZyBDQSAy
# MDIwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyyDvlx65ATJDoFup
# iiP9IF6uOBKLyizU/0HYGlXUGVO3/aMX53o5XMD3zhGj+aXtAfq1upPvr5Pc+OKz
# GUyDsEpEUAR4hBBqpNaWkI6B+HyrL7WjVzPSWHuUDm0PpZEmKrODT3KxintkktDw
# tFVflgsR5Zq1LLIRzyUbfVErmB9Jo1/4E541uAMC2qQTL4VK78QvcA7B1MwzEuy9
# QJXTEcrmzbMFnMhT61LXeExRAZKC3hPzB450uoSAn9KkFQ7or+v3ifbfcfDRvqey
# QTMgdcyx1e0dBxnE6yZ38qttF5NJqbfmw5CcxrjszMl7ml7FxSSTY29+EIthz5hV
# oySiiDby+Z++ky6yBp8mwAwBVhLhsoqfDh7cmIsuz9riiTSmHyagqK54beyhiBU8
# wurut9itYaWvcDaieY7cDXPA8eQsq5TsWAY5NkjWO1roIs50Dq8s8RXa0bSV6KzV
# SW3lr92ba2MgXY5+O7JD2GI6lOXNtJizNxkkEnJzqwSwCdyF5tQiBO9AKh0ubcdp
# 0263AWwN4JenFuYmi4j3A0SGX2JnTLWnN6hV3AM2jG7PbTYm8Q6PsD1xwOEyp4Lk
# tjICMjB8tZPIIf08iOZpY/judcmLwqvvujr96V6/thHxvvA9yjI+bn3eD36blcQS
# h+cauE7uLMHfoWXoJIPJKsL9uVMCAwEAAaOCAa0wggGpMA4GA1UdDwEB/wQEAwIB
# hjATBgNVHSUEDDAKBggrBgEFBQcDAzASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBQlndD8WQmGY8Xs87ETO1ccA5I2ETAfBgNVHSMEGDAWgBQfAL9GgAr8eDm3
# pbRD2VZQu86WOzCBkwYIKwYBBQUHAQEEgYYwgYMwOQYIKwYBBQUHMAGGLWh0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2NvZGVzaWduaW5ncm9vdHI0NTBGBggrBgEF
# BQcwAoY6aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvY29kZXNp
# Z25pbmdyb290cjQ1LmNydDBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2NvZGVzaWduaW5ncm9vdHI0NS5jcmwwVQYDVR0gBE4wTDBB
# BgkrBgEEAaAyAQIwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2ln
# bi5jb20vcmVwb3NpdG9yeS8wBwYFZ4EMAQMwDQYJKoZIhvcNAQELBQADggIBACV1
# oAnJObq3oTmJLxifq9brHUvolHwNB2ibHJ3vcbYXamsCT7M/hkWHzGWbTONYBgIi
# ZtVhAsVjj9Si8bZeJQt3lunNcUAziCns7vOibbxNtT4GS8lzM8oIFC09TOiwunWm
# dC2kWDpsE0n4pRUKFJaFsWpoNCVCr5ZW9BD6JH3xK3LBFuFr6+apmMc+WvTQGJ39
# dJeGd0YqPSN9KHOKru8rG5q/bFOnFJ48h3HAXo7I+9MqkjPqV01eB17KwRisgS0a
# Ifpuz5dhe99xejrKY/fVMEQ3Mv67Q4XcuvymyjMZK3dt28sF8H5fdS6itr81qjZj
# yc5k2b38vCzzSVYAyBIrxie7N69X78TPHinE9OItziphz1ft9QpA4vUY1h7pkC/K
# 04dfk4pIGhEd5TeFny5mYppegU6VrFVXQ9xTiyV+PGEPigu69T+m1473BFZeIbuf
# 12pxgL+W3nID2NgiK/MnFk846FFADK6S7749ffeAxkw2V4SVp4QVSDAOUicIjY6i
# vSLHGcmmyg6oejbbarphXxEklaTijmjuGalJmV7QtDS91vlAxxCXMVI5NSkRhyTT
# xPupY8t3SNX6Yvwk4AR6TtDkbt7OnjhQJvQhcWXXCSXUyQcAerjH83foxdTiVdDT
# HvZ/UuJJjbkRcgyIRCYzZgFE3+QzDiHeYolIB9r1MIIHbzCCBVegAwIBAgIMcE3E
# /BY6leBdVXwMMA0GCSqGSIb3DQEBCwUAMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUg
# RVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDAeFw0yMjAyMTUxMzM4MzVaFw0yNTAyMTUx
# MzM4MzVaMIHUMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjESMBAGA1UE
# BRMJNTEyMjkxNjQyMRMwEQYLKwYBBAGCNzwCAQMTAklMMQswCQYDVQQGEwJJTDEQ
# MA4GA1UECBMHQ2VudHJhbDEUMBIGA1UEBxMLUGV0YWggVGlrdmExEzARBgNVBAkT
# CjkgSGFwc2Fnb3QxHzAdBgNVBAoTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4xHzAd
# BgNVBAMTFkN5YmVyQXJrIFNvZnR3YXJlIEx0ZC4wggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDys9frIBUzrj7+oxAS21ansV0C+r1R+DEGtb5HQ225eEqe
# NXTnOYgvrOIBLROU2tCq7nKma5qA5bNgoO0hxYQOboC5Ir5B5mmtbr1zRdhF0h/x
# f/E1RrBcsZ7ksbqeCza4ca1yH2W3YYsxFYgucq+JLqXoXToc4CjD5ogNw0Y66R13
# Km94WuowRs/tgox6SQHpzb/CF0fMNCJbpXQrzZen1dR7Gtt2cWkpZct9DCTONwbX
# GZKIdBSmRIfjDYDMHNyz42J2iifkUQgVcZLZvUJwIDz4+jkODv/++fa2GKte06po
# L5+M/WlQbua+tlAyDeVMdAD8tMvvxHdTPM1vgj11zzK5qVxgrXnmFFTe9knf9S2S
# 0C8M8L97Cha2F5sbvs24pTxgjqXaUyDuMwVnX/9usgIPREaqGY8wr0ysHd6VK4wt
# o7nroiF2uWnOaPgFEMJ8+4fRB/CSt6OyKQYQyjSUSt8dKMvc1qITQ8+gLg1budzp
# aHhVrh7dUUVn3N2ehOwIomqTizXczEFuN0siQJx+ScxLECWg4X2HoiHNY7KVJE4D
# L9Nl8YvmTNCrHNwiF1ctYcdZ1vPgMPerFhzqDUbdnCAU9Z/tVspBTcWwDGCIm+Yo
# 9V458g3iJhNXi2iKVFHwpf8hoDU0ys30SID/9mE3cc41L+zoDGOMclNHb0Y5CQID
# AQABo4IBtjCCAbIwDgYDVR0PAQH/BAQDAgeAMIGfBggrBgEFBQcBAQSBkjCBjzBM
# BggrBgEFBQcwAoZAaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# Z3NnY2NyNDVldmNvZGVzaWduY2EyMDIwLmNydDA/BggrBgEFBQcwAYYzaHR0cDov
# L29jc3AuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNvZGVzaWduY2EyMDIwMFUG
# A1UdIAROMEwwQQYJKwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3
# Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMAkGA1UdEwQCMAAw
# RwYDVR0fBEAwPjA8oDqgOIY2aHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9nc2dj
# Y3I0NWV2Y29kZXNpZ25jYTIwMjAuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8G
# A1UdIwQYMBaAFCWd0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTRWDsgBgAr
# Xx8j10jVgqJYDQPVsTANBgkqhkiG9w0BAQsFAAOCAgEAU50DXmYXBEgzng8gv8EN
# mr1FT0g75g6UCgBhMkduJNj1mq8DWKxLoS11gomB0/8zJmhbtFmZxjkgNe9cWPvR
# NZa992pb9Bwwwe1KqGJFvgv3Yu1HiVL6FYzZ+m0QKmX0EofbwsFl6Z0pLSOvIESr
# ICa4SgUk0OTDHNBUo+Sy9qm+ZJjA+IEK3M/IdNGjkecsFekr8tQEm7x6kCArPoug
# mOetMgXhTxGjCu1QLQjp/i6P6wpgTSJXf9PPCxMmynsxBKGggs+vX/vl9CNT/s+X
# Z9sz764AUEKwdAdi9qv0ouyUU9fiD5wN204fPm8h3xBhmeEJ25WDNQa8QuZddHUV
# hXugk2eHd5hdzmCbu9I0qVkHyXsuzqHyJwFXbNBuiMOIfQk4P/+mHraq+cynx6/2
# a+G8tdEIjFxpTsJgjSA1W+D0s+LmPX+2zCoFz1cB8dQb1lhXFgKC/KcSacnlO4SH
# oZ6wZE9s0guXjXwwWfgQ9BSrEHnVIyKEhzKq7r7eo6VyjwOzLXLSALQdzH66cNk+
# w3yT6uG543Ydes+QAnZuwQl3tp0/LjbcUpsDttEI5zp1Y4UfU4YA18QbRGPD1F9y
# wjzg6QqlDtFeV2kohxa5pgyV9jOyX4/x0mu74qADxWHsZNVvlRLMUZ4zI4y3KvX8
# vZsjJFVKIsvyCgyXgNMM5Z4xghFEMIIRQAIBATBsMFwxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdD
# QyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMAIMcE3E/BY6leBdVXwMMA0GCWCG
# SAFlAwQCAQUAoHwwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEILiUBdSHbmeqskw2Jrj0kkWC/H3tuurzrbYJkdKgtHTVMA0GCSqGSIb3
# DQEBAQUABIICALcHBdncq8xW/FBkbuOwmgbN0jWY6btQ0u9zi1z8K900Tc4bu6Pl
# 4ACAUzg1Roz5ogL7/t2G4wpdLSemDxFx2LFhjUjf3Sh66hKkuShLsypaKstprW/V
# iw7Ol/Kh2u+gKzUazebS21dQVgNYmpiKcXAt1/tTUTXfNwe6TrRmBGn7BCETKDc7
# ZB7gx23J7GbuHX9gI6ambfmNZ1GICzgErvwL07Cp/5T5E2iskPLzUOi1ByE04Xk1
# CeslrLDzcHbD+VGcBCgQb8QhnHj82ZcN5Cwy2K7c1Npda4AOmyPIPd1QYLlZ+P4e
# wWfGQdfA/fhUzyGCBeA8GRYWlmTfTQCBQc4ShmqIT1u/cTyTzGFIsiDMyOAn7gZU
# 7+36mkng58LI1bRbQapM1YfkP46R8RJr0lAyhXToawghuJPkv8bIxnUl2ZzuAo5p
# B54M6DycZXgS6T1AgEdQ0cfzZICNj+on7Ot27cUVq9XhaCJhsqcUJYqYDd/qNAy6
# YXrDltBzZOec4RTx1z/J+kwenHwv2sNHJ0EqJzoHsURhEPCCi2d2oq+626tSeBDz
# aNjT4bDo9M/jb68onWFq40okxoUkNUd1UJAfFjNPo9z4cGfGx5I2gjxroCpDH+Y2
# iTGBx0zyfBIP+a8ljT1ErTLRN0mElbldpE3Ox9uZ9obABAU1kKLsS7G3oYIOKzCC
# DicGCisGAQQBgjcDAwExgg4XMIIOEwYJKoZIhvcNAQcCoIIOBDCCDgACAQMxDTAL
# BglghkgBZQMEAgEwgf4GCyqGSIb3DQEJEAEEoIHuBIHrMIHoAgEBBgtghkgBhvhF
# AQcXAzAhMAkGBSsOAwIaBQAEFLOw8Pc44ugLKtH1pzKF11/KMHtmAhRNZg+fF6Ze
# lya2HiiViHiqTz9eSRgPMjAyNDAxMjkyMDA1MThaMAMCAR6ggYakgYMwgYAxCzAJ
# BgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UE
# CxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazExMC8GA1UEAxMoU3ltYW50ZWMgU0hB
# MjU2IFRpbWVTdGFtcGluZyBTaWduZXIgLSBHM6CCCoswggU4MIIEIKADAgECAhB7
# BbHUSWhRRPfJidKcGZ0SMA0GCSqGSIb3DQEBCwUAMIG9MQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMOVmVyaVNpZ24sIEluYy4xHzAdBgNVBAsTFlZlcmlTaWduIFRydXN0
# IE5ldHdvcmsxOjA4BgNVBAsTMShjKSAyMDA4IFZlcmlTaWduLCBJbmMuIC0gRm9y
# IGF1dGhvcml6ZWQgdXNlIG9ubHkxODA2BgNVBAMTL1ZlcmlTaWduIFVuaXZlcnNh
# bCBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTE2MDExMjAwMDAwMFoX
# DTMxMDExMTIzNTk1OVowdzELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVj
# IENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMSgw
# JgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1mdWVVPnYxyXRqBoutV87ABrTxxrDKP
# BWuGmicAMpdqTclkFEspu8LZKbku7GOz4c8/C1aQ+GIbfuumB+Lef15tQDjUkQbn
# QXx5HMvLrRu/2JWR8/DubPitljkuf8EnuHg5xYSl7e2vh47Ojcdt6tKYtTofHjmd
# w/SaqPSE4cTRfHHGBim0P+SDDSbDewg+TfkKtzNJ/8o71PWym0vhiJka9cDpMxTW
# 38eA25Hu/rySV3J39M2ozP4J9ZM3vpWIasXc9LFL1M7oCZFftYR5NYp4rBkyjyPB
# MkEbWQ6pPrHM+dYr77fY5NUdbRE6kvaTyZzjSO67Uw7UNpeGeMWhNwIDAQABo4IB
# dzCCAXMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwZgYDVR0g
# BF8wXTBbBgtghkgBhvhFAQcXAzBMMCMGCCsGAQUFBwIBFhdodHRwczovL2Quc3lt
# Y2IuY29tL2NwczAlBggrBgEFBQcCAjAZGhdodHRwczovL2Quc3ltY2IuY29tL3Jw
# YTAuBggrBgEFBQcBAQQiMCAwHgYIKwYBBQUHMAGGEmh0dHA6Ly9zLnN5bWNkLmNv
# bTA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vcy5zeW1jYi5jb20vdW5pdmVyc2Fs
# LXJvb3QuY3JsMBMGA1UdJQQMMAoGCCsGAQUFBwMIMCgGA1UdEQQhMB+kHTAbMRkw
# FwYDVQQDExBUaW1lU3RhbXAtMjA0OC0zMB0GA1UdDgQWBBSvY9bKo06FcuCnvEHz
# KaI4f4B1YjAfBgNVHSMEGDAWgBS2d/ppSEefUxLVwuoHMnYH0ZcHGTANBgkqhkiG
# 9w0BAQsFAAOCAQEAdeqwLdU0GVwyRf4O4dRPpnjBb9fq3dxP86HIgYj3p48V5kAp
# reZd9KLZVmSEcTAq3R5hF2YgVgaYGY1dcfL4l7wJ/RyRR8ni6I0D+8yQL9YKbE4z
# 7Na0k8hMkGNIOUAhxN3WbomYPLWYl+ipBrcJyY9TV0GQL+EeTU7cyhB4bEJu8LbF
# +GFcUvVO9muN90p6vvPN/QPX2fYDqA/jU/cKdezGdS6qZoUEmbf4Blfhxg726K/a
# 7JsYH6q54zoAv86KlMsB257HOLsPUqvR45QDYApNoP4nbRQy/D+XQOG/mYnb5DkU
# vdrk08PqK1qzlVhVBH3HmuwjA42FKtL/rqlhgTCCBUswggQzoAMCAQICEHvU5a+6
# zAc/oQEjBCJBTRIwDQYJKoZIhvcNAQELBQAwdzELMAkGA1UEBhMCVVMxHTAbBgNV
# BAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVz
# dCBOZXR3b3JrMSgwJgYDVQQDEx9TeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1waW5n
# IENBMB4XDTE3MTIyMzAwMDAwMFoXDTI5MDMyMjIzNTk1OVowgYAxCzAJBgNVBAYT
# AlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3lt
# YW50ZWMgVHJ1c3QgTmV0d29yazExMC8GA1UEAxMoU3ltYW50ZWMgU0hBMjU2IFRp
# bWVTdGFtcGluZyBTaWduZXIgLSBHMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBAK8Oiqr43L9pe1QXcUcJvY08gfh0FXdnkJz93k4Cnkt29uU2PmXVJCBt
# MPndHYPpPydKM05tForkjUCNIqq+pwsb0ge2PLUaJCj4G3JRPcgJiCYIOvn6QyN1
# R3AMs19bjwgdckhXZU2vAjxA9/TdMjiTP+UspvNZI8uA3hNN+RDJqgoYbFVhV9Hx
# AizEtavybCPSnw0PGWythWJp/U6FwYpSMatb2Ml0UuNXbCK/VX9vygarP0q3InZl
# 7Ow28paVgSYs/buYqgE4068lQJsJU/ApV4VYXuqFSEEhh+XetNMmsntAU1h5jlIx
# Bk2UA0XEzjwD7LcA8joixbRv5e+wipsCAwEAAaOCAccwggHDMAwGA1UdEwEB/wQC
# MAAwZgYDVR0gBF8wXTBbBgtghkgBhvhFAQcXAzBMMCMGCCsGAQUFBwIBFhdodHRw
# czovL2Quc3ltY2IuY29tL2NwczAlBggrBgEFBQcCAjAZGhdodHRwczovL2Quc3lt
# Y2IuY29tL3JwYTBABgNVHR8EOTA3MDWgM6Axhi9odHRwOi8vdHMtY3JsLndzLnN5
# bWFudGVjLmNvbS9zaGEyNTYtdHNzLWNhLmNybDAWBgNVHSUBAf8EDDAKBggrBgEF
# BQcDCDAOBgNVHQ8BAf8EBAMCB4AwdwYIKwYBBQUHAQEEazBpMCoGCCsGAQUFBzAB
# hh5odHRwOi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wOwYIKwYBBQUHMAKGL2h0
# dHA6Ly90cy1haWEud3Muc3ltYW50ZWMuY29tL3NoYTI1Ni10c3MtY2EuY2VyMCgG
# A1UdEQQhMB+kHTAbMRkwFwYDVQQDExBUaW1lU3RhbXAtMjA0OC02MB0GA1UdDgQW
# BBSlEwGpn4XMG24WHl87Map5NgB7HTAfBgNVHSMEGDAWgBSvY9bKo06FcuCnvEHz
# KaI4f4B1YjANBgkqhkiG9w0BAQsFAAOCAQEARp6v8LiiX6KZSM+oJ0shzbK5pnJw
# Yy/jVSl7OUZO535lBliLvFeKkg0I2BC6NiT6Cnv7O9Niv0qUFeaC24pUbf8o/mfP
# cT/mMwnZolkQ9B5K/mXM3tRr41IpdQBKK6XMy5voqU33tBdZkkHDtz+G5vbAf0Q8
# RlwXWuOkO9VpJtUhfeGAZ35irLdOLhWa5Zwjr1sR6nGpQfkNeTipoQ3PtLHaPpp6
# xyLFdM3fRwmGxPyRJbIblumFCOjd6nRgbmClVnoNyERY3Ob5SBSe5b/eAL13sZgU
# chQk38cRLB8AP8NLFMZnHMweBqOQX1xUiz7jM1uCD8W3hgJOcZ/pZkU/djGCAlow
# ggJWAgEBMIGLMHcxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jw
# b3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEoMCYGA1UE
# AxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQe9Tlr7rMBz+hASME
# IkFNEjALBglghkgBZQMEAgGggaQwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEE
# MBwGCSqGSIb3DQEJBTEPFw0yNDAxMjkyMDA1MThaMC8GCSqGSIb3DQEJBDEiBCAB
# mOSIUzttY+fBgy5kFg4FIqbV/HOahSkwrmHffNK59DA3BgsqhkiG9w0BCRACLzEo
# MCYwJDAiBCDEdM52AH0COU4NpeTefBTGgPniggE8/vZT7123H99h+DALBgkqhkiG
# 9w0BAQEEggEAn/wwMrbusEHcgq7lmKWsd+SHoPEV4m5PZeihXaVTkyBxA0aW3Mey
# yRTVveOPjcI+5YNsOewLgLzqyIvaEB2jpZQRsgZ1byDAOI7raQkBV8oXoXbrNu6d
# ZDcL9FOuauR6kZ2LwgPZ6N+dJa5/zNnKiBLZ+lxvI1XQgNKnMTqCbXFER0rMvIbp
# b+GthYiSIrsrRs4kcXZgIJosc5fohEjvUz2GslCJaM2XIDTDAn0cJQqjDPsnKrce
# CCe361+tjViiCqDL8lo9x7pYi8nb6fCtPgtHdyhdkTloJ6hIkJAlvG63zgdIddGp
# z4Ah5jvT0f/nQ9HbUJO/cD5myHLFpdIwFg==
# SIG # End signature block
