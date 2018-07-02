<#
.SYNOPSIS
    Replicates vmWare templates across multiple
.DESCRIPTION
    This script will clone a template, then move the vm to a destination vCenter
    If more than one destination vCenter is specified it will clone the template multiple
    times
. PARAMETER SourceVC
    Define source vCenter with Templates. Can be multiple (separate by commas within parenthesis)
. PARAMETER SourceTemplates
    Define source Templates names. Must be exact. Can be multiple (separate by commas within parenthesis). 
    Default values are "WINSVR2Ol6STD" and "WINSVR2012R2STD"
.PARAMETER DestinationVCs
    Define source destination vCenter to transfer Templates. Can be multiple (separate by commas within parenthesis)
.PARAMETER DestinationNetwork
    destination Virtual Network Port group name This uses Regex to search
.PARAMETER Datastoresearch
    Search for a datastore name that contains this value Default value is "content"
    uses Regex to search

.PARAMETER TemplateFolder
    Search for a folder in the datastore that contains this value Default is "Template"
    This uses Regex to search.
        If folder is not found, it will clone the template to root directory of cluster
        If folder is not found but template is replacing an existing Template, it will move
        the new template to that folder.
.PARAMETER UseVICredsFile
    If defined, additionally define the CredFile parameter
    If not defined, then credentials are stored with the prompt using Get-Credential commandlet.
.PARAMETER CredFile
    Specify a location of the xml file.
        If file path not found, then it defaults to users temp directory (eg C:\Users\Admin\AppData\Local\Temp\VICreds xml)
        Use a PowerCLI stored credential command This will save a xml with host,username,encrypted password
        Allows script to run with credentials without prompting mutiple times (if needed)
        Before running script load credentials by running PowerCLI commandlet example:
            eg. New-VICredentialStoreItem -Host Passwrd1234 -File C:\temp\creds.xml
        If not defined, then credentials are stored with the prompt using Get-Credential commandlet.
.PARAMETER ForceNewCreds
    If UseVICredsFile switch used, can also force to load new credentials with this switch.
    This WILL delete existing xml file if found
        This is useful if multple destinations vCenters are used but all hosts are loaded in xml file.
        Credentials can be the same
.PARAMETER StoreDifferentDestinationCreds
    If UseVICredsFile switch used, can also force to load dffferent credentials for each host.
.PARAMETER CheckCloneStatus
    When defined, this will check to see if custom VM attributes (for cloning) exists,
    if not it will create them. Then it will set its value according to what stage it
    is in the process
    The custom attribute created are:
        Clonestatus : In the script it will change the value from:
            Cloning,Moving,Completed
        Cloneversion ; In the script it will check the version number and compare them
                        before moving. This version should be updated by another script to get record of template versioning
        CloneDate' : In the script it will change the value to the date the cloned image was last compeleted.
    
    This is useful if the script crashes and never sets the date and leaves the Clonestatus to Cloning or Moving, 
    if the date is older than one day it will ignore the Attribute checks.
.PARAMETER KeepAlive
    I found that if the moving of a VM takes longer than the PowerCLI Configuration
    WebOperationTimeoutSeconds or Vcenter inavtivety timeout, the next Vm to move will fail.
    This will set the WebOperationTimeoutSeconds to the below KeepAliveSecs and try to
    re-authenticate to the vCenter on each move.
.PARAMETER KeepAliveSecs
    Set timeout value for session for PowerCLI configuration
    WebOperationTimeoutSeconds. Default is "43200" [12 hours]
. PARAMETER NoPingCheck
    Ignores the ability to see if vcenter is conencted; this will be a WARNING. This is
    only useful is ICMP is not allowed on the network.
.PARAMETER IgnoreCerts
    Ignored non-trusted certs including self-signed
. EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -Command "& { & '.\Clone-TemplatesToDataCenters_v3.ps1' -UseVICredsFile 'C:\creds.xml'}"
. EXAMPLE
    '.\Clone-TemplatesToDataCenters_v3.psl -CheckCloneStatus -CheckCloneVersion
.EXAMPLE
    .\Clone4TemplatesToDataCenters_v3.psl -UseVICredsFile -KeepAlive -NoPingCheck
.NOTES
    To reduce downtime; script is designed to convert template to vm, then clone them multiple times if needed
    Then convert the vm back to template for use. The clone VM's will be transfered to their destination one at a time
    At the destination, the old template (if found) will be deleted and the new cloned VM will be renamed and converted as the new template
. LINK
    http://www.powershellcrack.com
#>
[CmdletBinding()]
    Param (
    [string]$SourceVC = "$Env:COMPUTERNAME",
    [String[]]$SourceTemplates = @('WINSVR2016STD','WINSVR2012R2STD'),
    [String[]]$DestinationVCs = @($Env:COMPUTERNAME),
    [string]$DestinationNetwork,
    [string]$DatastoreSearch = ‘content’,
    [string]$TemplateFolder = 'Template‘,
    [switch]$UseVICredsFile,
    [string]$CredsFile,
    [switch]$ForceNewCreds,
    [switch]$TestNewCredsOnly,
    [switch]$StoreDifferentDestinationCreds,
    [switch]$CheckCloneStatus,
    [switch]$KeepAlive,
    [int32]$KeepAliveSecs = 43200,
    [switch]$NoPingCheck,
    [switch]$IgnoreCerts
)
##*=============================================
## * FUNCTIONS
##*=============================================
#time-lapse formatter
Function FormatElapsedTime($ts) {
    $elapsedTime = ""
    if ( $ts.Minutes -gt 0 ){$elapsedTime = [string]::Format( "{0:00} min. {1:00}.{2:00}sec.", $ts.Minutes, $ts.Seconds, $ts.Milliseconds / 10 );}
    else{$elapsedTime = [string]::Format( "{0:00}.{1:00} sec.", $ts.Seconds, $ts.Milliseconds / 10 );}
    if ($ts.Hours -eq 0 -and $ts.Minutes -eq 0 -and $ts.Seconds -eq 0){$elapsedTime = [string]::Format("{0:00} ms.", $ts.Milliseconds);}
    if ($ts.Milliseconds -eq 0){$elapsedTime = [string]::Format("{0} ms", $ts.TotalMilliseconds);}
    return $elapsedTime
}

Function Format-ServerNameOutput {
    Param (
    [Parameter(Mandatory=$true)]
    [string]$VCHost
    )
    $ShortName = $VCHost.split(".")[0]
    $addspace = 20 - $Shortname.length
    $newName = $shortName + (' ' * $addspace)
    return $newName.ToUpper()
}

Function Store-VICreds{
    Param (
    [Parameter(Mandatory=$true)]
    [string]$VCHost,
    [Parameter(Mandatory=$true)]
    [string]$File,
    [strinq]$Username,
    [string]$Password,
    [switch]$VerifyOnly,
    [switch]$ReturnCreds
    )
    #clear variables just in case
    Clear-Variable Usernamelnput -ErrorAction SilentlyContinue
    Clear-Variable SecurePassword -ErrorAction SilentlyContinue
    Clear-Variable Passwordlnput -ErrorAction SilentlyContinue
    Clear-Variable NewCreds -ErrorAction SilentlyContinue

    $HostShortName = Format-ServerNameOutput -VCHost $VCHost
    If((!$Username-or !$Password) -and (!$VerifyOnly) ){
    
        Write-host("{0} INFO: Credential input is required to connect to [{1}] prompting" -f $ComputerShortName,$VCHost) -ForegroundColor Gray
        Start-sleep 3
        $UsernameInput = Read-Host -Prompt ("{0} PROMPT UserName [eg. $env:USERDNSDOMAIN\DomainAccount]" -f $HostShortName)
        #To mask the password, Read-Host's AsSecureString parameter must be set AsSecureString
        $SecurePassword = Read-Host -AsSecureString -Prompt ("{0} PROMPT Password" -f $HostShortName)
        #but it needs to be decrypted for PowerCLI to encrypt it with its cipher
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $PasswordInput = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }

    Try{
        If($VerifyOnly){
            $NewCreds = Get-VICredentialStoreItem -Host $VCHost -File $File -ErrorAction SilentlyContinue
            If($NewCreds){
                Write-host ("{0} SUCCESS: User [{2}] credentials exist for vCenter [{1}]" -f $ComputerShortName,$NewCreds.Host,$NewCreds.User) -ForegroundColor Green
            }Else{
                Write-host ("{0} WARNING: User [{2}] credentials do not exist for vCenter[{1}]" -f $ComputerShortName,$NewCreds.Host,$NewCreds.User) -ForegroundColor Yellow
            }
        } Else{
            New-VICredentialStoreItem -Host $VCHost -User $UsernameInput Password $PasswordInput -File $File | Out-Null
            $NewCreds = Get-VICredentialStoreItem -Host $VCHost -User $UsernameInput -File $File
            Write-host ("{0} SUCCESS: Stored User [{2}] credentials for vCenter [{1}]" -f $ComputerShortName,$NewCreds.Host,$NewCreds.User) -ForegroundColor Green
        }
        If($ReturnCreds){
            return $NewCreds
        }
    }Catch{
        Write-host("{0} ERROR: Error loading credentials" -f $ComputerShortName) -ForegroundColor Red
        Throw $_.Exception.Message
    }
    
}

Function Check-CloneStatusAttribute{
Param (
    [Parameter(Mandatory=$true)]
    [string]$VCHost,
    [Parameter(Mandatory=$false)]
    [string]$VM,
    [Parameter(Mandatory=$true)]
    [string]$CustomAttribute,
    [Parameter(Mandatory=$false)]
    [string]$SetValue,
    [Parameter(Mandatory=$false)]
    [switch]$ReturnValue
    )

    $HostShortName = Format-ServerNameOutput -VCHost $VCHost
    $VCAttributes = Get-CustomAttribute -TargetType VirtualMachine -Server $VCHost
    
    If($VCAttributes.Name -match $CustomAttribute){
        Write-host ("{0} INFO: Custom Attribute found [{1}]" -f $HostShortName,$CustomAttribute) -ForegroundColor Gray
    }Else{
        New-CustomAttribute -Name $CloneAttributeName -Server $VCHost -TargetType VirtualMachine
        Write-host ("{0} SUCCESS: Custom Attribute created [{1}]" -f $HostShortName,$CustomAttribute) -ForegroundColor Green
    }

    If($VM -and ($SetValue -or $ReturnValue) ){
        $VMExist = Get-VM -Name SVM -Server $VCHost -ErrorAction SilentlyContinue
        If($VMExist){
            If($SetValue){
                $Value = $VMExist | Set-Annotation -CustomAttribute $CustomAttribute -Value $SetValue
                Write-host ("{0} SUCCESS: Custom Attribute [{1}] value was set to [{2}]" -f $HostShortName,$CustomAttribute,$Value) -ForegroundColor Green
            }Else{
                $Value = $VMExist.CustomFields[$CustomAttribute]
                Write-host ("{0} INFO: Custom Attribute [{1}] value is [{2}]" -f $HostShortName,$CustomAttribute,$Value) -ForegroundColor Gray
            }
        }
    }
    If($ReturnValue){return $Value}
}

##*===============================================
## * VARIABLE DECLARATION
##*===============================================
$StartTime = Get-Date
$ComputerShortName = Format-ServerNameOutput -VCHost $Env:COMPUTERNAME
$SourceVCShortName = Format-ServerNameOutput -VCHost $SourceVC

Write-Host ("{0} INFO: Loading VMware.PowerCLI PowerShell Modules" -f $ComputerShortName) -ForegroundColor Gray
$PCLIModule = Import-Module Vmware.VimAutomation.Core -ErrorAction Stop -Force -Passthru
If($KeepAlive){
    Set-PowerCLIConfiguration -Scope Session -WebOperationTimeoutSeconds $KeepAliveSecs -DefaultVIServerMode Multiple -Confirm:$false | Out-Null
}
Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -DefaultVIServerMode Multiple -Confirm:$false | Out-Null
Write-Host ("{0} INFO: Configured PowerCLI to suppport Mutiple server connections" -f $ComputerShortName) -ForegroundColor Gray

[string]$PCLIVersion = $PCLIModule.Version
Write-Host ("{0} SUCCESS: VMware.PowerCLI Modules [{1}] were loaded successfully" -f $ComputerShortName,$PCLIVersion) -ForegroundColor Green

$CloneAttributes = @('CloneStatus',‘CloneVersion','CloneDate')
$DefaultCredFile = Join-Path $Env:Temp -ChildPath 'VICreds.xml'

#clear Variables
Clear-Variable task -ErrorAction SilentlyContinue
Clear-Variable SourceVCSession -ErrorAction SilentlyContinue

##*=============================================
##* MAIN SCRIPT = DO NOT MODIfY
##*=============================================
#disable certificate validation and trust all certs (even self-signed)
If($IgnoreCerts){
Add-Type @"
    using System.Net; T
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy
    {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem){
            return true;
        }
    }
"@
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
[Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

##*============================
##* PING CHECK
##*============================
# check to see if ALL vCenter servers are pingable before continuing
If($NoPingCheck){
    Write-Host ("{0} WARNING: vCenter [{1}] will not tested for connectivity. Script may fail..." -f $ComputerShortName,$SourceVC) -ForegroundColor Yellow
}Else{
    If(!(Test-Connection $SourceVC -Count 1)){
        Write-Host ("{0} ERROR: Unable to ping vCenter [{1}], check network connectivity" -f $ComputerShortName,$SourceVC) -ForegroundColor Red
        Exit -1
    }
}
    
ForEach($DestinationVC in $DestinationVCs){
    If($NoPingCheck){
        Write-host ("{0} WARNING: vCenter [{1}] will not tested for connectivity. Script may fail..." -f $ComputerShortName,$DestinationVC) -ForegroundColor Yellow
    }Else{
        If(!(Test-Connection $DestinationVC -Count 1)){
            Write-Host ("{0} ERROR: Unable to ping vCenter [{1}], check network connectivity" -f $ComputerShortName,$DestinationVC) -ForegroundColor Red
            Exit -1
        }
    }
}


##*============================
##* CREDENTIAL CHECK
##*============================

If($UseVICredsFile){
    #See if xml file exists, then check it for stored credentials
    If($CredsFile){
        $VICredFile = $CredsFile
    }Else{
        $VICredFile = $DefaultCredFile
    }

    $CredFileExists = Test-Path $VICredFile -ErrorAction SilentlyContinue
    If($ForceNewCreds -and $CredFileExists){Remove-item $VICredFile -Force -ErrorAction SilentlyContinue | Out-Null;$CredFileExists = $null}
    
    #If the credential file is not found, load new credentials
    If($CredFileExists){
        #delete specified credential file to start fresh
        #$StoredCreds = Get-VICredentialStoreItem -Host $SourceVC -File $VICredFile -ErrorAction SilentlyContinue | Select -First 1
        $StoredCreds = Store-VICreds -VCHost $SourceVC -File $VICredFile -VerifyOnly -ReturnCreds
    }Else{
        $StoredCreds = Store-VICreds -VCHost $SourceVC -File $VICredFile -ReturnCreds
    }
    
    #loop through all destination vCenters.
    #must create destination entries even if username/password is the same
    ForEach($DestinationVC in $DestinationVCs){
        #if different credentials are needed for destination, prompt. Otherwise use already stored credentials
        If($StoreDifferentDestinationCreds){
            #$StoredCreds = Get-VICredentialStoreItem -Host $DestinationVC -File $VICredFile -ErrorAction SilentlyContinue
            $StoredCreds = Store-VICreds -VCHost $SourceVC -File $VICredFile -VerifyOnly -ReturnCreds
            If(!$StoredCreds){
                Write-host ("{0} WARNING: Unable to find stored credentials for vCenter Server [{1}]" -f $ComputerShortName,$DestinationVC) -ForegroundColor Yellow
                $StoredCreds = Store-VICreds -VCHost $DestinationVC -File $VICredFile -ReturnCreds
            }Else{
                Write-host ("{0} SUCCESS: Found stored credentials for vCenter Server [{1}]" -f $ComputerShortName,$DestinationVC) -ForegroundColor Green
            }
        }
    }

}Else{
    Write-host ("{0} WARNING: Credentials required to connect to vCenter servers, prompting" -f $ComputerShortName) -ForegroundColor Yellow
    Start-Sleep 3
    $Credentials = Get-Credential -Message "Specify credentials for All vCenters" -ErrorAction Stop
    $AllCredsFound = $true
}
##*============================
##* SOURCE VCENTER CONNECTION
##*============================
#connect to to source vCenter using either session credentials or stored credentials
#if fails to connect throw an error
Try{
    If($UseVICredsFile){
        Write-host ("{0} INFO: Connecting to vCenter [{1}] with stored credentials [{2}]" -f $SourceVCShortName,$SourceVC,$StoredCreds.User) -ForegroundColor Gray
        $SourceVCConn = Connect-VIServer -Server $SourceVC -User $StoredCreds.User -Password $StoredCreds.Password -ErrorAction Stop
    }Else{
        Write-host ("{0} INFO: Connecting to vCenter [{1}] with session credentials [{2}]" -f $SourceVCShortName,$SourceVC,$Credentials.UserName) -ForegroundColor Gray
        $SourceVCConn = Connect-VIServer -Server $SourceVC -Credential $Credentials -ErrorAction Stop
    }
    Write-host ("{0} SUCCESS: Connected to vCenter [{1}]" -f $SourceVCShortName,$SourceVC) -ForegroundColor Green

    If($KeepAlive){
        $SourceVCSession = $SourceVCConn.SessionId
        Write-host ("{0} INFO: Using session id [{1}]" -f $SourceVCShortName,$SourceVCSession) -ForegroundColor Gray
    }

    #check if custom attributes are created at the source vCenter, if not do so
    If($CheckCloneStatus){
        Foreach($Attribute in $CloneAttributes){
            Check-CloneStatusAttribute -VCHost $SourceVC -CustomAttribute $attribute
        }
    }
}Catch{
    Write-host ("{0} ERROR: Unable to connect to vCenter [{1}]" -f $SourceVCShortName,$SourceVC) -ForegroundColor Red
    Throw $_.Exception.Message
}
##*============================
##* PROCESS SOURCE TEMPLATES
##*============================
If(!$TestNewCredsOnly){
    
    #build Empty Array
    $newVMs = @()
    $suffix = 01
    ForEach($TemplateName in $SourceTemplates){
        #build new name for copy process
        $cloneName = $TemplateName+'-01'
        #if copy VM is found, remove it to start fresh
        $cloneVMExists = Get-VM -Name $cloneName -Server $SourceVC -ErrorAction SilentlyContinue
        If($CloneVMExists){
            $cloneVMStatus = Check-CloneStatusAttribute -VCHost $SourceVC -VM $cloneName -CustomAttribute $CloneAttributes[0] -Returnvalue
            $CloneVMVersion = Check-CloneStatusAttribute -VCHost $SourceVC -VM $CloneName -CustomAttribute $CloneAttributes[1] -Returnvalue
            $CloneVMDate = Check-CloneStatusAttribute -VCHost $SourceVC -VM $CloneName -CustomAttribute $CloneAttributes[2] -ReturnValue
            If( (($CloneStatus -eq 'Cloning') -or ($CloneStatus -eq 'Moving')) -and ($cloneVMate -lt $StartTime.AddDays(-1)) ){
                Write-host ("{0} INFO: Clone VM [{1}] was found, but is currently beingn cloned by another process" -f $SourceVCShortName,$CloneName) -ForegroundColor Gray
            }Else{
                Write-host ("{0} INFO: Clone VM [{1}] was found" -f $SourceVCShortName,$CloneName) -ForegroundColor Gray
                Write-host ("{0} WARNING: Removing Clone VM [{1}]" -f $SourceVCShortName,$CloneName) -ForegroundColor Yellow
                Try{
                    $task = Remove-VM -VM $CloneName -Server $SourceVC -Confirm:$false -DeletePermanently:$true -ErrorAction Stop -RunAsync
                    Wait-Task -Task $task | Out-Null
                    Write-host ("{0} SUCCESS: Successfully removed VM [{1}]" -f$SourceVCShortName,$CloneName) -ForegroundColor Green
                }Catch{
                    Write-host ("{0} ERROR: Failed to remove VM [{1}]" -f $SourceVCShortName,$CloneName) -ForegroundColor Red
                    Throw $_.Exception.Message
                }
            }
        }
    
        $VMAsNonTemplateExists = Get-VM -Name $TemplateName -Server $SourceVC -ErrorAction SilentlyContinue
        If($VMAsNonTemplateExists){
            #reset original vm back to template
            Write-host ("{0} INFO: Template is currently a VM [{1}] changing back to a Template to continue" -f $SourceVCShortName,$VMAsNonTemplateExists.Name) -ForegroundColor Gray
        
            $task = Set-VM -VM $VMAsNonTemplateExists -ToTemplate -Server $SourceVC -Confirm:$false -RunAsync
                    Wait-Task -Task $task | Out-Null
        
            #Convert Templates to VM
            $TemplateExists = Get-template -Name $TemplateName -Server $SourceVC -ErrorAction SilentlyContinue
            If($TemplateExists){
                Write-host ("{0} INFO: Converting Template [{1}] to VM" -f $SourceVCShortName,$TemplateName) -ForegroundColor Gray
                $task = Set-Template -Template $TemplateName -ToVM -Server $SourceVC -Confirm:$false -ErrorAction Stop -RunAsync
                        Wait-Task -Task Stask | Out-Null
            }
    
            #to build a new VM, we must get a resource host and datastore.
            #in $ResourcePool you can specify ESX host, cluster or resource pool
            #select source hosts and datastore used to clone template
            $VMHosts = Get-VMHost -Server $SourceVC | Where {$_.ConnectionState -match 'Connected' -and $_.PowerState -match 'PoweredOn‘}
        
            #get random VMhost
            $ResourcePool = $VMHosts[(Get-Random -Maximum ($VMHosts).count)]
            $datastore = Get-Datastore -Server $SourceVC | Where {$_.Name -match $datastoreSearch} | Select -First 1
            Write-host ("{0} INFO: Connected to host [{1}] on datastore [{2}]" -f $SourceVCShortName,$ResourcePool.Name,$datastore.Name) -ForegroundColor Gray
            #build a new VM

            Write-Host ("{0} INFO: Cloning new VM [{1}]" -f $SourceVCShortName,$cloneName) -ForegroundColor Gray
            Try{
                $task = New-VM -Name $CloneName -VM $TemplateName -ResourcePool $ResourcePool -Datastore $datastore -DiskStorageFormat Thin -Server $SourceVC -ErrorAction Stop-RunAsync
                        Wait-Task -Task $task | Out-Null
                Write-Host ("{0} SUCCESS: Successfully cloned VM [{1}]" -f $SourceVCShortName,$CloneName) -ForegroundColor Green
            }Catch{
                Write-Host ("{0} ERROR: Failed to cloned VM [{1}]" -f $SourceVCShortName,$CloneName) -ForegroundColor Red
                Throw $_.Exception.Message
            }
        
            #get the new cloned Vm from source vCenter
            $vm = Get-VM $cloneName -Server $SourceVC
            $networkAdapter = Get-NetworkAdapter -VM $vm -Server $SourceVC
        
            #reset original vm back to template
            Write-Host ("{0} INFO: Converting VM [{1}] back to a Template" -f $SourceVCShortName,$TemplateName) -ForegroundColor Gray
            $task = Set-VM -VM $TemplateName -ToTemplate -Server $SourceVC -Confirm:$false -RunAsync
                    Wait-Task -Task $task | Out-Null
        
            # Collect an object that has the new VM information
            #this is used later on when move-VM command
            $NewVMs += new-object psobject -property @{
                    VMSourceName=$TemplateName
                    VMCloneName=$CloneName
                    NetworkAdapter=$networkAdapter
                    }
        }
    }
}
##*============================
##* MOVE AND PROCESS TEMPLATES ON DESTINATIQN VCENTERS
##*============================
ForEach($DestinationVC in $DestinationVCs){
    
    $DestVCShortName = Format-ServerNameOutput -VCHost $DestinationVC
    #connect to destination
    Try{
        If($UseVICredsFile){
            Write-Host ("{0} INFO: Connecting to vCenter [{1}] with stored credentials [{2}]" -f $DestVCShortName,$DestinationVC,$StoredCreds.User) -ForegroundColor Gray
            $destVCConn = Connect-VIServer -Server $DestinationVC -User $StoredCreds.User -Password $StoredCreds.Password -ErrorAction Stop
        }Else{
            Write-Host ("{0} INFO: Connecting to vCenter [{1}] with session credentials [{2}]" -f $DestVCShortName,$DestinationVC,$Credentials.UserName) -ForegroundColor Gray
            $destVCCOnn = Connect-VIServer -Server $DestinationVC -Credential $credentials -ErrorAction Stop
        }
        Write-Host ("{0} SUCCESS: Connected to vCenter [{1}]" -f $DestVCShortName,$DestinationVC) -ForegroundColor Green
    
        If($KeepAlive){
            $destVISession = $destVCConn.SessionId
            Write-Host ("{0} INFO: Using session id [{1}]" -f $DestVCShortName,$destVISession) -ForegroundColor Gray
        }
    }Catch{
        Write-Host ("{0} ERROR: Unable to connect to vCenter [{1}]" -f $DestVCShortName,$DestinationVC) -ForegroundColor Red
        Throw $_.Exception.Message
    }

    If(!$TestNewCredsOnly){
        #check if custom attributes are created at the destination, if not do so
        If($CheckCloneStatus){
            Foreach($Attribute in $CloneAttributes){
                Check-CloneStatusAttribute -VCHost $DestinationVC -CustomAttribute $attribute
            }
        }
        
        #Connect to destination vCenter host that is not in Maintenance mode or powered off
        #$destination = Get-VMHost -Server $DestinationVC | Where.{$_.ConnectionState -match 'Connected' -and $_.PowerState -match 'PoweredOn'} | Select -First 1
        $VMHosts = Get-VMHost -Server $DestinationVC | Where {$_.ConnectionState -match 'Connected' -and $_.PowerState -match 'PoweredOn'}
        #get random VMhost
        $DestResourcePool = $VMosts[(Get-Random -Maximum ($VMHosts).count)]
        Write-host ("{0} INFO: Connected to host [{1}]" -f $DestVCShortName,$DestResourcePool.Name) -ForegroundColor Gray
        
        #If DestinationNetwork Parameter specified, determine if it exists.
        If($DestinationNetwork){
            $destNetName = Get-VirtualPortGroup -Server $DestinationVC -VMHost $DestResourcePool | Where {$_.Name -match $DestinationNetwork}
        }
        
        #If DestinationNetwork Parameter not found or specified, get any virtual port group except VM Network and Management Network.
        If(!$destNetName){
            $FoundNetworks = Get-VirtualPortGroup -Server $DestinationVC -VMHost $DestResourcePool | Where {$_.Name -ne "VM Network" -and $_.Name -ne "Management Network"}
            $destNetName = $FoundNetworks[(Get-Random -Maximum ($FoundNetworks).count)]
        }
        Write-Host ("{0} INFO: Connected to Virtual Network Port Group [{1}]" -f$DestVCShortName,$destNetName.Name) -ForegroundColor Gray

        #determine if Distributed or standard switch is used
        # retrieve the network name
        $IsDistributedSwitch = Get-VirtualPortGroup -Server $DestinationVC | Where {$_.Key -like "dvportgroup-*"}
        If($IsDistributedSwitch){
            $DestSwitchName = Get-VDSwitch -Server $DestinationVC
            $DestPortGroup = Get-VDPortgroup -VDSwitch $DestSwitchName -Name $destNetName -Server $DestinationVC
            Write-Host ("{0} INFO: vCenter Server is configured with distributed switches" -f $DestVCShortName) -ForegroundColor Gray
        }
        Else{
            $DestSwitchName = Get-VirtualSwitch -Server $DestinationVC -VMHost $DestResourcePool
            $DestPortGroup = Get-VirtualPortgroup -VirtualSwitch $DestSwitchName -Name $destNetName -Server $DestinationVC
            Write-Host ("{0} INFO: vCenter Server is configured with standard switches" -f $DestVCShortName) -ForegroundColor Gray
        }

        Write-Host ("{0} INFO: Connecting to switch [{1}] on port group [{2}]" -f $DestVCShortName,$DestSwitchName.Name,$DestPortGroup.Name) -ForegroundColor Gray
        #Search for the datastore if exists
        $DestDatastore = Get-Datastore -Server $DestinationVC | Where {$_.Name -match $datastoreSearch}
        
        If($DestDataatore){
            Write-Host ("{0} INFO: Connected to host [{1}] on datastore [{2}]" -f $DestVCShortName,$DestResourcePool.Name,$DestDatastore.Name) -ForegroundColor Gray
            
            #Parse custom PS object built above
            Foreach($vm in $NewVMs){
                
                #move cloned Vm to new vCenter
                Write-Host ("{0} WARNING: Moving cloned VM [{1}] to destination vCenter [{2}]" -f $SourceVCShortName,$vm.VMCloneName,$DestinationVC) -ForegroundColor Yellow
                Write-Host ("{0} INFO: This can take awhile, please wait..." -f $SourceVCShortName) -ForegroundColor Gray
                
                $time = [System.Diagnostics.Stopwatch]::StartNew()
                $task = Move-VM -VM $vm.VMCloneName -Destination $DestResourcePool -NetworkAdapter $vm.NetworkAdapter -PortGroup $DestPortGroup -Datastore $DestDatastore -Server $SourceVC -ErrorAction Stop -RunAsync
                        #present a progress bar while waiting for task to complete
                        Wait-Task -Task $task | Out-Null
                
                #when task completes, get status
                #switch($task.State){
                # 'Success' { $task.result; Write-Host ("Successfully moved cloned VM [{0}] to [{1}].‘nRelocation took: {2}" -f $vm.VMCloneName,$DestinationVC,$sw) -ForegroundColor Green}
                # 'Error' {throw $task.ExtensionData.INFO.Error.LocalizedMessage; Continue}
                #} '

                #stop timer to get measure time
                $time.Stop()
                $sw = FormatElapsedTime($time.Elapsed)
                Start-Sleep 10
                
                $ClonedVM = Get-VM -Name $vm.VMCloneName -Server $DestinationVC -ErrorAction Silentlycontinue
                If($ClonedVM){
                    Write-Host ("{0} SUCCESS: Cloned VM [{1}] was successfully moved to [{2}]" -f $SourceVCShortName,$CloneName,$DestinationVC) -ForegroundColor Green
                    Write-Host ("{0} INFO: Relocation took: [{1}]" -f $SourceVCShortName,$sw) -ForegroundColor Gray
                }Else{
                    Write-Host ("{0} ERROR: Failed to move VM [{1}]" -f $SourceVCShortName,$CloneName) -ForegroundColor Red
                    #Throw $_.Exception.Message
                }
                
                If($KeepAlive){
                    Disconnect-VIServer -Server $DestinationVC -Confirm:$false | Out-Null
                    Try{
                        If($UseVICredsFile){
                            $SourceVCConn = Connect-VIServer -Server $SourceVC -User $StoredCreds.User -Password $StoredCreds.Password -Session $SourceVCSession
                            $destVCConn = Connect-VIServer -Server $DestinationVC -User $StoredCreds.User -Password $StoredCreds.Password -Session $destVISession
                        }Else{
                            $SourceVCConn = Connect-VIServer -Server $SourceVC -Credential $Credentials -Session $SourceVCSession
                            $destVCConn = Connect-VIServer -Server $DestinationVC -Credential $credentials -Session $SourceVCSession
                        }
                    }Catch{
                        Write-Host ("{0} ERROR: Unable to re-connect to vCenter [{1}]" -f $DestVCShortName,$DestinationVC) -ForegroundColor Red
                        Throw $_.Exception.Message
                    }
                }

                #delete VM is it exists
                $existingVM = Get-VM -Name $vm.VMSourceName -Server $DestinationVC -ErrorAction SilentlyContinue
                If($existingVM){
                    Write-host ("{0} INFO: Clone VM [{1}] was found" -f $DestVCShortName,$vm.VMSourceName) -ForegroundColor Gray
                    Write-Host ("{0} WARNING: Removing Clone VM [{1}]" -f $DestVCShortName,$vm.VMSourceName) -ForegroundColor Yellow
                    Try{
                        $task = Remove-VM -VM $vm.VMSourceName -Confirm:$false -DeletePermanently:$true -Server $DestinationVC -ErrorAction Stop -RunAsync
                        Wait-Task -Task $task | Out-Null
                        Write-host ("{0} SUCCESS: Successfully removed VM [{1}]" -f $DestVCShortName,$vm.VMSourceName) -ForegroundColor Green
                    }Catch{
                        Write-host ("{0} ERROR: Failed to remove VM [{1}]" -f $DestVCShortName,$vm.VMSourceName) -ForegroundColor Red
                        Throw $_.Exception.Message
                    }
                }

                #delete Template is it exists
                $existingTP | Get-Template -Name $vm.VMSourceName -Server $DestinationVC -ErrorAction SilentlyContinue
                If($existingTP){
                    #get folder template resides in
                    $currentTPfolder = (Get-Folder | Where {$_.ParentID -eq $existingTP.FolderId}).Parent.Name
                    #Write-host "Template was found, removing..." -ForegroundColor Yellow
                    Write-host ("{0} INFO: Template [{1}] was found" -f $DestVCShortName,$vm.VMSourceName) -ForegroundColor Gray
                    Write-host ("{0} WARNING: Removing Template [{1}]" -f $DestVCShortName,$vm.VMSourceName) -ForegroundColor Yellow
                    Try{
                        $task = Remove-Template -Template $vm.VMSourceName -Confirm:$false -DeletePermanently:$true -Server $DestinationVC -ErrorAction Stop -RunAsync
                                Wait-Task -Task $task | Out-Null
                        Write-Host ("{0} SUCCESS: Successfully removed Template [{1}]" -f $DestVCShortName,$vm.VMSourceName) -ForegroundColor Green
                    }Catch{
                        Write-Host ("{0} ERROR: Failed to remove Template [{1}]" -f $DestVCShortName,$vm.VMSourceName) -ForegroundColor Red
                        Throw $_.Exception.Message
                    }
                }

                #rename cloned vm to original
                Write-host ("{0} INFO: Renaming VM [{1}] to [{2}]" -f $DestVCShortName,$vm.VMCloneName,$vm.VMSourceName) -ForegroundColor Gray
                $task = Get-VM -Name $vm.VMCloneName -Server $DestinationVC | Set-VM -Name $vm.VMSourceName -Confirm:$false -ErrorAction Stop -RunAsync
                        Wait-Task -Task $task | Out-Null
                
                #move VM if templates folder exists
                If(!$currentTPFolder){$currentTPFolder = Get-Folder -Server $DestinationVC | Where {$_.Name -match "$TemplateFolder"}}
                If($currentTPFolder){
                    Write-host ("{0} INFO: {1} folder was found, moving VM to folder" -f $DestVCShortName,$currentTPfolder.Name) -ForegroundColor Gray
                    $task = Get-VM -Name $vm.VMSourceName -Server $DestinationVC | Move-VM -InventoryLocation $currentTPFolder -ErrorAction Stop -RunAsync
                            Wait-Task -Task $task | Out-Null
                }
                
                #convert cloned VM to template
                $task = Set-VM -VM $vm.VMSourceName -ToTemplate -Server $DestinationVC -Confirm:$false -ErrorAction Stop -RunAsync
                        Wait-Task -Task $task | Out-Null
                Write-Host ("{0} SUCCESS: Converted VM [{1}] to a Template" -f $DestVCShortName,$vm.VMSourceName) -ForegroundColor Green
            }#end vm loop
        }
        Else{
            Write-Host ("{0} ERROR: Unable to connect to the a datastore with [{1}] in the name" -f $DestVCShortName,$datastoreSearch) -ForegroundColor Red
            Continue
        }
    }
    ##*=================
    ##* COMPLETED MOVE
    ##*=================
    Write-Host ("{0} SUCCESS: Cloning Template script completed" -f $ComputerShortName) -ForegroundColor Green
    
    #disconnect
    Disconnect-VIServer -Server $DestinationVC -Confirm:$false | Out-Null
    Write-host ("{0} INFO: Disconnecting from vCenter Server [{1}]" -f $DestVCShortName,$DestinationVC) -ForegroundColor Gray
    
    #If($KeepAlive){
    # Remove-VICredentialStoreItem -Host $SourceVC -Confirm:$false
    # Remove-VICredentialStoreItem -Host $DestinationVC -Confirm:$false
    #}
}
Disconnect-VIServer -Server $SourceVC -Confirm:$false | Out-Null
Write-host ("{0} INFO: Disconnecting from vCenter Server [{1}]" -f $SourceVCShortName,$SourceVC) -ForegroundColor Gray