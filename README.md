# PowerCLI-CloneTemplatesToDataCenters_
Using PoweCLI to clone templates across multiple vCenter's that are not linked. 

# Pseudocode
     - Login into a specified source vCenter using credentials (prompt) or stored credentials (no prompt)
     - This script will convert a template(s) to a VM (we can't clone a template, it must be converted first)
     - If more than one destination vCenter is specified, clone multiple times for each transfer since you can only MOVE a VM <--NOT WORKING YET
     - Clone the VM using a incremental naming convention (eg. SVRTEMPLATE >> SVRTEMPLATE-01)
     - Convert original VM back to template (so it can be used with VRA or deployments)
     - Tag VM with Clone Attributes ('CloneStatus',‘CloneVersion','CloneDate') to identify VM as a cloning template and stop this script from running simutanously
     - Login into a destination vCenter using credentials (prompt) or stored credentials (no prompt)
     - Check If VM exists, then check their Clone Attributes.
     - If VM is not validated continue <--NOT WORKING YET
     
     - Convert any existing Template to VM's to get Clone Attributes, check validatation <--NOT WORKING YET
     - Determine if using Standard or Distributed switch, get a virtual port group (random)
     - Find a host (random)
     - Find Datastore specified
     - Determine space avaliable in datastore <--NOT WORKING YET
     - Move VM to vCenter with progress bar (a long process)
     - If move process took lonager than timeout, reauthenticate using credentials (prompt) or stored credentials (no prompt)
     - Delete VM if not validated from source Clone Attributes (not template yet) <--NOT WORKING YET
     - Move VM to Template folder if exists
     - Rename VM to original template name
     - Covert VM back to Template
     
     
# PARAMETERS
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
     .PARAMETER NoPingCheck
    Ignores the ability to see if vcenter is conencted; this will be a WARNING. This is
    only useful is ICMP is not allowed on the network.
     .PARAMETER IgnoreCerts
    Ignored non-trusted certs including self-signed
