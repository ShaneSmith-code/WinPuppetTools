$RegHiveType = data 
{
    ConvertFrom-StringData @'
    HKEY_CLASSES_ROOT = hkcr
    HKEY_LOCAL_MACHINE = hklm
    HKEY_USERS = hku
    HKEY_CURRENT_USER = hkcu
'@
}

$PuppetRegType = Data
{
    ConvertFrom-StringData @'
    REG_SZ = string
    REG_MULTI_SZ = array
    REG_EXPAND_SZ = expand
    REG_DWORD = dword
    REG_QWORD = qword
    REG_BINARY = binary
'@
}

Enum RegType {
    REG_NONE                       = 0	# No value type
    REG_SZ                         = 1	# Unicode null terminated string
    REG_EXPAND_SZ                  = 2	# Unicode null terminated string (with environmental variable references)
    REG_BINARY                     = 3	# Free form binary
    REG_DWORD                      = 4	# 32-bit number
    REG_DWORD_LITTLE_ENDIAN        = 4	# 32-bit number (same as REG_DWORD)
    REG_DWORD_BIG_ENDIAN           = 5	# 32-bit number
    REG_LINK                       = 6	# Symbolic link (Unicode)
    REG_MULTI_SZ                   = 7	# Multiple Unicode strings, delimited by \0, terminated by \0\0
    REG_RESOURCE_LIST              = 8  # Resource list in resource map
    REG_FULL_RESOURCE_DESCRIPTOR   = 9  # Resource list in hardware description
    REG_RESOURCE_REQUIREMENTS_LIST = 10
    REG_QWORD                      = 11 # 64-bit number
    REG_QWORD_LITTLE_ENDIAN        = 11 # 64-bit number (same as REG_QWORD)
}

Class GPRegistrySetting
{
    [string]  $SourceFile
    [string]  $PuppetKeyPath
    [string]  $HiveName
    [string]  $KeyName
    [string]  $ValueName
    [RegType] $ValueType
    [string]  $ValueLength
    [object]  $ValueData

    GPRegistrySetting()
    {
        $this.SourceFile    = $Null
        $this.PuppetKeyPath = $Null
        $this.HiveName      = $Null
        $this.KeyName       = $Null
        $this.ValueName     = $Null
        $this.ValueType     = [RegType]::REG_NONE
        $this.ValueLength   = 0
        $this.ValueData     = $Null
    }

    GPRegistrySetting(
            [string]  $SourceFile,
            [string]  $PuppetKeyPath,
            [string]  $HiveName,
            [string]  $KeyName,
            [string]  $ValueName,
            [RegType] $ValueType,
            [string]  $ValueLength,
            [object]  $ValueData
        )
    {
        $this.SourceFile    = $SourceFile
        $this.PuppetKeyPath = $PuppetKeyPath
        $this.HiveName      = $HiveName
        $this.KeyName       = $KeyName
        $this.ValueName     = $ValueName
        $this.ValueType     = $ValueType
        $this.ValueLength   = $ValueLength
        $this.ValueData     = $ValueData
    }
}
Class GPAdminTemplateRecord
{
    [string]  $SourceFile
    [string]  $PolicyPath
    [string]  $PolicySettingsName
    [string]  $RegistryInformation

    GPAdminTemplateRecord()
    {
        $this.SourceFile            = $null
        $this.PolicyPath            = $null
        $this.PolicySettingsName    = $null
        $this.RegistryInformation   = $null
    }

    GPAdminTemplateRecord(
        [string]  $SourceFile,
        [string]  $PolicyPath,
        [string]  $PolicySettingsName,
        [string]  $RegistryInformation
    )
    {
        $this.SourceFile            = $SourceFile
        $this.PolicyPath            = $PolicyPath
        $this.PolicySettingsName    = $PolicySettingsName
        $this.RegistryInformation   = $RegistryInformation
    }
}
Function AssertResult
{
    param
    (
        [Parameter(Mandatory)]
        $Condition,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ErrorMessage
    )

    if (!$Condition) 
    {
        throw $ErrorMessage
    }
}
function Convert-GpoToPuppetManifest 
{
    <#
    .SYNOPSIS
        Convert-GpoToPuppetManifest function will read group policy files that it is pointed toward and convert the machine based policy settings to a puppet manifest
    .DESCRIPTION
        This tool will read the setting files of a  group policy that it is pointed to and convert it to a puppet manifest based on a passed parameter information.
        A puppet manifest is created from the information and a Log is generated with the excluded settings in the folder path where the script is run from under a folder named
        Convert-GpoToPuppetManifest\<profile name passed>.
    .PARAMETER GPOFolderPath
        Path to the the GPO folder to be proccessed. This can be a GUID based folder in S?YSVOL or a saved copy of the group policy folder and sub-folders. (Required)
    .PARAMETER PolicyDefinitionsRepository
        Path to the domains Policy Definitions folder; usually \\<domain DNS name>\SYSVOL\contoso.com\Policies\PolicyDefinitions. (Required)
    .PARAMETER ProfileName
        This is the friendly name of the policy; it can be anything but it is highly recommended that it match the Group Policy Name that is being converted. (Required)
    .PARAMETER policyPathDictionary
        Path to the copy of the Microsoft Excel spreadsheet PolicySettingsDescriptions.csv that contains Microsoft's listing of group policy setting friendly names and registry settings. (Required)
    .PARAMETER IncludeAuditSettings
        Switch to indicate that audit settings should be converted as well as registry settings. (Optional)
    .PARAMETER AuditSettingsFilePath
        Path to the audit.csv file that contains the settings that should be converted. (Optional)
    .NOTES
        Name: Convert-GpoToPuppetManifest
        Author: Shane Smith
        Version History: 1.0
    .EXAMPLE
        Convert-GpoToPuppetManifest -GPOFolderPath 'C:\temp\SERVER-NIST-Hardening-2016wAuditing\' -PolicyDefinitionsRepository '\\contoso.com\SYSVOL\contoso.com\Policies\PolicyDefinitions' `
        -ProfileName 'SERVER-NIST-Hardening-2016wAuditing' -policyPathDictionary '\\foo.com\winrepo\Scripts\Puppet\SupportTools\PolicySettingsDescriptions.csv'

        Description
        -----------
        Convert the GPO in SERVER-NIST-Hardening-2016wAuditing folder to a puppet manifest and save it to .\Convert-GpoToPuppetManifest\SERVER-NIST-Hardening-2016wAuditing.
    .EXAMPLE
        Convert-GpoToPuppetManifest -GPOFolderPath 'C:\temp\SERVER-NIST-Hardening-2016wAuditing\' -PolicyDefinitionsRepository '\\contoso.com\SYSVOL\contoso.com\Policies\PolicyDefinitions' `
        -ProfileName 'SERVER-NIST-Hardening-2016wAuditing' -policyPathDictionary '\\foo.com\winrepo\Scripts\Puppet\SupportTools\PolicySettingsDescriptions.csv' -IncludeAuditSettings -AuditSettingsFilePath $auditCsvPath

        Description
        -----------
        Convert the GPO in SERVER-NIST-Hardening-2016wAuditing folder to a puppet manifest; including any audit settings and save it to .\Convert-GpoToPuppetManifest\SERVER-NIST-Hardening-2016wAuditing.
    #>
    [cmdletbinding(SupportsShouldProcess=$True)]
    Param
    (
        [Parameter(Mandatory= $true,Position = 1,ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$GPOFolderPath,

        [Parameter(Mandatory= $true,Position = 2,ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$PolicyDefinitionsRepository,

        [Parameter(Mandatory= $true,Position = 3,ValueFromPipeline=$true)]
        [string]$ProfileName,

        [Parameter(Mandatory= $true,Position = 4,ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$policyPathDictionary,

        [Parameter(ParameterSetName="AuditSettings",Mandatory= $false,Position = 5,ValueFromPipeline=$true)]
        [switch]$IncludeAuditSettings,

        [Parameter(ParameterSetName="AuditSettings",Mandatory= $false,Position = 4,ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$AuditSettingsFilePath
    )

    # Create an Array List Object that will hold excluded registry setttings
    $excludedRegSettings = New-Object System.Collections.ArrayList($null)

    # Import the admx/adml settings and the PolicySettingsDescriptions csv from Microsoft
    [System.Collections.ArrayList]$global:admFileDataObjects = GetAdmContentList -PolicyDefinitionsRepository $PolicyDefinitionsRepository -policyPathDictionary $policyPathDictionary
    $descriptionDictionary = Import-Csv -Path $policyPathDictionary

    # Build output folder path. Check if a folder and contents exist for the output path; removes the existing data that may exist and creates a new blank folder for the profile to be converted to a manifest
    $outputPath =  (-join((Get-Location).path,'\Convert-GpoToPuppetManifest\',$ProfileName))

    if((Test-Path -Path $outputPath))
    {
        Remove-Item -Recurse -Path $outputPath -Force
    }
    
    New-Item $outputPath -ItemType Directory -Force | Out-Null

    $retrievedRegSettings = ReadGpFileSettings -GPOFolderPath $GPOFolderPath -LogPath $outputPath

    # Create and setup generic information for the puppet manifest being created
    $manifestPath = "$outputPath\default.pp"
    $className = (-join("profile::",$ProfileName,"::default"))

    Add-Content -Path $manifestPath ("# $ProfileName puppet manifest")
    Add-Content -Path $manifestPath ("# Created on: $(get-date) by Convert-GpoToPuppetManifest script`n")
    Add-Content -Path $manifestPath ("class $className {")

    # Loop through each of the retrieved registry settings from reading the group policy files
    foreach($regSetting in $retrievedRegSettings)
    {
        # Check for value type that designates a registry key present check
        if($regSetting.ValueType -match "REG_NONE")
        {
            # Build the Puppet manifest registry present check and write it to the manifest
            $buildRegKey = (-join("  registry_key { ","'",$regSetting.PuppetKeyPath,"':"))
            
            Add-Content -Path $manifestPath ((-join("  # ",$regSetting.SourceFile)))
            Add-Content -Path $manifestPath ($buildRegKey)
            Add-Content -Path $manifestPath ("    ensure => present,")
            Add-Content -Path $manifestPath ("  }")
            Add-Content -Path $manifestPath ("")
        }

        # Check for a hive name other than HKEY_LOCAL_MACHINE and write the entry to the excluded entry log. Any user based settings are not handled at this point
        elseif($regSetting.HiveName -notmatch "HKEY_LOCAL_MACHINE")
        {
            $entry = [GPRegistrySetting]::new($regSetting.SourceFile,$regSetting.PuppetKeyPath, $regSetting.HiveName,$regSetting.KeyName,$regSetting.ValueName,$regSetting.ValueType,$regSetting.ValueLength,$regSetting.ValueData)
            $null = $excludedRegSettings.Add($entry)
        }

        #Check for value type that indicates a registry key absent check
        elseif($regSetting.ValueName -match "\*\*del.")
        {
            # Build the Puppet manifest registry absent check and write it to the manifest
            $buildRegKey = (-join("  registry_key { ","'",($regSetting.PuppetKeyPath -replace("\*\*del.","")),"':"))

            Add-Content -Path $manifestPath ((-join("  # ",$regSetting.SourceFile)))
            Add-Content -Path $manifestPath ($buildRegKey)
            Add-Content -Path $manifestPath ("    ensure => absent,")
            Add-Content -Path $manifestPath ("  }")
            Add-Content -Path $manifestPath ("")
        }

        # All other registry checks should fall under the registry value check category
        else
        {
            $buildRegValue = ""
            $RegType  = ""
            $puppetValueData = ""

            $buildRegValue = (-join("  registry_value { ","'",$regSetting.PuppetKeyPath,"':"))
            [string]$entryType = $regSetting.ValueType
            $RegType = $PuppetRegType.$entryType
            $puppetValueData = $regSetting.ValueData

            # Update to search new object data
            [string]$regSearchValue = (-join($regSetting.KeyName,'\',$regSetting.ValueName))
            $regSearchValue = $regSearchValue.Replace('\','\\')

            # Search the two sources of registry setting descriptions. Search (admx/adml) data and PolicySettingsDescriptions csv from Microsoft
            $policyDescription = $admFileDataObjects | Where-Object {$_.RegistryInformation -match $regSearchValue}

            If($policyDescription.length -eq 0)
            {
                $lookup = (-join('\',$regSetting.KeyName,'\',$regSetting.ValueName))
                $policyDescription  = $descriptionDictionary | Where-Object {$_.RegistryInformation -like $lookup}
            }
            
            # Loop through each description found and add it to the puppt check comments
            foreach($record in $policyDescription)
            {
                Add-Content -Path $manifestPath ((-join("  # ",$record.PolicyPath)))
                Add-Content -Path $manifestPath ((-join("  # ",$record.PolicySettingsName)))
                Add-Content -Path $manifestPath ((-join("  # ",$record.SourceFile)))
            }

            # Build the Puppet manifest registry value check and write it to the manifest
            $puppetType = (-join('    type   => ',$RegType,","))
            $puppetData = (-join('    data   => ',"'",$puppetValueData,"',"))
            
            Add-Content -Path $manifestPath ((-join("  # ",$regSetting.SourceFile)))
            Add-Content -Path $manifestPath ($buildRegValue)
            Add-Content -Path $manifestPath ("    ensure => present,")
            Add-Content -Path $manifestPath ($puppetType)
            Add-Content -Path $manifestPath ($puppetData)
            Add-Content -Path $manifestPath ("  }")
            Add-Content -Path $manifestPath ("")
        }
    }

    if($IncludeAuditSettings)
    {
        #Add call to Audit settings conversion
        if(-not($AuditSettingsFilePath))
        {
            If($GPOFolderPath -match "\\$")
            {
                #remove trailing backslash
                $GPOFolderPath = $GPOFolderPath.Substring((0,$GPOFolderPath.Length-1))
            }

            $AuditSettingsFilePath = -join($GPOFolderPath,"\Machine\microsoft\windows nt\Audit\audit.csv")
        }

        try
        {
            ConvertAuditSettingsToManifest -AuditFilePath $AuditSettingsFilePath -OutputManifestPath $manifestPath
            Write-Verbose ("SUCCESS: Writing Audit Setting values to $manifestPath") -Verbose
        }
        catch
        {
            Write-Warning ("ERROR: Writing Audit Setting values to $manifestPath")
        }
    }

    # Closing culey braces for manifest
    Add-Content -Path $manifestPath ("}")
    
    # Write excluded entries to log 
    WriteLogResults -Data $excludedRegSettings -LogLabel "Excluded-RegSettingsManifest" -OutputPath $outputPath
}
Function ConvertStringToInt
{
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [System.Object[]]$ValueString
    )
  
    if ($ValueString.Length -le 4)
    {
        [int32] $result = 0
    }
    elseif ($ValueString.Length -le 8)
    {
        [int64] $result = 0
    }
    else
    {
        Fail -ErrorMessage $LocalizedData.InvalidIntegerSize
    }

    for ($i = $ValueString.Length - 1 ; $i -ge 0 ; $i -= 1)
    {
        $result = $result -shl 8
        $result = $result + ([int][char]$ValueString[$i])
    }

    return $result
}
function GetAdmContentList
{
    <#
    .SYNOPSIS
        GetAdmContentList is a private function that reads all of the admx and adml files in a location; normalizes them and passes the normalized data object
    .DESCRIPTION
        This tool will read all the adml and admx files in the passed PolicyDefinitionsRepository; format and normalizes the deata and return normalized data object
    .PARAMETER PolicyDefinitionsRepository
        Path to the domains Policy Definitions folder; usually \\<domain DNS name>\SYSVOL\contoso.com\Policies\PolicyDefinitions. (Required)
    .PARAMETER policyPathDictionary
        Path to the copy of the Microsoft Excel spreadsheet PolicySettingsDescriptions.csv that contains Microsoft's listing of group policy setting friendly names and registry settings. (Required)
    .NOTES
        Name: GetAdmContentList
        Author: Shane Smith
        Version History: 1.0
    .EXAMPLE
        GetAdmContentList -PolicyDefinitionsRepository '\\contoso.com\SYSVOL\contoso.com\Policies\PolicyDefinitions' -policyPathDictionary '\\foo.com\winrepo\Scripts\Puppet\SupportTools\PolicySettingsDescriptions.csv'
        Description
        -----------
        Reads the admx and adml files in the PolicyDefinitions folder; loads the provided gpo description csv; formats and normalizes the data and returns it to the calling code.
    #>
    param
    (
        [Parameter(Mandatory= $true,Position=1,ValueFromPipeline=$true)]
        [string]$PolicyDefinitionsRepository,

        [Parameter(Mandatory= $false,Position=2,ValueFromPipeline=$true)]
        [string]$policyPathDictionary
    )

    # Object that stores normalized registry setting description information from varied formatted lists
    $regDescriptions = New-Object System.Collections.ArrayList($null)

    $counter = 0

    # If csv path dictionary provided load file into variable
    if($policyPathDictionary)
    {
        $descriptionDictionary = Import-Csv -Path $policyPathDictionary
    }

    # Used to get lists of the adm files that will be ingested and normalized
    $admlPath = (-join($PolicyDefinitionsRepository,"\en-us"))
    $admxFiles = Get-ChildItem  $PolicyDefinitionsRepository -Recurse -File | Where-Object {$_.FullName -like "*.admx"} | ForEach-Object { $_.FullName } | Sort-Object
    $admlFiles = Get-ChildItem  $admlPath -Recurse -File | Where-Object {$_.FullName -like "*.adml"} | ForEach-Object { $_.FullName } | Sort-Object

    # Loop through all of the admx and csv entries that have been passed; normalize them and store them as an object
    foreach($admx in $admxFiles)
    {
        #Used to show progress bar and display the current machine being checked
        $counter++
        $Parameters = @{ Activity = "Processing";
                        Status = "Enumerating admx and adml files -- completed $($counter) of $($admxFiles.count)";
                        CurrentOperation = $admx;
                        PercentComplete = (($counter/$admxFiles.count)*100) 
                    }     
        Write-Progress @Parameters

        # Format admx string to adml and search for matching adml file to use to create normalized description record
        $Splitadmx = $admx -Split("\\")
        [string]$admxFile = $Splitadmx[((($Splitadmx.length)-1))]
        $adml = (-join('*\',($admxFile.replace(".admx",".adml"))))
        $admlSearchResults = $admlFiles | Where-Object {$_ -like "$adml"}

        # Check if an adml match for the admx file was found and then process the data to get the description information
        if($admlSearchResults.length -gt 0)
        {
            [xml]$admlFileLoad = get-content $admlSearchResults
            [xml]$admxFileLoad = get-content $admx

            # Loop through admx file and look through adml file strings; try to find registry description match and then get Group Policy Path value 
            foreach($item in $admxFileLoad.policyDefinitions.policies.policy)
            {
                $policyPath = $null

                [string]$displyName = $item.displayname
                $displayNameSplit = $displyName.Split(".")
                $searchAdml = $displayNameSplit[1] -replace("\)","")
                $admlStrings =  $admlFileLoad.policyDefinitionResources.resources.stringTable.string

                foreach($line in $admlStrings)
                {
                    if($searchAdml -eq $line.Id)
                    {
                        $settingName = $line.'#text'
                        $lookupPath = $descriptionDictionary | Where-Object {$_.Setting -like "$settingName"}

                        foreach($settingResult in $lookupPath)
                        {

                            If(!$settingResult.Path)
                            {
                                $policyPath = "None"
                            }
                            else
                            {
                                $policyPath = $settingResult.Path
                            }

                            $registryInformation = (-join($item.key,'\',$item.name))
                            $regDescriptionRecord = [GPAdminTemplateRecord]::new($admxFile,$policyPath,$settingName,$registryInformation)
                            $null = $regDescriptions.Add($regDescriptionRecord)

                            $policyPath = $null
                        }
                    }
                }
            }
            
        }
    }

    # If csv path dictionary provided, loop through the list; seperate and format registry values in each row and then get Group Policy Path value 
    if($policyPathDictionary)
    {
        foreach($record in $descriptionDictionary)
        {
            $counter2++
            $Parameters = @{ Activity = "Processing";
                            Status = "Enumerating policy path dictionary rows -- completed $($counter2) of $($descriptionDictionary.count)";
                            CurrentOperation = $record;
                            PercentComplete = (($counter2/$descriptionDictionary.count)*100) 
                        }     
            Write-Progress @Parameters

            if($record.RegistryInformation -match "HKLM")
            {
                $splitKey = "HKLM"
            }
            elseif ($record.RegistryInformation -match "HKCU")
            {
                $splitKey = "HKCU"
            }
            elseif ($record.RegistryInformation -match "MACHINE")
            {
                $splitKey = "MACHINE"
            }

            $recordRegistrySplit = $record.RegistryInformation -split($splitKey)

            foreach($item in $recordRegistrySplit)
            {
                if($item.length -gt 0)
                {
                    [string]$cleanRegRecocord =  $item
                    $cleanRegRecocord = $cleanRegRecocord.TrimStart('\')
                    $cleanRegRecocord = $cleanRegRecocord.Replace('!','\')
                    $regDescriptionRecord = [GPAdminTemplateRecord]::new($policyPathDictionary,$record.PolicyPath,$record.PolicySettingName,$cleanRegRecocord)
                    $null = $regDescriptions.Add($regDescriptionRecord)
                }
            }
        }

    }
    return $regDescriptions
}
function GetPolicyFileList
{

    param
    (
        [Parameter(Mandatory= $true)]
        [ValidateScript({Test-Path $_})]
        [string]$GPOFolder
    )

    # Enumerate recursively through the provided path and find all admx and adml files
    $policySettingFiles = Get-ChildItem  $GPOFolder -Recurse -File | 
    Where-Object {$_.FullName -like "*.xml" -or $_.FullName -like "*.inf" -or $_.FullName -like "*.pol"} |
    ForEach-Object { $_.FullName } | Sort-Object

    return $policySettingFiles
}
function ReadGpFileSettings
{
    <#
    .SYNOPSIS
        ReadGpFileSettings is an internal function to read legacy .pol and .xml policy file types
    .DESCRIPTION
        This tool will read legacy .pol and .xml policy file types that need to be proccessed by Convert-GpoToPuppetManifest and normalize the data and pass it back.
    .PARAMETER GPOFolderPath
        Path to the the GPO folder by Convert-GpoToPuppetManifest. (Required)
    .PARAMETER LogPath
        Path to the profile folder that is being used by Convert-GpoToPuppetManifest. (Required)
    .NOTES
        Name: Convert-GpoToPuppetManifest
        Author: Shane Smith
        Version History: 1.0
    .EXAMPLE
        ReadGpFileSettings -GPOFolderPath 'C:\temp\SERVER-NIST-Hardening-2016wAuditing\' -LogPath 'c:\temp\Convert-GpoToPuppetManifest\SERVER-NIST-Hardening-2016wAuditing'
        Description
        -----------
        Read the .pol and .xml policy GP files in SERVER-NIST-Hardening-2016wAuditing folder; normalize the data; return results and log data to C:\temp\Convert-GpoToPuppetManifest\SERVER-NIST-Hardening-2016wAuditing.
    #>
    Param
    (
        [Parameter(Mandatory= $true,Position=1,ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$GPOFolderPath,
        [Parameter(Mandatory= $false,Position=2,ValueFromPipeline=$True)]
        [string]$LogPath
    )

    #Build log path and check if log folder exists. If the log folder does not exist create it.
    If (-not (Test-Path $LogPath))
    {
        New-Item $LogPath -ItemType Directory | Out-Null
    }

    # Object that stores normalized registry setting information from varied formatted group policy setting files
    $registrySettings = New-Object System.Collections.ArrayList($null)

    # Call function to enumerate the various file types that contain group policy settings
    $gpoFilesToProcess = GetPolicyFileList -GPOFolder $GPOFolderPath

    # Extract specific file extension types into lists for later processing
    $polFiles = $gpoFilesToProcess | Where-Object {$_ -like "*.pol"}
    $xmlRegFiles = $gpoFilesToProcess | Where-Object {$_ -like "*registry.xml"}

    # Loop through the .pol registry setting files; determine user or machine settings and add results to normalized registry setting array list
    foreach($polEntry in $polFiles)
    {
        if($polEntry -match "\\User\\registry.pol")
        {
            $hive = "HKEY_USERS"
        }
        else
        {
        $hive = "HKEY_LOCAL_MACHINE"
        }

        if((Test-Path -Path $polEntry))
        {
            Write-Verbose("GPO Policy file verified $polEntry.....") -Verbose
            $polReadResults = ReadPolFile -Path $polEntry -HiveValue $hive
            if($polReadResults)
            {
                if($polReadResults.Count -eq 1)
                {
                   $null = $registrySettings.Add($polReadResults)
                }
                elseif($polReadResults.Count -gt 1)
                {
                    $null = $registrySettings.AddRange($polReadResults)
                }
            }
        }
    }

    # Read .inf file registry settings and add results to normalized registry setting array list
    $secEditFullPathTest = (-join($GPOFolderPath,'\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf'))

    if(test-path -Path $secEditFullPathTest)
    {
        $GptTmplReadResults = ReadGptTmplFile
    }

    if($GptTmplReadResults)
    {
        if($GptTmplReadResults.Count -eq 1)
        {
            $null = $registrySettings.Add($GptTmplReadResults)
        }
        elseif($GptTmplReadResults.Count -gt 1)
        {
            $null = $registrySettings.AddRange($GptTmplReadResults)
        }
    }

    # Loop through the .xml registry setting files and add results to normalized registry setting array list
    foreach($xmlRegEntry in $xmlRegFiles)
    {
        if((Test-Path -Path $xmlRegEntry))
        {
            Write-Verbose("GPO Policy file verified $xmlRegEntry.....") -Verbose
            $xmlReadResults = ReadRegistryXml -RegXmlFile $xmlRegEntry
            if($xmlReadResults)
            {
                if($xmlReadResults.Count -eq 1)
                {
                    $null = $registrySettings.Add($xmlReadResults)
                }
                elseif($xmlReadResults.Count -gt 1)
                {
                    $null = $registrySettings.AddRange($xmlReadResults)
                }
            }
        }
    }
    # Call function to log all registry setting object results to file
    WriteLogResults -Data $registrySettings -LogLabel "ReadGpFileSettings" -OutputPath $LogPath
    return $registrySettings
}
function ReadGptTmplFile
{
    <#
    .SYNOPSIS
        ReadGptTmplFile reads gptTmpl.inf file; formats the data and returns the output
    .DESCRIPTION
        This tool is a private function that will reads gptTmpl.inf file in the standard policy path location; formats the data and returns the output
    .NOTES
        Name: ReadGptTmplFile
        Author: Shane Smith
        Version History: 1.0
    #>
    [Array] $RegistryPolicies = @()

    $secEditFullPath = (-join($GPOFolderPath,'\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf'))
    $secEditFile = Get-Item $secEditFullPath

    $global:ini = @{}
    switch -regex -file $secEditFile
    {
        "^\[(.+)\]$" # Section  
        {  
            $section = $matches[1]
            $ini[$section] = @{} 
            $CommentCount = 0
        }
        "^(;.*)$" # Comment
        {
            if (!($section))  
            {
                $section = "No-Section"
                $ini[$section] = @{}
            }
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = "Comment" + $CommentCount
            $ini[$section][$name] = $value
        }
        "(.+?)\s*=\s*(.*)" # Key
        {
            if (!($section))
            {  
                $section = "No-Section"
                $ini[$section] = @{}
            }
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }  
    }

    $regEntries = $ini.'Registry Values'

    foreach($line in $regEntries.keys)
    {
        [object]$value = $null
        [string]$keyName = $null
        [string]$valueName = $null
        [string]$valueType = $null
        [int]$valueLength = 4

        $lineValues = $regEntries[$line]
        $regPathsplit = $line -split("\\")
        $regPathCount = (($regPathsplit.Count)-1)

        for ($i = 0; $i -le ($regPathCount-1); $i++)
        {
            if($i -ne 0)
            {
                $keyName = (-join($keyName,$regPathsplit[$i],'\'))
            }
        }


        $keyName = $keyName.Substring(0,$keyName.Length-1)
        $valueName = $regPathsplit[$regPathCount]

        $regEntryValues = $lineValues -split(",")

        switch ($regEntryValues[0])
        {
            0{$valueType = "REG_NONE"}
            1{$valueType = "REG_SZ"}
            21{$valueType = "REG_EXPAND_SZ"}
            3{$valueType = "REG_BINARY"}
            4{$valueType = "REG_DWORD"}
            7{$valueType = "REG_MULTI_SZ"}
            11{$valueType = "REG_QWORD"}
        }

        $valueData = $regEntryValues[1]
        $valueLength = $valueName.Length

        if(!$valueLength -eq 0)
        {
            $entry = [GPRegistrySetting]::new($secEditFullPath,(-join($RegHiveType.HKEY_LOCAL_MACHINE,'\',$keyName,'\',$valueName)),"HKEY_LOCAL_MACHINE",$keyName,$valueName,$valueType,$valueLength,$valueData)
        }
        else
        {
            $entry = [GPRegistrySetting]::new($secEditFullPath,(-join($RegHiveType.HKEY_LOCAL_MACHINE,'\',$keyName)),"HKEY_LOCAL_MACHINE",$keyName,$valueName,$valueType,$valueLength,$valueData)
        }

        $RegistryPolicies += $entry
    }

    return $RegistryPolicies
}
Function ReadPolFile
{
    <#
    .SYNOPSIS
        ReadPolFile reads a passed registry .pol file; formats the data and returns the output
    .DESCRIPTION
        This tool is a private function that will read a passed .pol file; formats/noramlies the data and returns the output to the calling code
    .PARAMETER Path
        Path to the pol file to be read and processed. (Required)
    .PARAMETER HiveValue
        Registry hive that contains the registry settings in the pol file. For now this module only proccesses HKLM hive settings completely. (Required)
    .NOTES
        Name: ReadPolFile
        Author: Shane Smith
        Version History: 1.0
    .EXAMPLE
        ReadPolFile -Path 'c:\temp\registry.pol' -HiveValue 'HKEY_LOCAL_MACHINE'
        Description
        -----------
        Reads the passed pol file normalizes the data and returns the data object
    #>
    [OutputType([Array])]
    param 
    (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Path,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$HiveValue

    )

    [Array] $RegistryPolicies = @()
    $index = 8

    [string] $policyContents = Get-Content $Path -Raw
    [byte[]] $policyContentInBytes = Get-Content $Path -Raw -Encoding Byte

    # Start processing at byte 8
    while($index -lt $policyContents.Length - 2)
    {
        [string]$keyName = $null
        [string]$valueName = $null
        [int]$valueType = $null
        [int]$valueLength = $null

        [object]$value = $null

        # Next UNICODE character should be a [
        $leftbracket = [System.BitConverter]::ToChar($policyContentInBytes, $index)
        AssertResult ($leftbracket -eq '[') "Missing the openning bracket"
        $index+=2

        # Next UNICODE string will continue until the ; less the null terminator
        $semicolon = $policyContents.IndexOf(";", $index)
        AssertResult ($semicolon -ge 0) "Failed to locate the semicolon after key name."
        $keyName = [System.Text.Encoding]::UNICODE.GetString($policyContents[($index)..($semicolon-3)]) # -3 to exclude the null termination and ';' characters
        $index = $semicolon + 2

        # Next UNICODE string will continue until the ; less the null terminator
        $semicolon = $policyContents.IndexOf(";", $index)
        AssertResult ($semicolon -ge 0) "Failed to locate the semicolon after value name."
        $valueName = [System.Text.Encoding]::UNICODE.GetString($policyContents[($index)..($semicolon-3)]) # -3 to exclude the null termination and ';' characters
        $index = $semicolon + 2

        # Next DWORD will continue until the ;
        $semicolon = $index + 4 # DWORD Size
        AssertResult ([System.BitConverter]::ToChar($policyContentInBytes, $semicolon) -eq ';') "Failed to locate the semicolon after value type."
        $valueType = [System.BitConverter]::ToInt32($policyContentInBytes, $index)
        $index=$semicolon + 2 # Skip ';'

        # Next DWORD will continue until the ;
        $semicolon = $index + 4 # DWORD Size
        AssertResult ([System.BitConverter]::ToChar($policyContentInBytes, $semicolon) -eq ';') "Failed to locate the semicolon after value length."
        $valueLength = ConvertStringToInt -ValueString $policyContentInBytes[$index..($index+3)]
        $index=$semicolon + 2 # Skip ';'

        if ($valueLength -gt 0)
        {
            # String types less the null terminator for REG_SZ and REG_EXPAND_SZ
            # REG_SZ: string type (ASCII)
            if($valueType -eq [RegType]::REG_SZ)
            {
                [string] $value = [System.Text.Encoding]::UNICODE.GetString($policyContents[($index)..($index+$valueLength-3)]) # -3 to exclude the null termination and ']' characters
                $index += $valueLength
            }

            # REG_EXPAND_SZ: string, includes %ENVVAR% (expanded by caller) (ASCII)
            if($valueType -eq [RegType]::REG_EXPAND_SZ)
            {
                [string] $value = [System.Text.Encoding]::UNICODE.GetString($policyContents[($index)..($index+$valueLength-3)]) # -3 to exclude the null termination and ']' characters
                $index += $valueLength
            }

            # For REG_MULTI_SZ leave the last null terminator
            # REG_MULTI_SZ: multiple strings, delimited by \0, terminated by \0\0 (ASCII)
            if($valueType -eq [RegType]::REG_MULTI_SZ)
            {
                [string] $value = [System.Text.Encoding]::UNICODE.GetString($policyContents[($index)..($index+$valueLength-3)])
                $index += $valueLength
            }

            # REG_BINARY: binary values
            if($valueType -eq [RegType]::REG_BINARY)
            {
                [byte[]] $value = $policyContentInBytes[($index)..($index+$valueLength-1)]
                $index += $valueLength
            }
        }

        # DWORD: (4 bytes) in little endian format
        if($valueType -eq [RegType]::REG_DWORD)
        {
            $value = ConvertStringToInt -ValueString $policyContentInBytes[$index..($index+3)]
            $index += 4
        }

        # QWORD: (8 bytes) in little endian format
        if($valueType -eq [RegType]::REG_QWORD)
        {
            $value = ConvertStringToInt -ValueString $policyContentInBytes[$index..($index+7)]
            $index += 8
        }

        # Next UNICODE character should be a ]
        $rightbracket = $policyContents.IndexOf("]", $index) # Skip over null data value if one exists
        AssertResult ($rightbracket -ge 0) "Missing the closing bracket."
        $index = $rightbracket + 2

        if(!$valueLength -eq 0)
        {
            $entry = [GPRegistrySetting]::new($Path,(-join($RegHiveType.($HiveValue),'\',$keyName,'\',$valueName)),
            $HiveValue,$keyName,$valueName,$valueType,$valueLength,$value)
        }
        else
        {
            $entry = [GPRegistrySetting]::new($Path,(-join($RegHiveType.($HiveValue),'\',$keyName)),
            $HiveValue,$keyName,$valueName,$valueType,$valueLength,$value)
        }

        $RegistryPolicies += $entry
    }

    return $RegistryPolicies
}
function ReadRegistryXml
{
        <#
    .SYNOPSIS
        ReadRegistryXml reads a passed registry .xml file; formats the data and returns the output
    .DESCRIPTION
        This tool is a private function that will read a passed .xml file; formats/normalizes the data and returns the output to the calling code
    .PARAMETER RegXmlFile
        Path to the xml file to be read and processed. (Required)
    .NOTES
        Name: ReadRegistryXml
        Author: Shane Smith
        Version History: 1.0
    .EXAMPLE
        ReadRegistryXml -Manifest 'c:\temp\Drives.xml'
        Description
        -----------
        Reads the passed xml file normalizes the data and returns the data object
    #>
    param
    (
        [Parameter(Mandatory= $true,Position=0)]
        [ValidateScript({Test-Path $_})]
        [string]$RegXmlFile
    )

    [Array] $RegistryPolicies = @()

    [xml]$xmlRegContent = Get-Content -Path $RegXmlFile

    foreach($regEntry in $xmlRegContent.RegistrySettings.Registry.Properties)
    {
        [string]$keyName = ""
        [string]$valueName = ""
        [string]$valueType = ""
        [int]$valueLength = 4

        $cleanedKey = $regEntry.key
        if($cleanedKey.Substring(0,1) -eq '\')
        {
            $stringLength = $cleanedKey.Length
            $cleanedKey = $cleanedKey.Substring(1,$stringLength-1)
        }

        $formatedHive = $RegHiveType.($regEntry.hive)
        [string]$keyName = $cleanedKey
        [string]$valueName = $regEntry.name
        [string]$valueType = $regEntry.type
        $valueData = $regEntry.value
        $valueLength = $valueName.Length

        if(!$valueLength -eq 0)
        {
            $entry = [GPRegistrySetting]::new($RegXmlFile,(-join($formatedHive,'\',$cleanedKey,'\',$valueName)),
            ($regEntry.hive),$keyName,$valueName,$valueType,$valueLength,$valueData)
        }
        else
        {
            $entry = [GPRegistrySetting]::new($RegXmlFile,(-join($formatedHive,'\',$cleanedKey)),
            ($regEntry.hive),$keyName,$valueName,$valueType,$valueLength,$valueData)
        }

        $RegistryPolicies += $entry
    }

    return $RegistryPolicies
}
function WriteLogResults
{
    param
    (
        [System.Collections.ArrayList]$Data,
        [string]$LogLabel,
        [string]$OutputPath
    )

    # Create log file path and write out
    $logPath = (-join($OutputPath,"\$LogLabel-",(Get-Date -Format 'MM-dd-yyyy'),".log"))
    Write-Verbose("Writing log: $logPath.....") -Verbose

    # Process each row in the data list passed and write to log
    foreach($item in $Data)
    {
        $row = (-join($item.HiveName,",",$item.KeyName,",",$item.ValueName,",",$item.ValueType,",",$item.ValueLength,",",$item.ValueData,",",$item.PuppetKeyPath,",",$item.SourceFile))
        Add-Content -Path $logPath ($row)
    }
    
}
function ConvertAuditSettingsToManifest
{
    param
    (
        [Parameter(Mandatory= $true,Position = 1,ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$AuditFilePath,

        [Parameter(Mandatory= $true,Position = 2,ValueFromPipeline=$true)]
        [ValidateScript({Test-Path $_})]
        [string]$OutputManifestPath
    )
    
    $skip = $false
    # Logic to readaudit file and process results, accounting for remarking exclusion based settiings
    $genericLabel = "Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\AuditPolicies\"

    try
    {
        $auditData = Import-Csv $AuditFilePath
        Write-Verbose ("SUCCESS: Reading Audit Settings from $AuditFilePath") -Verbose
    }
    catch
    {
        Write-Warning ("ERROR: Reading Audit Settings from $AuditFilePath")
        $skip = $true
    }

    If (-not($skip))
    {
        foreach($auditEntry in $auditData)
        {
            $exclusionPrefix = $null

            if($auditEntry."Policy Target" -eq "System")
            {
                if($auditEntry."Inclusion Setting" -eq "Success")
                {
                    $entrySuccess = "    success => 'enable',"
                    $entryFailure = "    failure => 'disable',"
                }
                elseif($auditEntry."Inclusion Setting" -eq "Failure")
                {
                    $entrySuccess = "    success => 'disable',"
                    $entryFailure = "    failure => 'enable',"
                }
                elseif($auditEntry."Inclusion Setting" -eq "Success and Failure")
                {
                    $entrySuccess = "    success => 'enable',"
                    $entryFailure = "    failure => 'enable',"
                }

                $category = ($auditEntry.Subcategory -replace("Audit","")).Trim()

                If($auditEntry."Exclusion Setting")
                {
                    $exclusionPrefix = "# "
                    Add-Content -Path $OutputManifestPath (-join("# Exlusion Setting was populated entry is commented out. Add conditional logic for Exclusion Setting value:",$auditEntry."Exclusion Setting"))
                }

                Add-Content -Path $OutputManifestPath (-join($exclusionPrefix,"# ",$genericLabel,$category))
                Add-Content -Path $OutputManifestPath (-join($exclusionPrefix,"auditpol { '",$category,"':"))
                Add-Content -Path $OutputManifestPath (-join($exclusionPrefix,$entrySuccess))
                Add-Content -Path $OutputManifestPath (-join($exclusionPrefix,$entryFailure))
                Add-Content -Path $manifestPath (-join($exclusionPrefix,"  }"))
                Add-Content -Path $manifestPath ("")
            }
        }
    }
}