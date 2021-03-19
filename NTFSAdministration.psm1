    <#
       .DESCRIPTION
       MICROSOFT has failed us. They haven't setup a module to do this already. So we have to cook up or own solution. 

       .EXAMPLE
       Top Container in Scope:
       Set-NTFSOwner -Identity Contoso1\user1 -path \\sharename\ShareFolder -IncludeTopLevelContainer

       Top Container not in Scope:
       Set-NTFSOwner -Identity Contoso1\user1 -path C:\mis\folder

       SMB Folder Example (also works for NTFS):
       Set-NTFSOwner -Identity Contoso1\user1 -path \\sharename\ShareFolder
       
       .NOTES
       Runas account needs permissions to change/take ownership - like local admin or domain admin
       SMB Security modification will take longer than local - so be patient while the cookies bake.
   #>

Function Log($message){
    Write-Host $message -ForegroundColor Yellow -BackgroundColor Black
}

Function UserValidation {
    [CmdletBinding()]
    Param(
        $Identity
    )
        if(Get-ADUser -Filter "SamAccountName -like '$Identity'"){}
          elseif(Get-ADGroup -Filter "SamAccountName -like '$Identity'"){}
          else{Throw "AD Object not found. Please verify object Exists"}
}
    
Function PathValidation{
    [CmdletBinding()]
    Param(
        $Path
    )
        if( Get-Item -Path $Path -Exclude "*.*"){}
        else{Throw "Folder cannot be verified. Please confirm Folder exists and specified path is not a File."}
}

Function OrphanSIDCheck {
    param(
        $path
    )
    $aclCheck = Get-acl -Path $path

    Log "Checking Owner/Principal Identities"
    Log "Error will throw if Identity is not found or Owner is an Orphaned SID"
    foreach($account in $aclCheck.Access){
#        $AccessValue = $account.IdentityReference.Value
        if($account.IdentityReference.Value -match "S-1-5-*" -and !($account.IsInherited)){
            Log "Found $($account.IdentityReference). Removing."
            $aclCheck.RemoveAccessRule($account) | Out-Null
        }
        elseif($account.IdentityReference.Value -match "S-1-5-*"){
            Log $account.IdentityReference.Value
            Throw "Orphaned SID found. Please disable inheritance on $path to remove SID(s)"
        }
        } #EndOfForeach
    $result = $aclCheck.Owner -creplace '^[^\\]*\\', ''
    
    UserValidation -Identity $result
    $aclCheck | Set-Acl -Path $path
}

Function Set-ACLObject{
        param(
            $Owner,
            $Path,
            [switch]$EnableInherit,
            [switch]$DisableInherit
            )
            
            $acl = get-acl $Path

            #Enable or Disable Inheritance based on flag
            if($DisableInherit -and $EnableInherit){Throw "Check Set-ACLObject Function"}
            elseif($DisableInherit){
                $acl.SetAccessRuleProtection($true,$true) #disables inheritance on object
            }
                elseif($EnableInherit){
            $acl.SetAccessRuleProtection($false,$true) #enables inheritance on object
            }
            
            # Allows for only inheritance to be set and not take ownership
            if($owner){$acl.SetOwner($Owner)}
            # Apply ACL to path
            $acl | Set-Acl -Path $Path
}

Function Set-NTFSOwner {
    <#
       .DESCRIPTION
       Set the File/Folder owner for local and remote NTFS Objects

       .EXAMPLE
       Top Container in Scope:
       Set-NTFSOwner -Identity Contoso1\user1 -path \\sharename\ShareFolder -IncludeTopLevelContainer

       Top Container not in Scope:
       Set-NTFSOwner -Identity Contoso1\user1 -path C:\mis\folder

       SMB Folder Example:
       Set-NTFSOwner -Identity Contoso1\user1 -path \\sharename\ShareFolder
       
       .NOTES
       Runas account needs permissions to change/take ownership
       SMB Security modification will take longer than local
   #>
    [CmdletBinding()]
    [Alias("chown")]
    Param (
        $Identity,
        $Path,
        [Switch]$IncludeTopLevelContainer,
        [Switch]$Log
    )
     
    # User Validation and Path validation - defined outside of Function!
    UserValidation -Identity $Identity
    PathValidation -Path $Path
             
    # Creates the NT Security Object for the Identity
    $Owner = New-Object System.Security.Principal.NTAccount -ArgumentList "$Identity"

    #Sets owner at the Top container if Flag is set
    If($IncludeTopLevelContainer){
        # Set owner at Top level container
        Set-ACLObject -Owner $Owner -Path $Path -DisableInherit
        Log "$Identity is now owner of $Path" 
    }

    #Orphan SID Check (this will cause errors unless they are removed)
    OrphanSIDCheck -path $path
    
    ## Directory Count of Path
    $DirCount = Get-ChildItem -Path $Path
    $i = 0
    
    # Beginning of iteration through sub containers/files
    foreach($Dir in $DirCount){
        $i++
        $Percentage = "{0:N0}" -f ($i*100/$DirCount.Count)
        Write-Progress -Activity "Working on $($Dir.FullName)" -PercentComplete $Percentage -Status "$Percentage % Complete "
        Set-ACLObject -Owner $Owner -Path $Dir.FullName -EnableInherit
        if($Log){Log -message $Dir.Fullname}
        Get-ChildItem $Dir.Fullname -Recurse | ForEach-Object {
            Try{
               Set-ACLObject -Owner $Owner -Path $_.FullName -EnableInherit
               if($Log){Log -message $_.Fullname}
               }
            Catch{Write-Warning "Could not Access" $_.FullName}
            }
        } #End of Iteration
}#End of Set-NTFSOwner

Function Add-NTFSPermission {
        <#
        .DESCRIPTION
        Add an NTFS Permission to an object (Folder or File).
        .EXAMPLE
        Add-NTFSPermission -Identity jUser -path C:\users -PermissionLevel Modify
        Add-NTFSPermission -Identity jUser -path C:\users -PermissionLevel FullControl
        Add-NTFSPermission -Identity jUser -path C:\users -PermissionLevel ReadandExecute
        Add-NTFSPermission -Identity "Server\LocalGroup" -path C:\users -PermissionLevel ReadAndExecute -Local

        .NOTES
        SecurityObject:
        https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemaccessrule.-ctor?view=dotnet-plat-ext-3.1#System_Security_AccessControl_FileSystemAccessRule__ctor_System_Security_Principal_IdentityReference_System_Security_AccessControl_FileSystemRights_System_Security_AccessControl_InheritanceFlags_System_Security_AccessControl_PropagationFlags_System_Security_AccessControl_AccessControlType_
        (Identity,fileSystemRights,inheritanceFlags,propagationFlags,type)
        $Identity = object that encapsulates a reference to a user/group account.
        PermissionLevel = values that specifies the type of operation associated with the access rule.
        3 = values that specifies how access masks are propagated to child container/leaf objects "This object subfolders/files"
        0 = values that specifies how Access Control Entries (ACEs) are propagated to child objects. "Only subfolders/files"
        0 = Object is used to allow access to a secured object. 
        
    #>
        [CmdletBinding()]
        [Alias("chmod")]
        Param (
            [string]$Identity,
            [string]$Path,
            [string]$PermissionLevel,
            [switch]$Local
        )
        # User Validation and Path validation - defined outside of Function!
        PathValidation -Path $Path
        OrphanSIDCheck -path $Path

        if($Local){}
        else{UserValidation -Identity $Identity}

        # Check Permission Level to ensure valid            
        function PermissionCheck($Permcheck) {
            if($Permcheck -eq "FullControl"){}
            elseif($Permcheck -eq "Modify"){}
            elseif($Permcheck  -eq "ReadAndExecute"){}
            else{Throw "Permission level can only be FullControl, Modify, or ReadAndExecute"}
        }
        PermissionCheck -Permcheck $PermissionLevel

	#Identity-who it is, Permissions level (see above), number 3 - turn on inheritance.                 
        $SecurityObject = New-Object System.Security.AccessControl.FileSystemAccessRule("$Identity", "$PermissionLevel", "3" , "0", "0")
            
        $acl = Get-Acl $Path
        $acl.AddAccessRule($SecurityObject)
        $acl | Set-Acl -Path $Path 
        Log "Permission applied without issue"
        
        ## Verify at least Read Access of all subfolders. Access errors will log to screen and file
        Log "Checking Folder level access by 1 level." 
        Log "If running account is denied access, Folder will log to screen." 
        Log "If folder structure is dense, this process will take some time." 
        Get-ChildItem -Path $path -Depth 1 -ErrorAction SilentlyContinue -ErrorVariable +errorVariable | Out-Null
        
        foreach($e in $errorVariable){
        Log " $($e.CategoryInfo.TargetName) " 
        }

        If($errorVariable){Throw "Errors found, please correct access first before applying new permissions"}
        Else{
            Log "You may want to confirm access to the sub folder(s) with Get-ChildItem -Recurse"
        }
}  # End of Set-NTFSPermission

Function Set-NTFSInheritance {
            <#
            .DESCRIPTION
            Sets NTFS Inheritance on a single object (Folder or File)
            If you do not have full control permissions, or are the object owner, an error will throw.
            .EXAMPLE                         
            Set-NTFSInheritance -path C:\users\ -EnableInherit
            Set-NTFSInheritance -path C:\users\ -DisableInherit
            .NOTES
            https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectsecurity.setaccessruleprotection?view=dotnet-plat-ext-3.1
            isProtected - true to protect the access rules associated with this ObjectSecurity object from inheritance; false to allow inheritance.
            preserveInheritance - true to preserve inherited access rules; false to remove inherited access rules. This parameter is ignored if isProtected is false.
            #>
            Param(     
                $path,           
                [switch]$EnableInherit,
                [switch]$DisableInherit
            ) # End of Param block
     
            PathValidation $path
            OrphanSIDCheck -path $path
     
            if($DisableInherit -and $EnableInherit){Throw "Cannot set Enable and Disable together"}
            elseif($DisableInherit){
                Log "Disable Inheritance for $path" 
                Set-ACLObject -path $path -DisableInherit    
            }
            elseif($EnableInherit){
                Log "Enable on Inheritance" 
                Set-ACLObject -path $path -EnableInherit
                }
} # end of Set-NTFSInhertiance Function

function Get-NTFSPermission ($Path) {
    (Get-Item $Path).FullName
    (get-acl $Path).access | Select-Object `
    @{Label = "Identity"; Expression = { $_.IdentityReference } }, `
    @{Label = "Right"; Expression = { $_.FileSystemRights } }, `
    @{Label = "Access"; Expression = { $_.AccessControlType } }, `
    @{Label = "Inherited"; Expression = { $_.IsInherited } }, `
    @{Label = "Inheritance Flags"; Expression = { $_.InheritanceFlags } }, `
    @{Label = "Propagation Flags"; Expression = { $_.PropagationFlags } }
}