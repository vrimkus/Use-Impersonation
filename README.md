## PowerShell wrapper around C# SimpleImpersonation.

Designed to emulate C# using syntax with impersonation.


```powershell
#### This option allows specifying a string to -Credential, which will display the credential prompt.
Use-Impersonation -Credential DOMAIN\user -LogonType Batch {     
    sqlps
    $as = New-Object Microsoft.AnalysisServices.Server  
    $as.connect("server-name\instance-name")  
    $as.serverproperties  
}
```

Or

```powershell
#### this will display a Get-Credential prompt for interactive usage
Use-Impersonation ('DOMAIN\user', 'Interactive') { 
    "You are now impersonating user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
}

#### OR for clear text Parameter Signature 
Use-Impersonation ('DOMAIN', 'user', 'password', 'Interactive') { 
    "You are now impersonating user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
}
```