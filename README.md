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
Use-Impersonation -LogonUserArguments ('DOMAIN', 'user', 'password', 'Interactive') { 
    Write-Output "You are now impersonating user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
}
#### OR
Use-Impersonation -ArgumentList ('DOMAIN', 'user', 'password', 'Interactive') { 
    Write-Output "You are now impersonating user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
}
```