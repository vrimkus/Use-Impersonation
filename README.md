## PowerShell wrapper around C# SimpleImpersonation.

Designed to emulate C# using syntax with impersonation.


```powershell
Use-Impersonation -Credential DOMAIN\user -LogonType NewCredentials {     
    sqlps
    $as = New-Object Microsoft.AnalysisServices.Server  
    $as.connect("server-name\instance-name")  
    $as.serverproperties  
}
```

Or

```powershell
Use-Impersonation ('DOMAIN', 'user', 'password', 'Interactive') { 
    Write-Output "You are now impersonating user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
}
```