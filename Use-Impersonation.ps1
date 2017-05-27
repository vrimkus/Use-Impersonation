function Use-Impersonation {
    <#
    .SYNOPSIS
        Function to allow executing a block of code using impersonation.
    .DESCRIPTION
        Function to allow executing a block of code, within the context of another Windows Principal.
        The WindowsImpersonationContext is disposed following completion of the ScriptBlock execution, 
        which restores the context back to the calling Windows Principal.

        The function is meant to emulate a C# using block by automatically disposing the Impersonation object.
    .PARAMETER ArgumentList
        List of arguments to be passed to the Impersonation object.
        
        This parameter is designed to simulate the C# using syntax when using SimpleImpersonation.Impersonation.
        This parameter is a member of the ArgumentList Parameter Set and can be used positionally.
    .PARAMETER Credential
        PSCredential object to be passed to the Impersonation object.
        
        This parameter is a member of the Credential Parameter Set and can only be used as a named parameter.
    .PARAMETER LogonType
        PowerShell.SimpleImpersonation.LogonType object to be passed to the Impersonation object. The argument specified
        to this parameter can be coerced from a string. 
        
        This parameter is a member of the Credential Parameter Set and can only be used as a named parameter.
    .PARAMETER ScriptBlock
        ScriptBlock object to be executed under the context of the supplied Windows Principal.
        
        This parameter is a member of all Parameter Sets and can be used positionally.
    .EXAMPLE
        PS C:\> Use-Impersonation ('DOMAIN', 'user', 'password', 'Interactive') { 
            "You are now impersonating user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        }

        This example demonstrates supplying the required arguments, in the form of an array and Scriptblock,
        as positional arguments. The code will perform an Interactive logon as user, DOMAIN\user, and then execute 
        the specified ScriptBlock. The context will be restored to the caller Windows Principal following completion.
    .EXAMPLE
        PS C:\> Use-Impersonation -Credential DOMAIN\user -LogonType NewCredentials {     
            sqlps
            $as = New-Object Microsoft.AnalysisServices.Server  
            $as.connect("server-name\instance-name")  
            $as.serverproperties  
        }

        This example demonstrates the other parameter set by supplying a PSCredential, LogonType, and ScriptBlck.        
        The Credential and LogonType parameters in this example are passed as named arguments, which is required for the parameter set.
        The code will perform an NewCredentials logon as user, DOMAIN\user, and then execute the specified ScriptBlock.  
    #>
    [CmdletBinding(DefaultParameterSetName = 'ArgumentList')]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ArgumentList')]
        [object[]] $ArgumentList,

        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential] $Credential,

        [Parameter(Mandatory = $true, ParameterSetName = 'Credential')]
        [object] $LogonType,
 
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Credential')]
        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = 'ArgumentList')]
        [scriptblock] $ScriptBlock
    )

    if ($PSCmdlet.ParameterSetName -eq 'ArgumentList' -and $ArgumentList.Count -ne 4) {
        throw New-Object ArgumentException(
            ('Invalid arguent specified. Signature: ' +
            '(string Domain, string UserName, string Password, string LogonType)'), 
            'ArgumentList'
        )
    }

    #region Type Loading
    try {
        if (-not ('PowerShell.SimpleImpersonation.Impersonation' -as [type])) {
            #### Add custom type
            Add-Type -TypeDefinition @' 
/*
The MIT License (MIT)
Copyright (c) 2013 Matt Johnson <mj1856@hotmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
using System;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Runtime.ConstrainedExecution;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;

namespace PowerShell.SimpleImpersonation
{
    [PermissionSet(SecurityAction.Demand, Name = "FullTrust")]
    public sealed class Impersonation : IDisposable
    {
        private readonly SafeTokenHandle _handle;
        private readonly WindowsImpersonationContext _context;

        public static Impersonation LogonUser(string domain, string username, string password, LogonType logonType)
        {
            return new Impersonation(domain, username, password, logonType);
        }

        public static Impersonation LogonUser(string domain, string username, SecureString password, LogonType logonType)
        {
            return new Impersonation(domain, username, password, logonType);
        }

        private Impersonation(string domain, string username, SecureString password, LogonType logonType)
        {
            IntPtr token;
            IntPtr passPtr = Marshal.SecureStringToGlobalAllocUnicode(password);
            bool success;
            try
            {
                success = NativeMethods.LogonUser(username, domain, passPtr, (int)logonType, 0, out token);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(passPtr);
            }
            CompleteImpersonation(success, token, out _handle, out _context);
        }

        private Impersonation(string domain, string username, string password, LogonType logonType)
        {
            IntPtr token;
            bool success = NativeMethods.LogonUser(username, domain, password, (int)logonType, 0, out token);
            CompleteImpersonation(success, token, out _handle, out _context);
        }

        private void CompleteImpersonation(bool success, IntPtr token, out SafeTokenHandle handle, out WindowsImpersonationContext context)
        {
            if (!success)
            {
                var errorCode = Marshal.GetLastWin32Error();
                if (token != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(token);
                }
                throw new ApplicationException(string.Format("Could not impersonate the elevated user.  LogonUser returned error code {0}.", errorCode));
            }
            handle = new SafeTokenHandle(token);
            context = WindowsIdentity.Impersonate(_handle.DangerousGetHandle());
        }

        public void Dispose()
        {
            _context.Dispose();
            _handle.Dispose();
        }
    }

    public enum LogonType
    {
        Interactive = 2,
        Network = 3,
        Batch = 4,
        Service = 5,
        Unlock = 7,
        NetworkCleartext = 8,
        NewCredentials = 9
    }

    internal class NativeMethods
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool LogonUser(String lpszUsername, String lpszDomain, IntPtr phPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

        [DllImport("kernel32.dll")]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
    }

    internal sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeTokenHandle(IntPtr handle)
            : base(true)
        {
            this.handle = handle;
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.CloseHandle(handle);
        }
    }
}
'@
        }
    } catch {
        throw New-Object System.TypeLoadException(
            'An error occurred while attempting to load PowerShell.SimpleImpersonation.Impersonation type definition.',
            $_.Exception
        )
    }
    #endregion Type Loading

    try {
        $impersonation = if ($PSCmdlet.ParameterSetName -eq 'Credential') {
            [PowerShell.SimpleImpersonation.Impersonation]::LogonUser(
                $Credential.GetNetworkCredential().Domain,
                $Credential.GetNetworkCredential().UserName,
                $Credential.Password,
                $LogonType
            )
        } else {
            [PowerShell.SimpleImpersonation.Impersonation]::LogonUser(
                $ArgumentList[0],  #### string    domain
                $ArgumentList[1],  #### string    username
                $ArgumentList[2],  #### string    password
                $ArgumentList[3]   #### LogonType logonType
            )
        }

        Write-Verbose "WindowsIdentity: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        $ScriptBlock.Invoke()

    } finally {
        if ($impersonation -is [IDisposable]) {
            $impersonation.Dispose()
        }
    }
}
