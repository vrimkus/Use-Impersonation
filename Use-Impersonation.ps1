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
        
        This parameter is designed to simulate the C# using keyword syntax with SimpleImpersonation.Impersonation.
        This parameter accepts multiple parameter signatures, determined by the argument count and object types.

        Parameter Signatures:
            (PSCredential credential, PowerShell.SimpleImpersonation.LogonType logonType)
            (string domain, string userName, SecureString password, PowerShell.SimpleImpersonation.LogonType logonType)
            (string domain, string userName, string password, PowerShell.SimpleImpersonation.LogonType logonType)
            
        Type transformation will be attempted if specifying a string as the PSCredential credential argument.  
    .PARAMETER ScriptBlock
        ScriptBlock object to be executed under the context of the supplied Windows Principal. Mandatory with all parameter sets.
        
        This parameter  can be used positionally or as a named parameter argument.
    .PARAMETER Credential
        PSCredential object to be passed to the Impersonation object. Mandatory with Named parameter set.
        
        This parameter is available as a named parameter when ArgumentList is not specified.
    .PARAMETER LogonType
        PowerShell.SimpleImpersonation.LogonType object to be passed to the Impersonation object. The argument specified
        to this parameter can be coerced from a string. Mandatory with Named parameter set.
        
        This parameter is available as a named parameter when ArgumentList is not specified.
    .EXAMPLE
        PS C:\> Use-Impersonation -Credential DOMAIN\user -LogonType Batch {     
            sqlps
            $as = New-Object Microsoft.AnalysisServices.Server  
            $as.connect("server-name\instance-name")  
            $as.serverproperties  
        }

        This example demonstrates the other parameter set by supplying a PSCredential, LogonType, and ScriptBlck.        
        The Credential and LogonType parameters in this example are passed as named arguments, which is required for the parameter set.
        The code will perform an NewCredentials logon as user, DOMAIN\user, and then execute the specified ScriptBlock.  
    .EXAMPLE
        PS C:\> Use-Impersonation ('DOMAIN', 'user', 'password', 'Interactive') { 
            "You are now impersonating user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        }

        This example demonstrates supplying the required arguments, in the form of an array to ArgumentList, and Scriptblock as positional arguments.
        Since there are four options included in the specified array, the Parameter Signature using clear text credentials is selected.
        The code will perform an Interactive logon as user, DOMAIN\user, and then execute the specified ScriptBlock. 
        The context will be restored to the caller Windows Principal following completion.
    .EXAMPLE
        PS C:\> Use-Impersonation ('DOMAIN\user', 'Interactive') { 
            "You are now impersonating user $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        }

        This example demonstrates supplying the required arguments, in the form of an array to ArgumentList, and Scriptblock as positional arguments.
        Since there are twp options included in the specified array, the Parameter Signature using a PSCredential is selected.
        If the first option to ArgumentList is a string, a credential will try to be obtained with a prompt. 
        The code will perform an Interactive logon as user, DOMAIN\user, and then execute the specified ScriptBlock. 
        The context will be restored to the caller Windows Principal following completion.
    #>
    [CmdletBinding(DefaultParameterSetName = 'ArgumentList')]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ArgumentList')]
        [object[]] $ArgumentList,

        [Parameter(Mandatory = $true, Position = 1)]
        [scriptblock] $ScriptBlock,

        [Parameter(Mandatory = $true, ParameterSetName = 'Named')]
        [ValidateSet('Interactive', 'Network', 'Batch', 'Service', 'Unlock', 'NetworkCleartext', 'NewCredentials')]
        $LogonType,

        [Parameter(Mandatory = $true, ParameterSetName = 'Named')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()] $Credential
    )
    #region Custom Parameter Validation
    #### The custom parameter set we are trying to achieve will not work with built-in ParameterValidation
    #### But we can manually parse the input to make determinations about which parameter set is desired.
    if ($PSCmdlet.ParameterSetName -eq 'ArgumentList') {
        if ($ArgumentList.Count -eq 2) {
            #### ArgumentList Signature: 
            #### [0]   PSCredential  domain
            #### [1]   LogonType     logonType
            if (([System.Management.Automation.PSCredential], [string]) -contains $ArgumentList[0].GetType()) {
                #### The Credential() attribute declaration will treat this like it was an original 
                #### command line parameter argument, even when it is a member of a different parameter set.
                $Credential = $ArgumentList[0]
            }
            if ($null -eq $Credential) {
                throw New-Object System.Management.Automation.ParameterBindingException(
                    "Cannot process argument transformation on parameter 'Credential': $($ArgumentList[0])"
                )
            }
            
            $LogonType = $ArgumentList[1]
        
        } elseif ($ArgumentList.Count -eq 4) {
            #### ArgumentList Signature: 
            #### [0]   string        domain
            #### [1]   string        userName
            #### [2]   SecureString  password  or  string password
            #### [3]   LogonType     logonType
            $password = if ($ArgumentList[2] -is [System.Security.SecureString]) {
                $ArgumentList[2]
            } elseif ($ArgumentList[2] -is [string]) {
                $ArgumentList[2] | ConvertTo-SecureString -AsPlainText -Force
            }
            $Credential = New-Object System.Management.Automation.PSCredential(
                ('{0}\{1}' -f $ArgumentList[0], $ArgumentList[1]), #### string        userName
                $password                                           #### SecureString  password
            )
            
            $LogonType = $ArgumentList[3]
        } else {
            throw New-Object ArgumentException(
                ("Specified data object does not match any available signtures:`r`n" + 
                    "    (PSCredential credential)`r`n" + 
                    "    (string domain, string userName, SecureString password)`r`n" + 
                    "    (string domain, string userName, string password)"),
                'ArgumentList'
            )
        }
    }
    #endregion Custom Parameter Validation

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
        $impersonation = [PowerShell.SimpleImpersonation.Impersonation]::LogonUser(
            $Credential.GetNetworkCredential().Domain,
            $Credential.GetNetworkCredential().UserName,
            $Credential.Password,
            $LogonType
        )

        Write-Verbose "Executing as WindowsIdentity: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        
        . $ScriptBlock
        
        Write-Verbose 'Execution completed.'
    } finally {
        if ($impersonation -is [IDisposable]) {
            $impersonation.Dispose()
            Write-Verbose 'WindowsImpersonationContext restored.'
        }
    }
}
