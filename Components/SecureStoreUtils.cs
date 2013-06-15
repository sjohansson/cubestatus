using Microsoft.Office.SecureStoreService.Server;
using Microsoft.SharePoint;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;

namespace CubeStatus.Components
{
    public static class SecureStoreUtils
    {
        public static Dictionary<string, string> GetCredentials(string applicationID)
        {
            var serviceContext = SPServiceContext.Current;
            var secureStoreProvider = new SecureStoreProvider { Context = serviceContext };
            var credentialMap = new Dictionary<string, string>();
            using (var credentials = secureStoreProvider.GetCredentials(applicationID))
            {
                var fields = secureStoreProvider.GetTargetApplicationFields(applicationID);
                for (var i = 0; i < fields.Count; i++)
                {
                    var field = fields[i];
                    var credential = credentials[i];
                    var decryptedCredential = ToClrString(credential.Credential);
                    credentialMap.Add(field.Name, decryptedCredential);
                }
            }
            return credentialMap;
        }
        public static string ToClrString(this SecureString secureString)
        {
            var ptr = Marshal.SecureStringToBSTR(secureString);
            try
            {
                return Marshal.PtrToStringBSTR(ptr);
            }
            finally
            {
                Marshal.FreeBSTR(ptr);
            }
        }

    }
}
