/*
 * This project uses the Analysis Services dll, Microsoft.AnalysisServices.dll that must be downloaded and installed on each web front end that will run the web partcode. 
 * This is not part of the source code package... 
  * 
 */
namespace CubeStatus.Components
{
    using System;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Permissions;
    using System.Security.Principal;
    using System.Web.UI;
    using System.Web.UI.WebControls;
    using System.Web.UI.WebControls.WebParts;
    using Microsoft.AnalysisServices;
    using Microsoft.Office.SecureStoreService.Server;
    using Microsoft.Office.SecureStoreService;
    using Microsoft.SharePoint;
    using Microsoft.SharePoint.Security;
    using wsswebparts = Microsoft.SharePoint.WebPartPages;

    /// <summary>
    /// CubeStatus Webpart displays the state and status of an analysis cube from a SSAS database
    /// </summary>
    [SharePointPermission(SecurityAction.LinkDemand, ObjectModel = true)]
    [SharePointPermission(SecurityAction.InheritanceDemand, ObjectModel = true)]
    public class CubeStatus : wsswebparts.WebPart
    {
        private bool error = false;

        #region enums
        //enumeration of the different icons available for the status display, corresponds to image names in the images mapped folder
        public enum IconListEnum
        {
            Book,
            Bug,
            Circle,
            Cone,
            Cube,
            Flag,
            Flask,
            Pill,
            Pin,
            Puzzle,
            Shield,
            Star,
            Torso,
            Triangle
        }

        // The different authentication methods available for the communications with the SSAS server instance
        public enum AuthenticationMethods
        {
            Delegate,
            SpecificUser,
            SecureStoreId
        }

        #endregion

        #region private members

        //configurable web part properties
        string ssasServerName = "SSASServername";
        string userLoginName = "userName";
        string userLoginDomain = "Domain";
        string userLoginPassword = "Password";
        string ssasDatabaseName = "Database Name";
        string ssasCubeName = "Database Name";
        string secureStoreId = "Secure Store Id";

        private AuthenticationMethods authenticationMethod = AuthenticationMethods.Delegate;
        private IconListEnum iconList = IconListEnum.Star;

        #endregion

        #region Configurable Web Part Properties
        /*
         * Below are the configurable properties that are available 
         * in the "configure shared web part" dialog in SharePoint
         */

        //Holds the SSAS server name
        [
            Personalizable(PersonalizationScope.Shared),
            WebBrowsable(true),
            WebDisplayName("SSAS Server Name"),
            WebDescription("SSAS server name/address and instance to attach monitor to"),
            System.ComponentModel.Category("Cube Configuration")
        ]
        public string SsasServerName
        {
            get { return ssasServerName; }
            set { ssasServerName = value; }
        }

        //Holds the SSAS database to query
        [
            Personalizable(PersonalizationScope.Shared),
            WebBrowsable(true),
            WebDisplayName("Database Name"),
            WebDescription("SSAS Database to query"),
            System.ComponentModel.Category("Cube Configuration")
        ]
        public string SsasDatabaseName
        {
            get { return ssasDatabaseName; }
            set { ssasDatabaseName = value; }
        }

        //Holds the SSAS Cube to query
        [
            Personalizable(PersonalizationScope.Shared),
            WebBrowsable(true),
            WebDisplayName("Cube Name"),
            WebDescription("SSAS Cube to query"),
            System.ComponentModel.Category("Cube Configuration")
        ]
        public string SsasCubeName
        {
            get { return ssasCubeName; }
            set { ssasCubeName = value; }
        }

        //Holds the Authentication mode (Delegate users credentials, Specify login or use Secure Store id)
        [
            Personalizable(PersonalizationScope.Shared),
            WebBrowsable(true),
            WebDisplayName("Authentication mode"),
            WebDescription("Choose Authentication mode (Delegate, Specify username or use Secure Store"),
            System.ComponentModel.Category("Security Configuration")
        ]
        public AuthenticationMethods AuthenticationMethod
        {
            get { return authenticationMethod; }
            set { authenticationMethod = value; }
        }

        //Holds the Secure Store id
        [
            Personalizable(PersonalizationScope.Shared),
            WebBrowsable(true),
            WebDisplayName("Secure Store Id"),
            WebDescription("The Secure Store Id to use for authentication"),
            System.ComponentModel.Category("Security Configuration")
        ]
        public string SecureStoreId
        {
            get { return secureStoreId; }
            set { secureStoreId = value; }
        }

        //Holds the User login name
        [
            Personalizable(PersonalizationScope.Shared),
            WebBrowsable(true),
            WebDisplayName("Login Name"),
            WebDescription("User login name to use for impersonation"),
            System.ComponentModel.Category("Security Configuration")
        ]
        public string UserLoginName
        {
            get { return userLoginName; }
            set { userLoginName = value; }
        }

        //Holds the User domain
        [
            Personalizable(PersonalizationScope.Shared),
            WebBrowsable(true),
            WebDisplayName("Login Domain Name"),
            WebDescription("domain for login"),
            System.ComponentModel.Category("Security Configuration")
        ]
        public string UserLoginDomain
        {
            get { return userLoginDomain; }
            set { userLoginDomain = value; }
        }

        //Holds the password
        [
            Personalizable(PersonalizationScope.Shared),
            WebBrowsable(true),
            WebDisplayName("Login Password"),
            WebDescription("Login password to use for impersonation"),
            System.ComponentModel.Category("Security Configuration")
        ]
        public string UserLoginPassword
        {
            get { return userLoginPassword; }
            set { userLoginPassword = value; }
        }

        //Holds the icon/image choice
        [
            Personalizable(PersonalizationScope.Shared),
            WebBrowsable(true),
            WebDisplayName("Status Icon"),
            WebDescription("The icon to use to diplay the job status"),
            System.ComponentModel.Category("Appearance Configuration")
        ]
        public IconListEnum IconList
        {
            get { return iconList; }
            set { iconList = value; }
        }
        #endregion

        #region Impersonation Code

        /*
         * Code for impersionation of user from:
         * http://blog.softartisans.com/2011/07/14/solving-the-double-hop-issue-using-secure-store/
         */

        public const int LOGON32_LOGON_INTERACTIVE = 2;
        public const int LOGON32_PROVIDER_DEFAULT = 0;
        WindowsImpersonationContext impersonationContext;
        [DllImport("advapi32.dll")]
        public static extern int LogonUserA(String lpszUserName,
                                            String lpszDomain,
                                            String lpszPassword,
                                            int dwLogonType,
                                            int dwLogonProvider,
                                            ref IntPtr phToken);
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int DuplicateToken(IntPtr hToken,
                                                int impersonationLevel,
                                                ref IntPtr hNewToken);
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool RevertToSelf();
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern bool CloseHandle(IntPtr handle);

        private bool ImpersonateValidUser(String sername, String domain, String password)
        {
            WindowsIdentity tempWindowsIdentity;
            IntPtr token = IntPtr.Zero;
            IntPtr tokenDuplicate = IntPtr.Zero;
            if (RevertToSelf())
            {
                if (LogonUserA(sername, domain, password, LOGON32_LOGON_INTERACTIVE,
                    LOGON32_PROVIDER_DEFAULT, ref token) != 0)
                {
                    if (DuplicateToken(token, 2, ref tokenDuplicate) != 0)
                    {
                        tempWindowsIdentity = new WindowsIdentity(tokenDuplicate);
                        impersonationContext = tempWindowsIdentity.Impersonate();
                        if (impersonationContext != null)
                        {
                            CloseHandle(token);
                            CloseHandle(tokenDuplicate);
                            return true;
                        }
                    }
                }
            }
            if (token != IntPtr.Zero)
                CloseHandle(token);
            if (tokenDuplicate != IntPtr.Zero)
                CloseHandle(tokenDuplicate);
            return false;
        }

        private void UndoImpersonation()
        {
            impersonationContext.Undo();
        }



        #endregion

        /// <summary>
        /// build the resource address to the image icon to use.
        /// </summary>
        private string GetIconResourceString(IconListEnum icontype, string iconcolor)
        {
            string fileNamePrefix = "~/_layouts/15/Images/CubeStatus.Components/icons/";
            string fileNameSuffix = ".png";
            return fileNamePrefix + icontype + "_" + iconcolor + fileNameSuffix;
        }

        private void RenderCubeStatus(string olapServerName, string olapdb, string olapCube)
        {
            String connStr;

            olapServerName = SsasServerName;
            olapdb = SsasDatabaseName;
            olapCube = SsasCubeName;

            connStr = "Provider=MSOLAP;Data Source=" + olapServerName + ";";

            try
            {
                Server olapServer = new Server();
                olapServer.Connect(connStr);
                var foundDatabase = false;

                foreach (Database olapDatabase in olapServer.Databases)
                {
                    if (olapDatabase.Name.ToString() == olapdb)
                    {
                        foundDatabase = true;
                        var foundCube = false;
                        foreach (Cube olapCubex in olapDatabase.Cubes)
                        {
                            if (olapCubex.Name == olapCube)
                            {
                                foundCube = true;
                                this.Controls.Add(new LiteralControl("<table style='width: 600px'><tr><td rowspan='5' style='width: 50px'>"));

                                /*
                                 * create icon image from Cube state
                                 */
                                string cubeState;
                                try
                                {
                                    cubeState = olapCubex.State.ToString();
                                }
                                catch
                                {
                                    cubeState = "Unknown";
                                }

                                Image statusImage = new Image();
                                statusImage.ImageAlign = ImageAlign.Middle;

                                string statusImageUrl = "";
                                switch (cubeState)
                                {
                                    case "Processed":
                                        statusImageUrl = GetIconResourceString(iconList, "green");
                                        break;
                                    case "PartiallyProcessed":
                                        statusImageUrl = GetIconResourceString(iconList, "yellow");
                                        break;
                                    case "Unprocessed":
                                        statusImageUrl = GetIconResourceString(iconList, "red");
                                        break;
                                    case "Unknown":
                                    default:
                                        statusImageUrl = GetIconResourceString(iconList, "grey");
                                        break;
                                }

                                statusImage.ImageUrl = statusImageUrl;

                                this.Controls.Add(statusImage);

                                //todo: cleanup markup/styling
                                this.Controls.Add(new LiteralControl("</td>"));
                                try
                                {
                                    this.Controls.Add(new LiteralControl("<td style='width: 100px'>Cube</td><td style='width: 100px'>" + olapCubex.Name + "</td>"));
                                }
                                catch
                                {
                                    this.Controls.Add(new LiteralControl("<td>Cube</td><td>Unknown Name</td>"));
                                }

                                this.Controls.Add(new LiteralControl("</tr><tr>"));


                                try
                                {
                                    this.Controls.Add(new LiteralControl("<td>Description</td><td>" + olapCubex.Description.ToString() + "</td></tr>"));
                                }
                                catch
                                {
                                    this.Controls.Add(new LiteralControl("<td>Description</td><td>Unknown</td></tr>"));
                                }

                                this.Controls.Add(new LiteralControl("</tr><tr>"));

                                try
                                {
                                    this.Controls.Add(new LiteralControl("<td>Last Processed</td><td>" + olapCubex.LastProcessed.ToString("yyyy-MM-dd HH:mm:ss") + "</td>"));
                                }
                                catch
                                {
                                    this.Controls.Add(new LiteralControl("<td>Last Processed</td><td>Unknown</td>"));
                                }



                                this.Controls.Add(new LiteralControl("</tr><tr>"));
                                try
                                {
                                    this.Controls.Add(new LiteralControl("<td>State</td><td>" + olapCubex.State.ToString() + "</td>"));
                                }
                                catch
                                {
                                    this.Controls.Add(new LiteralControl("<td>State</td><td>Unknown</td>"));
                                }

                                this.Controls.Add(new LiteralControl("</tr>	<tr>"));
                                try
                                {
                                    this.Controls.Add(new LiteralControl("<td>Last schema update</td><td>" + olapCubex.LastSchemaUpdate.ToString("yyyy-MM-dd HH:mm:ss") + "</td>"));
                                }
                                catch
                                {
                                    this.Controls.Add(new LiteralControl("<td>Last schema update</td><td>Unknown</td>"));
                                }

                                this.Controls.Add(new LiteralControl("</tr></table>"));
                            }

                        }
                        if (!foundCube)
                        {
                            this.Controls.Add(new LiteralControl("Cube " + ssasCubeName + " not found..."));
                        }
                    }
                }
                if (!foundDatabase)
                {
                    this.Controls.Add(new LiteralControl("Database " + ssasDatabaseName + " not found..."));
                }
            }
            catch (Exception ex)
            {
                this.Controls.Add(new LiteralControl("Error: " + ex.Message + ", " + ex.InnerException));
            }
        }

        /// <summary>
        /// Creating controls
        /// </summary>
        protected override void CreateChildControls()
        {
            if (!this.error)
            {
                try
                {
                    base.CreateChildControls();

                    switch (AuthenticationMethod)
                    {
                        case AuthenticationMethods.SecureStoreId:
                            Dictionary<string, string> creds = SecureStoreUtils.GetCredentials(secureStoreId);

                            //Try to find user name and password from SSS, assume group mode and standard key names. If you use different key names etc, either update here or implement as parameters/web part properties in webpart

                            string sssUN = "";
                            string sssPW = "";

                            string userDomain = "";
                            string userName = "";

                            try
                            {
                                sssUN = creds["Windows User Name"];
                                sssPW = creds["Windows Password"];

                                int index = creds[@"Windows User Name"].IndexOf(@"\");

                                if (index >= 0)
                                {
                                    userDomain = sssUN.Substring(0, index);
                                    userName = sssUN.Substring(index + 1, sssUN.Length - index - 1);
                                }
                            }
                            catch (Exception ex)
                            {
                                this.Controls.Add(new LiteralControl("Unable to read information from SSS, exception: " + ex.Message));
                                break;
                            }
                            ImpersonateValidUser(userName, userDomain, sssPW);
                            break;

                        case AuthenticationMethods.SpecificUser:
                            ImpersonateValidUser(UserLoginName, UserLoginDomain, UserLoginPassword);
                            break;

                        case AuthenticationMethods.Delegate:

                            break;
                    }

                    RenderCubeStatus(SsasServerName, SsasDatabaseName, SsasCubeName);
                    UndoImpersonation();
                }

                catch (Exception ex)
                {
                    this.Controls.Add(new LiteralControl("Error: " + ex.Message));
                }
            }
        }

        protected override void OnLoad(EventArgs e)
        {
            if (!this.error)
            {
                try
                {
                    base.OnLoad(e);
                    this.EnsureChildControls();
                }
                catch (Exception ex)
                {
                    this.error = true;
                    this.Controls.Clear();
                    this.Controls.Add(new LiteralControl("Error: " + ex.Message));
                }
            }
        }
    }
}

