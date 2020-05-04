//LocalAdmin WMI Provider by Roger Zander

using System;
using System.Collections;
using System.Management.Instrumentation;
using System.DirectoryServices;
using System.Management;
using System.Security.Principal;


[assembly: WmiConfiguration(@"root\cimv2", HostingModel = ManagementHostingModel.LocalService)]
namespace LocalAdminWMIProvider
{
    [System.ComponentModel.RunInstaller(true)]
    public class MyInstall : DefaultManagementInstaller
    {
        public override void Install(IDictionary stateSaver)
        {
            base.Install(stateSaver);
            System.Runtime.InteropServices.RegistrationServices RS = new System.Runtime.InteropServices.RegistrationServices();

            try
            {
                new System.EnterpriseServices.Internal.Publish().GacInstall(System.Reflection.Assembly.GetExecutingAssembly().Location);
            }
            catch { }
        } 

        public override void Uninstall(IDictionary savedState)
        {
            
            try
            {
                ManagementClass MC = new ManagementClass(@"root\cimv2:Win32_LocalAdmins");
                MC.Delete();
            }
            catch { }

            try
            {
                base.Uninstall(savedState);
            }
            catch { }

            try
            {
                new System.EnterpriseServices.Internal.Publish().GacRemove(System.Reflection.Assembly.GetExecutingAssembly().Location);
            }
            catch { }
        }
    }

    [ManagementEntity(Name = "Win32_LocalAdmins")]
    public class LocalAdmins
    {
        [ManagementKey]
        public string Member { get; set; }

        [ManagementProbe]
        public string Type { get; set; }

        [ManagementProbe]
        public string SID { get; set; }

        /// <summary>
        /// The Constructor to create new instances of the LocalAdmins class...
        /// </summary>
        public LocalAdmins(string sMember, string sGUID, string sType)
        {
            Member = sMember;
            SID = sGUID;
            Type = sType;
        }

        /// <summary>
        /// This Function returns all members of the local Administrators group
        /// </summary>
        /// <returns></returns>
        [ManagementEnumerator]
        static public IEnumerable GetAdmins()
        {
            //Get the Builtin Administrators Group name based on the SID (S-1-5-32-544)
            SecurityIdentifier Sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            NTAccount LAdmins = (NTAccount)Sid.Translate(typeof(NTAccount)); 
   
            //Enumerate all members of the local Administrators Group 
            DirectoryEntry localMachine = new DirectoryEntry("WinNT://" + Environment.MachineName + ",Computer");
            DirectoryEntry admGroup = localMachine.Children.Find(LAdmins.Value.Split('\\')[1], "group");
                        
            foreach (object obj in (IEnumerable)admGroup.Invoke("members", null))
            {
                using (DirectoryEntry user = new DirectoryEntry(obj))
                {
                    string sName = user.Path;
                    sName = sName.Replace("WinNT://", "");
                    if (sName.Contains(Environment.MachineName))
                    {
                        //Remove the Domain Name if it's a local User / Group
                        sName = sName.Remove(0, sName.LastIndexOf("/") + 1);
                    }
                    string sSID = "";
                    try
                    {
                        //Get the SID from each User/Group
                        byte[] oSid = user.Properties["objectSid"].Value as byte[];
                        SecurityIdentifier SID = new SecurityIdentifier(oSid, 0);
                        sSID = SID.ToString();
                    }
                    catch { }

                    yield return new LocalAdmins(sName, sSID, user.SchemaClassName);
                }
            }
        }
    }

}
