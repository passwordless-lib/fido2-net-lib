using System;
using System.Collections.Generic;
using System.DirectoryServices;
using Fido2NetLib.Development;
using System.Linq;
using System.Threading.Tasks;

/*

dn: CN=fIDO-Authenticator-Aaguid,<SchemaContainerDN>
changetype: ntdsSchemaAdd
adminDescription: fIDO-Authenticator-Aaguid
adminDisplayName: fIDO-Authenticator-Aaguid
attributeID: 1.2.840.113556.1.8000.2554.54579.64576.60639.19922.45518.10745386.112824.2.2
attributeSyntax: 2.5.5.10
isSingleValued: TRUE
lDAPDisplayName: fIDOAuthenticatorAaguid
name: fIDO-Authenticator-Aaguid
oMSyntax: 4
objectCategory: CN=Attribute-Schema,<SchemaContainerDN>
objectClass: attributeSchema
rangeLower: 16
rangeUpper: 16
schemaIdGuid:: 6mK5hwhZRTG0yl5t5AB3WQ==


dn: CN=fIDO-Authenticator-Credential-Id,<SchemaContainerDN>
changetype: ntdsSchemaAdd
adminDescription: fIDO-Authenticator-Credential-Id
adminDisplayName: fIDO-Authenticator-Credential-Id
attributeID: 1.2.840.113556.1.8000.2554.54579.64576.60639.19922.45518.10745386.112824.2.1
attributeSyntax: 2.5.5.10
isSingleValued: TRUE
lDAPDisplayName: fIDOAuthenticatorCredentialId
name: fIDO-Authenticator-Credential-Id
oMSyntax: 4
objectCategory: CN=Attribute-Schema,<SchemaContainerDN>
objectClass: attributeSchema
rangeLower: 16
rangeUpper: 128
schemaIdGuid:: CW0AgPCsTwKMz0nVQKC3Xw==
searchFlags: 1


dn: CN=fIDO-Authenticator-Devices,<SchemaContainerDN>
changetype: ntdsSchemaAdd
adminDescription: fIDO-Authenticator-Devices
adminDisplayName: fIDO-Authenticator-Devices
defaultSecurityDescriptor: D:S:
governsID: 1.2.840.113556.1.8000.2554.54579.64576.60639.19922.45518.10745386.112824.1
lDAPDisplayName: fIDOAuthenticatorDevices
name: fIDO-Authenticator-Devices
objectCategory: CN=Class-Schema,<SchemaContainerDN>
objectClass: classSchema
objectClassCategory: 1
rDNAttID: cn
schemaIdGuid:: loYx5wh5TNqHYH8lAqrQnQ==
subClassOf: top
possSuperiors: user


dn:
changetype: ntdsSchemaModify
replace: schemaUpdateNow
schemaUpdateNow: 1
-


dn: CN=fIDO-Authenticator-Device,<SchemaContainerDN>
changetype: ntdsSchemaAdd
adminDescription: fIDO-Authenticator-Device
adminDisplayName: fIDO-Authenticator-Device
defaultSecurityDescriptor: D:S:
governsID: 1.2.840.113556.1.8000.2554.54579.64576.60639.19922.45518.10745386.112824.1.2
lDAPDisplayName: fIDOAuthenticatorDevice
name: fIDO-Authenticator-Device
objectCategory: CN=Class-Schema,<SchemaContainerDN>
objectClass: classSchema
objectClassCategory: 1
rDNAttID: cn
schemaIdGuid:: Pd68TF6uRXmql6LCWgtm0g==
subClassOf: top
possSuperiors: fIDOAuthenticatorDevices
mayContain: userCertificate
mayContain: logonCount
mayContain: fIDOAuthenticatorAaguid
mayContain: fIDOAuthenticatorCredentialId


dn:
changetype: ntdsSchemaModify
replace: schemaUpdateNow
schemaUpdateNow: 1
-

*/

namespace Fido2NetLib
{
    public class ActiveDirectoryStore
    {
        DirectoryEntry GetDevice(byte[] credentialId)
        {
            var queryGuid = "";
            foreach (var b in credentialId)
            {
                queryGuid += @"\" + b.ToString("x2");
            }
            var deviceresult = GetObjectFromFilter("(&(objectCategory=fIDOAuthenticatorDevice)(fIDOAuthenticatorCredentialId=" + queryGuid + "))");
            if (null != deviceresult)
            {
                return deviceresult.GetDirectoryEntry();
            }
            return null;
        }
        public void UpdateCounter(byte[] credentialId, uint counter)
        {
            var device = GetDevice(credentialId);
            if (null != device)
            {
                device.Properties["logonCount"].Value = Convert.ToInt32(counter);
                device.CommitChanges();
            }
        }
        DirectorySearcher GetSearcher(string filter, DirectoryEntry searchBase = null)
        {
            DirectoryEntry entry;
            if (null == searchBase)
                entry = new DirectoryEntry();
            else entry = searchBase;

            var search = new DirectorySearcher(entry)
            {
                Filter = filter
            };
            search.PropertiesToLoad.Add("fIDOAuthenticatorCredentialId");
            search.PropertiesToLoad.Add("userCertificate");
            search.PropertiesToLoad.Add("logonCount");
            search.PropertiesToLoad.Add("displayName");
            search.PropertiesToLoad.Add("sAMAccountName");
            search.PropertiesToLoad.Add("objectGUID");

            return search;
        }

        SearchResult GetObjectFromFilter(string filter, DirectoryEntry searchBase = null)
        {
            var search = GetSearcher(filter, searchBase);
            return search.FindOne();
        }
        SearchResultCollection GetObjectsFromFilter(string filter, DirectoryEntry searchBase = null)
        {
            var search = GetSearcher(filter, searchBase);
            return search.FindAll();
        }
        public User GetUser(string upn)
        {
            var entry = GetUserEntry(upn);
            return new User
            {
                DisplayName = entry.Properties["displayName"].Value.ToString(),
                Id = entry.Guid.ToByteArray(),
                Name = entry.Properties["sAMAccountName"].Value.ToString()
            };
        }
        public Task<List<StoredCredential>> GetCredentialsByUserHandleAsync(byte[] userHandle)
        {
            var storedCredentials = new List<StoredCredential>();
            var userGuid = new Guid(userHandle);
            var userentry = new DirectoryEntry("LDAP://<GUID=" + userGuid.ToString("D") + ">");
            var credentialCollection = GetObjectsFromFilter("(objectCategory=fIDOAuthenticatorDevice)", userentry);
            foreach (SearchResult device in credentialCollection)
            {
                var storedCred = new StoredCredential()
                {
                    Descriptor = new Objects.PublicKeyCredentialDescriptor()
                    {
                        Id = (byte[]) device.Properties["fIDOAuthenticatorCredentialId"][0],
                        Type = "public-key"
                    },
                    PublicKey = (byte[]) device.Properties["userCertificate"][0],
                    SignatureCounter = Convert.ToUInt32(device.Properties["logonCount"][0]),
                    UserHandle = userHandle,
                    UserId = userHandle
                };
                storedCredentials.Add(storedCred);
            }
            return Task.FromResult(storedCredentials.Where(c => c.UserHandle.SequenceEqual(userHandle)).ToList());
        }
        public List<StoredCredential> GetCredentialsByUser(User user)
        {
            var results = GetCredentialsByUserHandleAsync(user.Id);
            return results.Result;
        }
        public Task<List<User>> GetUsersByCredentialIdAsync(byte[] credentialId)
        {
            var entry = GetCredentialOwnerById(credentialId);
            if (null == entry)
                return Task.FromResult(new List<User>());

            var storedUsers = new List<User>()
            {
                new User()
                {
                    DisplayName = entry.Properties["displayName"].Value.ToString(),
                    Id = entry.Guid.ToByteArray(),
                    Name = entry.Properties["sAMAccountName"].Value.ToString()
                }
            };
            return Task.FromResult(storedUsers);
        }
        private DirectoryEntry GetUserEntry(string upn)
        {
            var result = GetObjectFromFilter("(&(objectCategory=user)(userPrincipalName=" + upn + "))");
            if (null == result)
                throw new Fido2VerificationException("User not found in active directory");
            else return result.GetDirectoryEntry();
        }
        private DirectoryEntry GetUserEntry(byte[] objectGuid)
        {
            var userGuid = new Guid(objectGuid);
            var userentry = new DirectoryEntry("LDAP://<GUID=" + userGuid.ToString("D") + ">");
            if (null == userentry)
                throw new Fido2VerificationException("User not found in active directory");
            else return userentry;
        }
        DirectoryEntry AddDevicesContainerIfNotExists(DirectoryEntry entry)
        {
            var devicesresult = GetObjectFromFilter("(objectCategory=fIDOAuthenticatorDevices)", entry);
            if (null == devicesresult)
            {
                var devices = entry.Children.Add("CN=FIDO Authenticator Devices", "fIDOAuthenticatorDevices");
                devices.CommitChanges();
                return devices;
            }
            else return devicesresult.GetDirectoryEntry();
        }
        public void AddCredentialToUser(User user, StoredCredential credential)
        {
            var result = GetUserEntry(user.Id);
            if (null != result)
            {
                var devices = AddDevicesContainerIfNotExists(result);
                if (null != devices)
                {
                    if (null != GetDevice(credential.Descriptor.Id))
                        throw new Fido2VerificationException("Device already registered to user");

                    else
                    {
                        var device = devices.Children.Add("CN=" + BitConverter.ToString(credential.Descriptor.Id, 0, 32).Replace("-", ""), "fIDOAuthenticatorDevice");
                        device.CommitChanges();
                        device.Properties["fIDOAuthenticatorCredentialId"].Value = credential.Descriptor.Id;
                        device.Properties["userCertificate"].Value = credential.PublicKey;
                        device.Properties["logonCount"].Value = Convert.ToInt32(credential.SignatureCounter);
                        device.CommitChanges();
                    }
                }
                else throw new Fido2VerificationException("Unable to create devices container");
            }
            else throw new Fido2VerificationException("User not found");
        }
        public DirectoryEntry GetCredentialOwnerById(byte[] id)
        {
            var queryGuid = "";
            foreach (byte b in id)
            {
                queryGuid += @"\" + b.ToString("x2");
            }

            var result = GetObjectFromFilter("(&(objectCategory=fIDOAuthenticatorDevice)(fIDOAuthenticatorCredentialId=" + queryGuid + "))");

            if (null == result)
                return null;

            var device = result.GetDirectoryEntry();
            var devicecontainer = device.Parent;
            var user = devicecontainer.Parent;

            return user;
        }
        public StoredCredential GetCredentialById(byte[] id)
        {
            try
            {
                var queryGuid = "";
                foreach (byte b in id)
                {
                    queryGuid += @"\" + b.ToString("x2");
                }

                var result = GetObjectFromFilter("(&(objectCategory=fIDOAuthenticatorDevice)(fIDOAuthenticatorCredentialId=" + queryGuid + "))");

                if (null != result)
                {
                    var device = result.GetDirectoryEntry();
                    var cred = new StoredCredential
                    {
                        Descriptor = new Objects.PublicKeyCredentialDescriptor()
                        {
                            Id = (byte[])device.Properties["fIDOAuthenticatorCredentialId"].Value,
                            Type = "public-key"
                        },
                        PublicKey = (byte[])device.Properties["userCertificate"].Value,
                        SignatureCounter = Convert.ToUInt32(device.Properties["logonCount"].Value),
                        UserHandle = device.Parent.Parent.Guid.ToByteArray(),
                        UserId = device.Parent.Parent.Guid.ToByteArray()
                    };
                    return cred;
                }
                else throw new Fido2VerificationException("User not found in active directory");
            }
            catch (Exception e)
            {
                Console.WriteLine("Exception caught:\n\n" + e.ToString());
            }
            return null;
        }
    }
}
