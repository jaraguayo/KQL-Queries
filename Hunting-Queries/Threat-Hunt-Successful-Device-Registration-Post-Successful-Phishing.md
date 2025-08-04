This rule detects successful device registrations to the 'Device Registration Service' in Azure Entra. It specifically looks for sign-in events where the ResourceDisplayName is 'Device Registration Service', the ErrorCode is '0' (indicating success), and the ConditionalAccessStatus is not '1' (which typically means that conditional access did not block the authentication flow for device registration).

The rule is pivotal for hunting devices registered for persistence, post-successful phishing campaign execution, where >= 1 accounts were compromised.

```
union AADSignInEventsBeta,AADSignInEventsBeta
| where AccountUpn contains @"@"
| where ResourceDisplayName =="Device Registration Service" and ErrorCode == "0" and ConditionalAccessStatus != 1
//Exclude your Organization's Proxy / Public CIDR
//| where not(ipv4_is_in_any_range(IPAddress,dynamic(["1.1.0.0/16", "0.0.0.0/16"])))
| where isnotempty(DeviceName) or isnotempty(AadDeviceId)
|summarize by AccountDisplayName,AccountUpn,IPAddress,Country,Application,ResourceDisplayName,CorrelationId,SessionId,DeviceAdded=DeviceName,AadDeviceId,OSPlatform,DeviceTrustType,AuthenticationRequirement,AuthenticationProcessingDetails
```
