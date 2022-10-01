
## Identifying the Attacker IP address from Microsoft 365 Defender alerts 


```python
let timeWindow = 3d; 
//Script file extensions to match on, can be expanded for your environment 
let scriptExtensions = dynamic([".asp", ".aspx", ".asmx", ".asax"]); 
SecurityAlert 
| where TimeGenerated > ago(timeWindow) 
| where ProviderName == "MDATP" 
//Parse and expand the alert JSON 
| extend alertData = parse_json(Entities) 
| mvexpand alertData 
| where alertData.Type == "file" 
//This can be expanded to include more file types 
| where alertData.Name has_any(scriptExtensions) 
| extend FileName = tostring(alertData.Name), Directory = tostring(alertData.Directory) 
| project TimeGenerated, FileName, Directory 
| join (  
W3CIISLog  
| where TimeGenerated > ago(timeWindow)  
| where csUriStem has_any(scriptExtensions)  
| extend splitUriStem = split(csUriStem, "/")  
| extend FileName = splitUriStem[-1] 
| summarize StartTime=min(TimeGenerated), EndTime=max(TimeGenerated) by AttackerIP=cIP, AttackerUserAgent=csUserAgent, SiteName=sSiteName, ShellLocation=csUriStem, tostring(FileName)  
) on FileName 
| project StartTime, EndTime, AttackerIP, AttackerUserAgent, SiteName, ShellLocation 
```


```python
  let alertTimeWindow = 1h;
  let logTimeWindow = 7d;
  // Define script extensions that suit your web application environment - a sample are provided below
  let scriptExtensions = dynamic([".php", ".jsp", ".js", ".aspx", ".asmx", ".asax", ".cfm", ".shtml"]); 
  let alertData = materialize(SecurityAlert 
  | where TimeGenerated > ago(alertTimeWindow) 
  | where ProviderName == "MDATP" 
  // Parse and expand the alert JSON 
  | extend alertData = parse_json(Entities) 
  | mvexpand alertData);
  let fileData = alertData
  // Extract web script files from MDATP alerts - our malicious web scripts - candidate webshells
  | where alertData.Type =~ "file" 
  | where alertData.Name has_any(scriptExtensions) 
  | extend FileName = tostring(alertData.Name), Directory = tostring(alertData.Directory);
  let hostData = alertData
  // Extract server details from alerts and map to alert id
  | where alertData.Type =~ "host"
  | project HostName = tostring(alertData.HostName), DnsDomain = tostring(alertData.DnsDomain), SystemAlertId
  | distinct HostName, DnsDomain, SystemAlertId;
  // Join the files on their impacted servers
  let webshellData = fileData
  | join kind=inner (hostData) on SystemAlertId 
  | project TimeGenerated, FileName, Directory, HostName, DnsDomain;
  webshellData
  | join (  
  // Find requests that were made to this file on the impacted server in the W3CIISLog table 
  W3CIISLog  
  | where TimeGenerated > ago(logTimeWindow) 
  // Restrict to accesses to script extensions 
  | where csUriStem has_any(scriptExtensions)
  | extend splitUriStem = split(csUriStem, "/")  
  | extend FileName = splitUriStem[-1], HostName = sComputerName
  // Summarize potential attacker activity
  | summarize count(), StartTime=min(TimeGenerated), EndTime=max(TimeGenerated), RequestUserAgents=make_set(csUserAgent), ReqestMethods=make_set(csMethod), RequestStatusCodes=make_set(scStatus), RequestCookies=make_set(csCookie), RequestReferers=make_set(csReferer), RequestQueryStrings=make_set(csUriQuery) by AttackerIP=cIP, SiteName=sSiteName, ShellLocation=csUriStem, tostring(FileName), HostName  
  ) on FileName, HostName
  | project StartTime, EndTime, AttackerIP, RequestUserAgents, HostName, SiteName, ShellLocation, ReqestMethods, RequestStatusCodes, RequestCookies, RequestReferers, RequestQueryStrings, RequestCount = count_
  // Expose the attacker ip address as a custom entity
  | extend timestamp=StartTime, IPCustomEntity = AttackerIP, HostCustomEntity = HostName
```
