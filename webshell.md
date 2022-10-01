
## Web Shell Threat Hunting

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
