##################################
# Created by mmdmustaman
# Date : 11 Sept 2020
##################################



# Output File Name
$filename = "$(get-date -f yyyy-MM-dd)_$($env:COMPUTERNAME)_ServerReport.txt"

"============================================================================"  | Out-File $filename
"Basic Information" | Out-File $filename -Append
"----------------------------------------------------------------------------"  | Out-File $filename -Append
"$env:COMPUTERNAME Server Report" | Out-File $filename -Append
"Date : $(get-date)" | Out-File $filename -Append
"User : $env:USERNAME" | Out-File $filename -Append
"" | Out-File $filename -Append
"============================================================================"  | Out-File $filename -Append
"Check Valid Server License" | Out-File $filename -Append
"----------------------------------------------------------------------------"  | Out-File $filename -Append
# Get valid server license

$lstat = DATA {

ConvertFrom-StringData -StringData @’

0 = Unlicensed

1 = Licensed

2 = OOB Grace

3 = OOT Grace

4 = Non-Genuine Grace

5 = Notification

6 = Extended Grace

‘@

}

function get-licensestatus {

param (

[parameter(ValueFromPipeline=$true,

   ValueFromPipelineByPropertyName=$true)]

  [string]$computername=”$env:COMPUTERNAME”

)

PROCESS {

 Get-WmiObject SoftwareLicensingProduct | where {$_.PartialProductKey} | select Name, @{N=”LicenseStatus”; E={$lstat[“$($_.LicenseStatus)”]} }

}}

get-licensestatus | ft -AutoSize  | Out-File $filename -Append



"============================================================================"  | Out-File $filename -Append
"Basic Networking" | Out-File $filename -Append
"----------------------------------------------------------------------------"  | Out-File $filename -Append
#Get networking info
$Table = @()

$Networks = Get-WmiObject Win32_NetworkAdapterConfiguration  -EA Stop | ? {$_.IPEnabled}

foreach ($Network in $Networks) {
$IPAddress  = $Network.IpAddress[0]
$SubnetMask  = $Network.IPSubnet[0]
$DefaultGateway = $Network.DefaultIPGateway
$DNSServers  = $Network.DNSServerSearchOrder
$WINS = @($WINS1,$WINS2)         
$IsDHCPEnabled = $false
If($network.DHCPEnabled) {
    $IsDHCPEnabled = $true
}
$MACAddress  = $Network.MACAddress
$OutputObj  = New-Object -Type PSObject
$OutputObj | Add-Member -MemberType NoteProperty -Name IPAddress -Value $IPAddress
$OutputObj | Add-Member -MemberType NoteProperty -Name SubnetMask -Value $SubnetMask
$OutputObj | Add-Member -MemberType NoteProperty -Name Gateway -Value ($DefaultGateway -join ",")      
$OutputObj | Add-Member -MemberType NoteProperty -Name IsDHCPEnabled -Value $IsDHCPEnabled
$OutputObj | Add-Member -MemberType NoteProperty -Name DNSServers -Value ($DNSServers -join ",")     
$OutputObj | Add-Member -MemberType NoteProperty -Name MACAddress -Value $MACAddress
$Table += $OutputObj 
}
$Table | ft -AutoSize | Out-File $filename -Append
"" | Out-File $filename -Append
"============================================================================"  | Out-File $filename -Append
"IP Route " | Out-File $filename -Append
"----------------------------------------------------------------------------"  | Out-File $filename -Append
#get ip route
Get-NetRoute | ft ifIndex, DestinationPrefix, NextHop, RouteMetric -AutoSize | Out-File $filename -Append
"" | Out-File $filename -Append

"============================================================================"  | Out-File $filename -Append
"TCP Window Tuning" | Out-File $filename -Append
"----------------------------------------------------------------------------"  | Out-File $filename -Append
#get auto tuning level
Get-NetTCPSetting | select settingname, AutoTuningLevelLocal  | Out-File $filename -Append
"============================================================================"  | Out-File $filename -Append
"VMNET3 RX Ring Buffer" | Out-File $filename -Append
"----------------------------------------------------------------------------"  | Out-File $filename -Append
Get-NetAdapterAdvancedProperty | ft -AutoSize | Out-File $filename -Append


"============================================================================"  | Out-File $filename -Append
"Memory Utilization" | Out-File $filename -Append
"----------------------------------------------------------------------------"  | Out-File $filename -Append

$os = Get-Ciminstance Win32_OperatingSystem
$pctFree = [math]::Round(($os.FreePhysicalMemory/$os.TotalVisibleMemorySize)*100,2)
 
if ($pctFree -ge 45) {
$Status = "OK"
}
elseif ($pctFree -ge 15 ) {
$Status = "Warning"
}
else {
$Status = "Critical"
}
 
$os | Select @{Name = "Status";Expression = {$Status}},
@{Name = "PctFree"; Expression = {$pctFree}},
@{Name = "FreeGB";Expression = {[math]::Round($_.FreePhysicalMemory/1mb,2)}},
@{Name = "TotalGB";Expression = {[int]($_.TotalVisibleMemorySize/1mb)}} | Out-File $filename -Append
"============================================================================"  | Out-File $filename -Append
"CPU Utilization" | Out-File $filename -Append
"----------------------------------------------------------------------------"  | Out-File $filename -Append

Get-WMIObject win32_processor | select @{name="CPU Utilization (%)" ;expression ={“{0:N2}” -f (get-counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 5 | select -ExpandProperty countersamples | select -ExpandProperty cookedvalue | Measure-Object -Average).average}} | Where-Object {[decimal]$_."CPU Utilization (%)" -gt [decimal]$cputhreshold} | Out-File $filename -Append

"============================================================================"  | Out-File $filename -Append
"Disk Utilization" | Out-File $filename -Append
"----------------------------------------------------------------------------"  | Out-File $filename -Append
Get-WmiObject Win32_logicaldisk | Format-Table SystemName, DeviceID, @{Name="Size(GB)";Expression={[decimal]("{0:N0}" -f($_.size/1gb))}}, @{Name="Used Space(GB)";Expression={[decimal]("{0:N0}" -f(($_.size-$_.freespace)/1gb))}}, @{Name="Free Space(GB)";Expression={[decimal]("{0:N0}" -f($_.freespace/1gb))}}, @{Name="Free (%)";Expression={"{0,6:P0}" -f(($_.freespace/1gb) / ($_.size/1gb))}} -AutoSize  | Out-File $filename -Append

"============================================================================"  | Out-File $filename -Append
"NTP Server Setting" | Out-File $filename -Append
"----------------------------------------------------------------------------"  | Out-File $filename -Append

w32tm /query /peers | Out-File $filename -Append
"============================================================================"  | Out-File $filename -Append
