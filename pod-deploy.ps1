param(
	[Parameter(Mandatory=$true)] [String]$configFile,
	[switch]$deployESXi,
	[switch]$deployVCSA,
	[switch]$configureVCSA,
	[switch]$configureHosts,
	[switch]$configureVDSwitch,
	[switch]$configureVSAN,
	[switch]$deployNSXManager,
	[switch]$configureNSX,
	[switch]$deployvRAAppliance
)
Get-Module -ListAvailable VMware*,PowerNSX | Import-Module
if ( !(Get-Module -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) ) {
	throw "PowerCLI must be installed"
}
# Hat tips and thanks go to...
# William Lam http://www.virtuallyghetto.com/2016/11/vghetto-automated-vsphere-lab-deployment-for-vsphere-6-0u2-vsphere-6-5.html
# Rawlinson Riviera http://www.punchingclouds.com/2016/03/24/vmware-virtual-san-automated-deployments-powercli/
# Brian Graf http://www.vtagion.com/automatically-deploy-nsx-connect-vcenter/
# Anthony Burke https://networkinferno.net/license-nsx-via-automation-with-powercli

# Get the folder location
$ScriptLocation = Split-Path -Parent $PSCommandPath

# Import the JSON Config File
$podConfig = (get-content $($configFile) -Raw) | ConvertFrom-Json


$VCSAInstaller  = "$($ScriptLocation)\$($podConfig.sources.VCSAInstaller)"
$ESXiAppliance  = "$($ScriptLocation)\$($podConfig.sources.ESXiAppliance)"
$NSXAppliance   = "$($ScriptLocation)\$($podConfig.sources.NSXAppliance)"
$vRAAppliance   = "$($ScriptLocation)\$($podConfig.sources.vRAAppliance)"

# Log File
$verboseLogFile = "pod-deploy.log"

$StartTime = Get-Date

Function Write-Log {
	param(
		[Parameter(Mandatory=$true)]
		[String]$message,
		[switch]$Warning
	)
	$timeStamp = Get-Date -Format "dd-MM-yyyy hh:mm:ss"
	Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
	if($Warning){
		Write-Host -ForegroundColor Yellow " WARNING: $message"
	} else {
		Write-Host -ForegroundColor Green " $message"
	}
	$logMessage = "[$timeStamp] $message" | Out-File -Append -LiteralPath $verboseLogFile
}

function Get-VCSAConnection {
	param(
		[string]$vcsaName,
		[string]$vcsaUser,
		[string]$vcsaPassword
	)
	$existingConnection =  $global:DefaultVIServers | where-object -Property Name -eq -Value $vcsaName
	if($existingConnection -ne $null) {
		return $existingConnection;
	} else {
        $connection = Connect-VIServer -Server $vcsaName -User $vcsaUser -Password $vcsaPassword -WarningAction SilentlyContinue;
		return $connection;
	}
}

function Close-VCSAConnection {
	param(
		[string]$vcsaName
	)
	if($vcsaName.Length -le 0) {
		Disconnect-VIServer -Server $Global:DefaultVIServers -Confirm:$false
	} else {
		$existingConnection =  $global:DefaultVIServers | where-object -Property Name -eq -Value $vcsaName
        if($existingConnection -ne $null) {
		    Disconnect-VIServer -Server $existingConnection -Confirm:$false;
        } else {
            Write-Warning -Message "Could not find an existing connection named $($vcsaName)"
        }
	}
}

function Get-PodFolder {
	param(
		$vcsaConnection,
		[string]$folderPath
	)
	$folderArray = $folderPath.split("/")
	$parentFolder = Get-Folder -Server $vcsaConnection -Name vm
	foreach($folder in $folderArray) {
		$folderExists = Get-Folder -Server $vcsaConnection | Where-Object -Property Name -eq -Value $folder
		if($folderExists -ne $null) {
			$parentFolder = $folderExists
		} else {
			$parentFolder = New-Folder -Name $folder -Location $parentFolder
		}
	}
	return $parentFolder
}

if($deployESXi) {
	Write-Log "#### Deploying Nested ESXi VMs ####"
	Write-Log "Getting connection for $($podConfig.target.server)"
	$pVCSA = Get-VCSAConnection -vcsaName $podConfig.target.server -vcsaUser $podConfig.target.user -vcsaPassword $podConfig.target.password
	$pCluster = Get-Cluster -Name $podConfig.target.cluster -Server $pVCSA
	$pDatastore = Get-Datastore -Name $podConfig.target.datastore -Server $pVCSA
	$pPortGroup = Get-VDPortgroup -Name $podConfig.target.portgroup -Server $pVCSA
	$pFolder = Get-PodFolder -vcsaConnection $pVCSA -folderPath $podConfig.target.folder

	if ($pDatastore.Type -eq "vsan") {
		Write-Log "VSAN Datastore detected, checking Fake SCSI Reservations"
		$pHosts = Get-VMHost -Location $pCluster
		foreach($pHost in $pHosts) {
			$Setting = Get-AdvancedSetting -Entity $pHost -Name "VSAN.FakeSCSIReservations"
			if($Setting.Value -ne 1) {
				Write-Log "Setting FakeSCSIReservations on $($pHost)"
				Get-AdvancedSetting -Entity $pHost -Name "VSAN.FakeSCSIReservations" | Set-AdvancedSetting -Value 1 -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
			}
		}
	}

	$podConfig.esxi.hosts | ForEach-Object {
		Write-Log "Selecting a host from $($podConfig.target.cluster)"
		$pESXi = $pCluster | Get-VMHost -Server $pVCSA | where { $_.ConnectionState -eq "Connected" } | Get-Random
		Write-Log "$($pESXi) selected."

		$nestedESXiName = $_.name
		$nestedESXiIPAddress = $_.ip

		if((Get-VM | Where-Object -Property Name -eq -Value $nestedESXiName) -eq $null) {
			$ovfConfig = Get-ovfConfiguration -Ovf $ESXiAppliance
			$ovfConfig.Common.guestinfo.hostname.Value = $nestedESXiName
			$ovfConfig.Common.guestinfo.ipaddress.Value = $nestedESXiIPAddress
			$ovfConfig.Common.guestinfo.netmask.Value = $podConfig.target.network.netmask
			$ovfConfig.Common.guestinfo.gateway.Value = $podConfig.target.network.gateway
			$ovfConfig.Common.guestinfo.dns.Value = $podConfig.target.network.dns
			$ovfConfig.Common.guestinfo.domain.Value = $podConfig.target.network.domain
			$ovfConfig.Common.guestinfo.ntp.Value = $podConfig.target.network.ntp
			$ovfConfig.Common.guestinfo.syslog.Value = $podConfig.general.syslog
			$ovfConfig.Common.guestinfo.password.Value = $podConfig.general.password
			$ovfConfig.Common.guestinfo.ssh.Value = $podConfig.general.ssh
			$ovfConfig.Common.guestinfo.createvmfs.Value = $podConfig.esxi.createVMFS
			$ovfConfig.NetworkMapping.VM_Network.Value = $pPortGroup

			Write-Log "Deploying Nested ESXi VM $($nestedESXiName)"
			$importedVApp = Import-VApp -Server $pVCSA -VMHost $pESXi -Source $ESXiAppliance -ovfConfiguration $ovfConfig -Name $nestedESXiName -Location $pCluster -Datastore $pDatastore -DiskStorageFormat thin

			sleep 20

			$nestedESXiVM = Get-VM -Name $nestedESXiName -Server $pVCSA

			Write-Log "Updating vCPU Count to $($podConfig.esxi.cpu) & vMEM to $($podConfig.esxi.ram) GB"
			$nestedESXiVM | Set-VM -NumCpu $podConfig.esxi.cpu -MemoryGB $podConfig.esxi.ram -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

			Write-Log "Updating vSAN Caching VMDK size to $($podConfig.esxi.cacheDisk) GB"
			# Work around for VSAN issue with not enough disk space - delete and add new disk
			Get-HardDisk -VM $nestedESXiVM | where-object -Property "CapacityGB" -eq -Value 4 | Remove-HardDisk -DeletePermanently -Confirm:$false
			New-HardDisk -VM $nestedESXiVM -Persistence persistent -SizeGB $podConfig.esxi.cacheDisk -StorageFormat Thin | Out-File -Append -LiteralPath $verboseLogFile

			Write-Log "Updating vSAN Capacity VMDK size to $podConfig.esxi.capacityDisk GB"
			# Work around for VSAN issue with not enough disk space - delete and add new disk
			Get-HardDisk -VM $nestedESXiVM | where-object -Property "CapacityGB" -eq -Value 8 | Remove-HardDisk -DeletePermanently -Confirm:$false
			New-HardDisk -VM $nestedESXiVM -Persistence persistent -SizeGB $podConfig.esxi.capacityDisk -StorageFormat Thin | Out-File -Append -LiteralPath $verboseLogFile

			# Ensure the disks are marked as SSD
			New-AdvancedSetting -Entity $nestedESXiVM -Name 'scsi0:0.virtualSSD' -Value $true -Confirm:$false -Force | Out-File -Append -LiteralPath $verboseLogFile
			New-AdvancedSetting -Entity $nestedESXiVM -Name 'scsi0:1.virtualSSD' -Value $true -Confirm:$false -Force | Out-File -Append -LiteralPath $verboseLogFile
			New-AdvancedSetting -Entity $nestedESXiVM -Name 'scsi0:2.virtualSSD' -Value $true -Confirm:$false -Force | Out-File -Append -LiteralPath $verboseLogFile

			Write-Log "Moving $nestedESXiName to $($pFolder.Name) folder"
			Move-VM -VM $nestedESXiVM -Destination $pFolder | Out-File -Append -LiteralPath $verboseLogFile

			Write-Log "Powering On $nestedESXiName"
			Start-VM -VM $nestedESXiVM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
		} else {
			Write-Log "Nested ESXi host $($nestedESXiName) exists, skipping" -Warning
		}
	}
}

if($deployVCSA) {
	Write-Log "#### Deploying VCSA ####"
	Write-Log "Getting connection for $($podConfig.target.server)"
	$pVCSA = Get-VCSAConnection -vcsaName $podConfig.target.server -vcsaUser $podConfig.target.user -vcsaPassword $podConfig.target.password
	$pCluster = Get-Cluster -Name $podConfig.target.cluster -Server $pVCSA
	$pDatastore = Get-Datastore -Name $podConfig.target.datastore -Server $pVCSA
	$pPortGroup = Get-VDPortgroup -Name $podConfig.target.portgroup -Server $pVCSA
	$pFolder = Get-PodFolder -vcsaConnection $pVCSA -folderPath $podConfig.target.folder

	$config = (Get-Content -Raw "$($VCSAInstaller)\vcsa-cli-installer\templates\install\embedded_vCSA_on_VC.json") | convertfrom-json
	$config.'target.vcsa'.vc.hostname = $podConfig.target.server
	$config.'target.vcsa'.vc.username = $podConfig.target.user
	$config.'target.vcsa'.vc.password = $podConfig.target.password
	$config.'target.vcsa'.vc.datacenter = @($podConfig.target.datacenter)
	$config.'target.vcsa'.vc.datastore = $podConfig.target.datastore
	$config.'target.vcsa'.vc.target = @($podConfig.target.cluster)
	$config.'target.vcsa'.appliance.'deployment.network' = $podConfig.target.portgroup
	$config.'target.vcsa'.appliance.'thin.disk.mode' = $true
	$config.'target.vcsa'.appliance.'deployment.option' = $podConfig.vcsa.deploymentSize
	$config.'target.vcsa'.appliance.name = $podConfig.vcsa.name
	$config.'target.vcsa'.network.'ip.family' = "ipv4"
	$config.'target.vcsa'.network.mode = "static"
	$config.'target.vcsa'.network.ip = $podConfig.vcsa.ip
	$config.'target.vcsa'.network.'dns.servers'[0] = $podConfig.target.network.dns
	$config.'target.vcsa'.network.'dns.servers'[1] = $null
	$config.'target.vcsa'.network.prefix = $podConfig.target.network.prefix
	$config.'target.vcsa'.network.gateway = $podConfig.target.network.gateway
	$config.'target.vcsa'.network.hostname = $podConfig.vcsa.hostname
	$config.'target.vcsa'.os.password = $podConfig.vcsa.rootPassword
	$config.'target.vcsa'.sso.password = $podConfig.vcsa.sso.password
	$config.'target.vcsa'.sso.'domain-name' = $podConfig.vcsa.sso.domain
	$config.'target.vcsa'.sso.'site-name' = $podConfig.vcsa.sso.site
	if($podConfig.vcsa.sso.replicationPartner.length -gt 0) {
		# Join existing domain
		$config.'target.vcsa'.sso | Add-Member -Name "first-instance" -Value $false -MemberType NoteProperty
		$config.'target.vcsa'.sso | Add-Member -Name "replication-partner-hostname" -Value $replicationPartnerHostname -MemberType NoteProperty
	}

	Write-Log "Creating VCSA JSON Configuration file for deployment"
	$config | ConvertTo-Json | Set-Content -Path "$($ENV:Temp)\jsontemplate.json"

	Write-Log "Deploying the VCSA"
	if((Get-VM | Where-Object -Property Name -eq -Value $podConfig.vcsa.nam) -eq $null) {
		Write-Log "Disabling DRS on $($podConfig.target.cluster)"
		$pCluster | Set-Cluster -DrsEnabled:$false -Confirm:$false |  Out-File -Append -LiteralPath $verboseLogFile
		Invoke-Expression "$($VCSAInstaller)\vcsa-cli-installer\win32\vcsa-deploy.exe install --no-esx-ssl-verify --accept-eula $($ENV:Temp)\jsontemplate.json" -ErrorVariable vcsaDeployOutput 2>&1
		$vcsaDeployOutput | Out-File -Append -LiteralPath $verboseLogFile
		Write-Log "Moving $($podConfig.vcsa.name) to $($podConfig.target.folder)"
		Get-VM -Name $podConfig.vcsa.name | Move-VM -Destination $pFolder |  Out-File -Append -LiteralPath $verboseLogFile
		Write-Log "Enabling DRS on $($podConfig.target.cluster)"
		$pCluster | Set-Cluster -DrsEnabled:$true -Confirm:$false |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "VCSA exists, skipping" -Warning
	}

}


if($configureVCSA) {
	Write-Log "#### Configuring VCSA ####"
	Write-Log "Getting connection to the new VCSA"
	$nVCSA = Get-VCSAConnection -vcsaName $podConfig.vcsa.ip -vcsaUser "administrator@$($podConfig.vcsa.sso.domain)" -vcsaPassword $podConfig.vcsa.sso.password

	Write-Log "## Configuring Datacenter and Cluster ##"
	Write-Log "Creating Datacenter $($podConfig.vcsa.datacenter)"
	$nDatacenter = (Get-Datacenter -Server $nVCSA | Where-Object -Property Name -eq -Value $podConfig.vcsa.datacenter)
	if($nDatacenter -eq $null) {
		$nDatacenter = New-Datacenter -Server $nVCSA -Name $podConfig.vcsa.datacenter -Location (Get-Folder -Type Datacenter -Server $nVCSA)
	} else {
		Write-Log "Datacenter exists, skipping" -Warning
	}
	Write-Log "Creating VSAN Cluster $($podConfig.vcsa.cluster)"
	$nCluster = Get-Cluster -Server $nVCSA | Where-object -Property Name -eq -Value $podConfig.vcsa.cluster
	if($nCluster -eq $null) {
		$nCluster = New-Cluster -Server $nVCSA -Name $podConfig.vcsa.cluster -Location $nDatacenter -DrsEnabled
	} else {
		Write-Log "Cluster exists, skipping" -Warning
	}

	Write-Log "Licensing vSphere"
	$serviceInstance = Get-View ServiceInstance -Server $nVCSA
	$licenseManagerRef=$serviceInstance.Content.LicenseManager
	$licenseManager=Get-View $licenseManagerRef
	$licenseManager.AddLicense($podConfig.license.vcenter,$null) |  Out-File -Append -LiteralPath $verboseLogFile
	$licenseManager.AddLicense($podConfig.license.vsphere,$null) |  Out-File -Append -LiteralPath $verboseLogFile
	$licenseManager.AddLicense($podConfig.license.vsan,$null) |  Out-File -Append -LiteralPath $verboseLogFile
	$licenseManager.AddLicense($podConfig.license.nsx,$null) |  Out-File -Append -LiteralPath $verboseLogFile
	$licenseAssignmentManager = Get-View $licenseManager.LicenseAssignmentManager
	Write-Log "Assigning vCenter Server License"
	try {
		$licenseAssignmentManager.UpdateAssignedLicense($nVCSA.InstanceUuid, $podConfig.license.vcenter, $null) | Out-File -Append -LiteralPath $verboseLogFile
	}
	catch {
		$ErrorMessage = $_.Exception.Message
		Write-Log $ErrorMessage -Warning
	}


	if($configureHosts) {
		Write-Log "## Adding hosts to cluster ##"
		$nCluster = Get-Cluster -Name $podConfig.vcsa.cluster -Server $nVCSA
		$podConfig.esxi.hosts | ForEach-Object {
			$nestedESXiName = $_.name
			$nestedESXiIPAddress = $_.ip
			Write-Log "Adding ESXi host $nestedESXiIPAddress to Cluster"
			if((Get-VMHost -Server $nVCSA | Where-Object -Property Name -eq -Value $nestedESXiIPAddress) -eq $null) {
				Add-VMHost -Server $nVCSA -Location $nCluster -User "root" -Password $podConfig.general.password -Name $nestedESXiIPAddress -Force | Set-VMHost -LicenseKey $podConfig.license.vsphere -State "Maintenance" | Out-File -Append -LiteralPath $verboseLogFile
			} else {
				Write-Log "Host exists, skipping" -Warning
			}
		}
	}

	if($configureVDSwitch) {
		Write-Log "## Configuring Distributed Switching ##"
		$nHosts = Get-VMHost -Location $podConfig.vcsa.cluster -Server $nVCSA
		$nDatacenter = Get-Datacenter -Name $podConfig.vcsa.datacenter -Server $nVCSA
		$distributedSwitch = Get-VDSwitch -Server $nVCSA | Where-Object -Property Name -eq -Value $podConfig.vcsa.distributedSwitch
		if($distributedSwitch -eq $null) {
			Write-Log "Creating distributed switch"
			$distributedSwitch = New-VDSwitch -Name $podConfig.vcsa.distributedSwitch -Location $nDatacenter -Server $nVCSA
		} else {
			Write-Log "Distributed switch exists, skipping" -Warning
		}
		Write-Log "Adding hosts to distributed switch"
		foreach ($nHost in $nHosts) {
			if(($distributedSwitch | Get-VMHost | where {$_.Name -eq $nHost.Name}) -eq $null) {
				Add-VDSwitchVMHost -VDSwitch $distributedSwitch -VMHost $nHost
			} else {
				Write-Log "$($nHost) is already added to VDS" -Warning
			}
		}
		$dvPortGroup = Get-VDPortgroup | Where-Object -Property Name -eq -Value $podConfig.vcsa.portgroup
		if($dvPortGroup -eq $null) {
			Write-Log "Creating distributed port group"
			$dvPortGroup = New-VDPortgroup -Name $podConfig.vcsa.portgroup -NumPorts 1000 -VDSwitch $distributedSwitch
		} else {
			Write-Log "Distributed port group exists, skipping" -Warning
		}
		foreach($nHost in $nHosts) {
			Write-Log "Adding $($nHost.Name) vmnic1 to distributed switch"
			Add-VDSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter (Get-VMHostNetworkAdapter -Name "vmnic1" -VMHost $nHost) -DistributedSwitch $distributedSwitch -Confirm:$false
			Write-Log "Migrating $($nHost.Name) VMKernel to distributed switch"

			$VMHNA = Get-VMHostNetworkAdapter -VMHost $nHost -Name vmk0
			if($VMHNA.PortGroupName -eq $podConfig.vcsa.portgroup) {
				Write-Log "vmk0 on $($nHost.Name) is already assigned to the port group $($dvPortGroup)" -Warning
			} else {
				Set-VMHostNetworkAdapter -PortGroup $dvPortGroup -VirtualNic (Get-VMHostNetworkAdapter  -Name vmk0 -VMHost $nHost) -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
			}
			Start-Sleep -Seconds 5
			Write-Log "Moving $($nHost.Name) vmnic0 to distributed switch"
			Add-VDSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter (Get-VMHostNetworkAdapter -Name "vmnic0" -VMHost $nHost) -DistributedSwitch $distributedSwitch -Confirm:$false
		}
		Write-Log "Removing standard vSwitches"
		Get-VirtualSwitch -Server $nVCSA -Standard | Remove-VirtualSwitch -Confirm:$false
	}

	if($configureVSAN) {
		Write-Log "## Configuring VSAN ##"
		$VSANCluster = Get-Cluster -Name $podConfig.vcsa.cluster -Server $nVCSA
		if($VSANCluster.VsanEnabled) {
			Write-Log "VSAN is enabled, skipping" -Warning
		} else {
			$VSANCluster | Set-Cluster -VsanEnabled:$true -VsanDiskClaimMode Manual -Confirm:$false
			Write-Log "Assigning VSAN License"
			$serviceInstance = Get-View ServiceInstance -Server $nVCSA
			$licenseManagerRef=$serviceInstance.Content.LicenseManager
			$licenseManager=Get-View $licenseManagerRef
			$licenseAssignmentManager = Get-View $licenseManager.LicenseAssignmentManager
			$clusterRef = (Get-Cluster -Server $nVCSA -Name $podConfig.vcsa.cluster | get-view).MoRef
			try {
				$licenseAssignmentManager.UpdateAssignedLicense(($clusterRef.value), $podConfig.license.vsan, $null) | Out-File -Append -LiteralPath $verboseLogFile
			}
			catch {
				$ErrorMessage = $_.Exception.Message
				Write-Log $ErrorMessage -Warning
			}
		}

		$nHosts = Get-VMHost -Server $nVCSA -Location $podConfig.vcsa.cluster
		foreach ($nHost in $nHosts) {
			$luns = $nHost | Get-ScsiLun | Select-Object CanonicalName, CapacityGB
			if((Get-VsanDiskGroup -VMHost $nHost) -eq $null) {
				Write-Log "Querying ESXi host disks to create VSAN Diskgroups"
				foreach ($lun in $luns) {
					if(([int]($lun.CapacityGB)).toString() -eq "$($podConfig.esxi.cacheDisk)") {
						$vsanCacheDisk = $lun.CanonicalName
					}
					if(([int]($lun.CapacityGB)).toString() -eq "$($podConfig.esxi.capacityDisk)") {
						$vsanCapacityDisk = $lun.CanonicalName
					}
				}
				Write-Log "Creating VSAN DiskGroup for $nHost"
				New-VsanDiskGroup -Server $nVCSA -VMHost $nHost -SsdCanonicalName $vsanCacheDisk -DataDiskCanonicalName $vsanCapacityDisk | Out-File -Append -LiteralPath $verboseLogFile
			}
		}
	}
}

if($DeployNSXManager) {
	Write-Log "#### Deploying NSX Manager ####"
	Write-Log "Getting connection for $($podConfig.target.server)"
	$pVCSA = Get-VCSAConnection -vcsaName $podConfig.target.server -vcsaUser $podConfig.target.user -vcsaPassword $podConfig.target.password
	$pCluster = Get-Cluster -Name $podConfig.target.cluster -Server $pVCSA
	$pDatastore = Get-Datastore -Name $podConfig.target.datastore -Server $pVCSA
	$pPortGroup = Get-VDPortgroup -Name $podConfig.target.portgroup -Server $pVCSA
	$pFolder = Get-PodFolder -vcsaConnection $pVCSA -folderPath $podConfig.target.folder
	$pESXi = $pCluster | Get-VMHost -Server $pVCSA | where { $_.ConnectionState -eq "Connected" } | Get-Random

	if((Get-VM -Server $pVCSA | Where-Object -Property Name -eq -Value $podConfig.nsx.name) -eq $null) {
		$ovfconfig = @{
			"vsm_cli_en_passwd_0" = "$($podConfig.nsx.password)"
			"NetworkMapping.VSMgmt" = "$($podConfig.target.portgroup)"
			"vsm_gateway_0" = "$($podConfig.target.network.gateway)"
			"vsm_cli_passwd_0" = "$($podConfig.nsx.password)"
			"vsm_isSSHEnabled" = "$($podConfig.general.ssh)"
			"vsm_netmask_0" = "$($podConfig.target.network.netmask)"
			"vsm_hostname" = "$($podConfig.nsx.name).$($podConfig.target.network.domain)"
			"vsm_ntp_0" = "$($podConfig.target.network.ntp)"
			"vsm_ip_0" = "$($podConfig.nsx.ip)"
			"vsm_dns1_0" = "$($podConfig.target.network.dns)"
			"vsm_domain_0" = "$($podConfig.target.network.domain)"
		}
		Write-Log "Deploying NSX Manager OVA"
		$importedVApp = Import-VApp -Server $pVCSA -VMhost $pESXi -Source $podConfig.sources.NSXAppliance -OVFConfiguration $ovfconfig -Name $podConfig.nsx.name -Datastore $pDatastore -DiskStorageFormat thin
		$NSX = Get-VM -Name $podConfig.nsx.name -Server $pVCSA
		Write-Log "Moving $($podConfig.nsx.name) to $($podConfig.target.folder) folder"
		Move-VM -VM $NSX -Destination $pFolder |  Out-File -Append -LiteralPath $verboseLogFile
		Write-Log "Powering On $($podConfig.nsx.name)"
		Start-VM -Server $pVCSA -VM $NSX -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
		do {
			Sleep -Seconds 20
			$VM_View = Get-VM $podConfig.nsx.name -Server $pVCSA | Get-View
			$toolsStatus = $VM_View.Summary.Guest.ToolsRunningStatus
		} Until ($toolsStatus -eq "guestToolsRunning")
		Write-Log "$($podConfig.nsx.name) has booted up successfully, waiting for API"
		$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f "admin",$podConfig.nsx.password)))
		$header = @{Authorization=("Basic {0}" -f $base64AuthInfo)}
		$uri = "https://$($podConfig.nsx.ip)/api/2.0/vdn/controller"
		do {
			Start-Sleep -Seconds 20
			$result = try { Invoke-WebRequest -Uri $uri -Headers $header -ContentType "application/xml"} catch { $_.Exception.Response}
		} Until ($result.statusCode -eq "200")
		Write-Log "Connected to NSX API successfully"
	} else {
		Write-Log "NSX manager exists, skipping" -Warning
	}
}

if($configureNSX) {
	Write-Log "#### Configuring NSX Manager ####"
	Write-Log "Getting connection to the new VCSA"
	$nVCSA = Get-VCSAConnection -vcsaName $podConfig.vcsa.ip -vcsaUser "administrator@$($podConfig.vcsa.sso.domain)" -vcsaPassword $podConfig.vcsa.sso.password
	$nCluster = Get-Cluster -Server $nVCSA -Name $podConfig.vcsa.cluster
	Write-Log "Licensing NSX"
	$ServiceInstance = Get-View ServiceInstance
	$LicenseManager = Get-View $ServiceInstance.Content.licenseManager
	$LicenseAssignmentManager = Get-View $LicenseManager.licenseAssignmentManager
	$LicenseAssignmentManager.UpdateAssignedLicense("nsx-netsec",$podConfig.license.nsx,$NULL)
	Write-Log "Exiting host maintenance mode"
	Get-VMHost -Server $nVCSA | Set-VMHost -State Connected | Out-Null
	Write-Log "## Connect NSX Manager to vCenter ##"
	Connect-NSXServer $podConfig.nsx.ip -Username admin -Password $podConfig.nsx.password |  Out-File -Append -LiteralPath $verboseLogFile
	$NSXVC = Get-NsxManagerVcenterConfig
	if($NSXVC.Connected -ne $true) {
		Set-NsxManager -vcenterusername "administrator@$($podConfig.vcsa.sso.domain)" -vcenterpassword $podConfig.vcsa.sso.password -vcenterserver $podConfig.vcsa.ip |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "NSX Manager connected to vCenter"
	}
	$NSXSSO = Get-NsxManagerSsoConfig
	if($NSXSSO.Connected -ne $true) {
		Set-NsxManager -ssousername "administrator@$($podConfig.vcsa.sso.domain)" -ssopassword $podConfig.vcsa.sso.password -ssoserver $podConfig.vcsa.ip |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "NSX Manager connected to SSO"
	}
	if((Get-NsxIpPool -Name "Controllers") -eq $null) {
		New-NsxIPPool -Name "Controllers" -Gateway $podConfig.target.network.gateway -SubnetPrefixLength $podConfig.target.network.prefix -StartAddress $podConfig.nsx.controller.startIp -EndAddress $podConfig.nsx.controller.endIp -DnsServer1 $podConfig.target.network.dns -DnsSuffix $podConfig.target.network.domain |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "NSX IP Pool exists, skipping" -Warning
	}
	if((Get-NSXController) -eq $null) {
		$NSXPool = Get-NSXIPPool "Controllers"
		$NSXPortGroup = Get-VDPortGroup -Name $podConfig.vcsa.portgroup -Server $nVCSA
		$NSXDatastore = Get-Datastore -Name "vsanDatastore" -Server $nVCSA
		Write-Log "Deploying NSX Controller"
		$NSXController = New-NsxController -Cluster $nCluster -datastore $NSXDatastore -PortGroup $NSXPortGroup -IpPool $NSXPool -Password $podConfig.nsx.controller.password -Confirm:$false
		do {
			Sleep -Seconds 20
			$ControllerStatus = (Get-NSXController -ObjectId $NSXController.id).status
		} Until (($ControllerStatus -eq "RUNNING") -or ($ControllerStatus -eq $null))
		if($ControllerStatus -eq $null) {
			Write-Log "Controller deployment failed" -Warning
		} else {
			Write-Log "Controller deployed successfully"
		}
	} else {
		Write-Log "NSX Controller Exists, skipping" -Warning
	}
	Write-Log "## Preparing hosts ##"
	$clusterStatus = ($nCluster | Get-NsxClusterStatus | select -first 1).installed
	if($clusterStatus -eq "false") {
		Write-Log "Initiating installation of NSX agents"
		$nCluster | Install-NsxCluster | Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "Cluster is already installed" -Warning
	}
	Write-Log "Creating VTEP IP Pool"
	if((Get-NsxIpPool -Name "VTEPs") -eq $null) {
		New-NsxIPPool -Name "VTEPs" -Gateway $podConfig.target.network.gateway -SubnetPrefixLength $podConfig.target.network.prefix -StartAddress $podConfig.nsx.vtep.startIp -EndAddress $podConfig.nsx.vtep.endIp -DnsServer1 $podConfig.target.network.dns -DnsSuffix $podConfig.target.network.domain |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "VTEP IP Pool exists, skipping" -Warning
	}
	$nVDSwitch = Get-VDSwitch -Server $nVCSA -Name $podConfig.vcsa.distributedSwitch
	if((Get-NsxVdsContext) -eq $null) {
		Write-Log "Creating VDS Context"
		New-NsxVdsContext -VirtualDistributedSwitch $nVDSwitch -Teaming LOADBALANCE_SRCID -Mtu 1600 | Out-File -Append -LiteralPath $verboseLogFile
	}
	$vxlanStatus =  (Get-NsxClusterStatus $nCluster | where {$_.featureId -eq "com.vmware.vshield.vsm.vxlan" }).status
	if($vxlanStatus -ne "GREEN") {
		$nCluster | New-NsxClusterVxlanConfig -VirtualDistributedSwitch $nVDSwitch -ipPool (Get-NsxIpPool -Name "VTEPs") -VlanId 0 -VtepCount 2
	} else {
		Write-Log "VXLAN already configured, skipping" -Warning
	}
	# Change the NSX VXLAN UDP Port to enable nested ESXi, if you have NSX enabled on the
	# VDSwitch that hosts the nested environment, then you must change the port to something
	# that is different.
	Invoke-NsxRestMethod -Method PUT -URI "/api/2.0/vdn/config/vxlan/udp/port/8472"
	Write-Host "Creating Transport Zone"
	if((Get-NsxTransportZone -Name "TZ") -eq $null) {
		New-NSXTransportZone -Name "TZ" -Cluster $nCluster -ControlPlaneMode "UNICAST_MODE" | Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "Transport Zone exists, skipping" -warning
	}
}

# if($deployvRAAppliance) {
# 	Write-Log "Deploying vRealize Automation Appliance"
# 	$ovfConfig = Get-ovfConfiguration $vRAAppliance
# 	$ovfConfig.NetworkMapping.Network_1.value = $Network
# 	$ovfConfig.IpAssignment.IpProtocol.value = "IPv4"
# 	$ovfConfig.vami.VMware_vRealize_Appliance.ip0.value = $vRAAppIpAddress
# 	$ovfConfig.vami.VMware_vRealize_Appliance.netmask0.value = $podConfig.target.network.netmask
# 	$ovfConfig.vami.VMware_vRealize_Appliance.gateway.value = $podConfig.target.network.gateway
# 	$ovfConfig.vami.VMware_vRealize_Appliance.DNS.value = $podConfig.target.network.dns
# 	$ovfConfig.vami.VMware_vRealize_Appliance.domain.value  = $podConfig.target.network.domain
# 	$ovfConfig.vami.VMware_vRealize_Appliance.searchpath.value = $podConfig.target.network.domain
# 	$ovfConfig.common.varoot_password.value = $podConfig.general.password
# 	$ovfConfig.common.va_ssh_enabled.value = $podConfig.general.ssh
# 	$vRAVM = Import-VApp -Server $vCenter -VMHost $pEsxi -Source $vRAAppliance -ovfConfiguration $ovfConfig -Name $vRAAppName -Location $cluster -Datastore $datastore -DiskStorageFormat thin
# 	Write-Log "Moving $vRAAppName to $VMFolder"
# 	$vm = Get-VM -Name $vRAAppName
# 	$vm | Move-VM -Destination $folder | Out-File -Append -LiteralPath $verboseLogFile
# 	Write-Log "Powering on $vRAAppName"
# 	Start-VM -Server $vCenter -VM $vm -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
# }

Write-Log "Disconnecting from vCenter Servers"
Close-VCSAConnection

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes,2)

Write-Log "Pod Deployment Completed in $($duration) minutes"