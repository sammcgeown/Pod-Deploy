param(
	[Parameter(Mandatory=$true)] [String]$configFile,
	[switch]$deployESXi,
	[switch]$deployVCSA,
	[switch]$configureVCSA,
	[switch]$licenseVCSA,
	[switch]$configureHosts,
	[switch]$configureVDSwitch,
	[switch]$configureVSAN,
	[switch]$deployNSXManager,
	[switch]$configureNSX,
	[switch]$deployvRAAppliance
)
try {
	Get-Module -ListAvailable VMware.PowerCLI,PowerNSX | Import-Module -ErrorAction SilentlyContinue
}
catch {}
finally {}

if ( !(Get-Module -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) ) {
	throw "PowerCLI must be installed"
}
# Hat tips and thanks go to...
# William Lam http://www.virtuallyghetto.com/2016/11/vghetto-automated-vsphere-lab-deployment-for-vsphere-6-0u2-vsphere-6-5.html
# Rawlinson Riviera http://www.punchingclouds.com/2016/03/24/vmware-virtual-san-automated-deployments-powercli/
# Brian Graf http://www.vtagion.com/automatically-deploy-nsx-connect-vcenter/
# Anthony Burke https://networkinferno.net/license-nsx-via-automation-with-powercli

# Get the folder location
#$ScriptLocation = Split-Path -Parent $PSCommandPath

# Import the JSON Config File
$podConfig = (get-content $($configFile) -Raw) | ConvertFrom-Json


# Log File
$verboseLogFile = $podConfig.general.log

$StartTime = Get-Date

# Platform independant temp directory...
if($env:TMPDIR) { $temp = $env:TMPDIR } elseif ($env:TMP) { $temp = $env:TMP } else { $temp = "/tmp" }

# There must be an easier way than this...
switch ($PSVersionTable.PSEdition) {
	"Core" {
		# Mac, Linux or Windows
		if($PSVersionTable.OS -match "Darwin") {
			# Mac
			$vcsaDeploy = "$($podConfig.sources.VCSAInstaller)/vcsa-cli-installer/mac/vcsa-deploy"
		} elseif ($PSVersionTable.OS -match "Linux") {
			# Linux
			$vcsaDeploy = "$($podConfig.sources.VCSAInstaller)/vcsa-cli-installer/lin64/vcsa-deploy"
		} else {
			# Windows
			$vcsaDeploy = "$($podConfig.sources.VCSAInstaller)\vcsa-cli-installer\win32\vcsa-deploy.exe"
		}
	}
	"Desktop" {
		# Windows
		$vcsaDeploy = "$($podConfig.sources.VCSAInstaller)\vcsa-cli-installer\win32\vcsa-deploy.exe"
	}
}
$externalPSCconfig = "$($podConfig.sources.VCSAInstaller)\vcsa-cli-installer\templates\install\PSC_first_instance_on_VC.json"
$externalVCSAconfig = "$($podConfig.sources.VCSAInstaller)\vcsa-cli-installer\templates\install\vCSA_on_VC.json"
$embeddedVCSAconfig = "$($podConfig.sources.VCSAInstaller)\vcsa-cli-installer\templates\install\embedded_vCSA_on_VC.json"

Function Write-Log {
	param(
		[Parameter(Mandatory=$true)]
		[String]$Message,
		[switch]$Warning,
		[switch]$Info
	)
	$timeStamp = Get-Date -Format "dd-MM-yyyy hh:mm:ss"
	Write-Host -NoNewline -ForegroundColor White "[$timestamp]"
	if($Warning){
		Write-Host -ForegroundColor Yellow " WARNING: $message"
	} elseif($Info) {
		Write-Host -ForegroundColor White " $message"
	}else {
		Write-Host -ForegroundColor Green " $message"
	}
	"[$timeStamp] $message" | Out-File -Append -LiteralPath $verboseLogFile
}

function Get-VcConnection {
	param(
		[string]$vcsaName,
		[string]$vcsaUser,
		[string]$vcsaPassword
	)
	#Write-Log "Getting connection for $($vcsaName)"
	$existingConnection =  $global:DefaultVIServers | Where-Object -Property Name -eq -Value $vcsaName
	if($existingConnection -ne $null) {
		return $existingConnection;
	} else {
        $connection = Connect-VIServer -Server $vcsaName -User $vcsaUser -Password $vcsaPassword -WarningAction SilentlyContinue;
		return $connection;
	}
}

function Close-VcConnection {
	param(
		[string]$vcsaName
	)
	if($vcsaName.Length -le 0) {
		if($Global:DefaultVIServers.count -ge 0) {
	        Write-Log -Message "Disconnecting from all vCenter Servers"
			Disconnect-VIServer -Server $Global:DefaultVIServers -Confirm:$false
		}
	} else {
		$existingConnection =  $global:DefaultVIServers | where-object -Property Name -eq -Value $vcsaName
        if($existingConnection -ne $null) {
            Write-Log -Message "Disconnecting from $($vcsaName)"
			Disconnect-VIServer -Server $existingConnection -Confirm:$false;
        } else {
            Write-Log -Message "Could not find an existing connection named $($vcsaName)" -Warning
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

Write-Log "#### Validating Configuration ####"
Write-Log "### Testing Sources"
if(Test-Path -Path $podConfig.sources.VCSAInstaller) { Write-Log "VCSA Source: OK" -Info } else { Write-Log "VCSA Source: Failed" -Warning; $preflightFailure = $true }
if(Test-Path -Path $podConfig.sources.ESXiAppliance) { Write-Log "ESXi Source: OK" -Info } else { Write-Log "ESXi Source: Failed" -Warning; $preflightFailure = $true }
if(Test-Path -Path $podConfig.sources.NSXAppliance) { Write-Log "NSX Source: OK" -Info } else { Write-Log "NSX Source: Failed" -Warning; $preflightFailure = $true }
Write-Log "### Validating Target"
$pVCSA = Get-VcConnection -vcsaName $podConfig.physical.server -vcsaUser $podConfig.physical.user -vcsaPassword $podConfig.physical.password -ErrorAction SilentlyContinue
if($pVCSA) { Write-Log "Physical VCSA: OK" -Info } else { Write-Log "Physical VCSA: Failed" -Warning; $preflightFailure = $true }
$pCluster = Get-Cluster -Name $podConfig.physical.cluster -Server $pVCSA -ErrorAction SilentlyContinue
if($pCluster) { Write-Log "Physical Cluster: OK" -Info } else { Write-Log "Physical Cluster: Failed" -Warning; $preflightFailure = $true }
$pDatastore = Get-Datastore -Name $podConfig.physical.datastore -Server $pVCSA -ErrorAction SilentlyContinue
if($pDatastore) { Write-Log "Physical Datastore: OK" -Info } else { Write-Log "Physical Datastore: Failed" -Warning; $preflightFailure = $true }
$pPortGroup = Get-VDPortgroup -Name $podConfig.physical.portgroup -Server $pVCSA -ErrorAction SilentlyContinue
if($pPortGroup) { Write-Log "Physical Portgroup: OK" -Info } else { Write-Log "Physical Portgroup: Failed" -Warning; $preflightFailure = $true }
if($pPortGroup.ExtensionData.Config.DefaultPortConfig.SecurityPolicy.AllowPromiscuous.Value -eq "Accept") {   Write-Log "Physical Portgroup (Promiscuous mode): OK" -Info } else { Write-Log "Physical Portgroup: Promiscuous mode denied" -Warning; $preflightFailure = $true }
if($pPortGroup.ExtensionData.Config.DefaultPortConfig.SecurityPolicy.ForgedTransmits.Value -eq "Accept") {   Write-Log "Physical Portgroup (Forged transmits): OK" -Info } else { Write-Log "Physical Portgroup: Forged transmits denied" -Warning; $preflightFailure = $true }
$pFolder = Get-PodFolder -vcsaConnection $pVCSA -folderPath $podConfig.physical.folder -ErrorAction SilentlyContinue
if($pFolder) { Write-Log "Physical Folder: OK" -Info } else { Write-Log "Physical Folder: Failed" -Warning; $preflightFailure = $true }
$pHost = $pCluster | Get-VMHost -Server $pVCSA  -ErrorAction SilentlyContinue | Where-Object { $_.ConnectionState -eq "Connected" } | Get-Random
if($pHost) { Write-Log "Physical Host: OK" -Info } else { Write-Log "Physical Host: Failed" -Warning; $preflightFailure = $true }


if($preflightFailure) {
	Write-Log "#### Aborting - please fix pre-flight configuration errors ####" -Warning
	Close-VcConnection
	return;
}

if($deployESXi) {
	Write-Log "#### Deploying Nested ESXi VMs ####"
	$pVCSA = Get-VcConnection -vcsaName $podConfig.physical.server -vcsaUser $podConfig.physical.user -vcsaPassword $podConfig.physical.password
	$pCluster = Get-Cluster -Name $podConfig.physical.cluster -Server $pVCSA
	$pDatastore = Get-Datastore -Name $podConfig.physical.datastore -Server $pVCSA
	$pPortGroup = Get-VDPortgroup -Name $podConfig.physical.portgroup -Server $pVCSA
	$pFolder = Get-PodFolder -vcsaConnection $pVCSA -folderPath $podConfig.physical.folder

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

	$deployTasks = @()
 
	$podConfig.esxi.hosts | ForEach-Object {
		$pESXi = $pCluster | Get-VMHost -Server $pVCSA | Where-Object { $_.ConnectionState -eq "Connected" } | Get-Random

		$nestedESXiName = $_.name
		$nestedESXiIPAddress = $_.ip

		if((Get-VM | Where-Object -Property Name -eq -Value $nestedESXiName) -eq $null) {
			$ovfConfig = Get-ovfConfiguration -Ovf $podConfig.sources.ESXiAppliance
			$ovfConfig.Common.guestinfo.hostname.Value = $nestedESXiName
			$ovfConfig.Common.guestinfo.ipaddress.Value = $nestedESXiIPAddress
			$ovfConfig.Common.guestinfo.netmask.Value = $podConfig.physical.network.netmask
			$ovfConfig.Common.guestinfo.gateway.Value = $podConfig.physical.network.gateway
			$ovfConfig.Common.guestinfo.dns.Value = $podConfig.physical.network.dns
			$ovfConfig.Common.guestinfo.domain.Value = $podConfig.physical.network.domain
			$ovfConfig.Common.guestinfo.ntp.Value = $podConfig.physical.network.ntp
			$ovfConfig.Common.guestinfo.syslog.Value = $podConfig.general.syslog
			$ovfConfig.Common.guestinfo.password.Value = $podConfig.general.password
			$ovfConfig.Common.guestinfo.ssh.Value = $podConfig.general.ssh
			$ovfConfig.Common.guestinfo.createvmfs.Value = $podConfig.esxi.createVMFS
			$ovfConfig.NetworkMapping.VM_Network.Value = $pPortGroup

			Write-Log "Deploying Nested ESXi VM $($nestedESXiName) to $($pESXi)"
			$task = Import-VApp -Server $pVCSA -VMHost $pESXi -Source $podConfig.sources.ESXiAppliance -ovfConfiguration $ovfConfig -Name $nestedESXiName -Location $pCluster -Datastore $pDatastore -DiskStorageFormat thin -RunAsync -ErrorAction SilentlyContinue
			$deployTasks += $task
		} else {
			Write-Log "Nested ESXi host $($nestedESXiName) exists, skipping" -Warning
		}
	}

	$taskCount = $deployTasks.Count
	while($taskCount -gt 0) {
		$deployTasks | ForEach-Object {
			#Write-Log -Message "Task $($_.Id) - $($_.State) - $($_.PercentComplete)%"
			Write-Progress -Activity "Deploying ESXi ($($_.Id))" -Status "$($_.PercentComplete)% Complete" -PercentComplete $_.PercentComplete
			if($_.State -eq "Success") {
				# Deployment Completed
				Write-Progress -Activity "Deploying ESXi ($($_.Result))" -Completed
				$nestedESXiVM = Get-VM -Name $_.Result -Server $pVCSA
				$nestedESXiName = $nestedESXiVM.Name

				Write-Log "$($nestedESXiName): Updating vCPU ($($podConfig.esxi.cpu)) & RAM ($($podConfig.esxi.ram)GB)"
				$nestedESXiVM | Set-VM -NumCpu $podConfig.esxi.cpu -MemoryGB $podConfig.esxi.ram -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

				Write-Log "$($nestedESXiName): Updating vSAN Caching disk to $($podConfig.esxi.cacheDisk)GB"
				# Work around for VSAN issue with not enough disk space - delete and add new disk
				Get-HardDisk -VM $nestedESXiVM | Where-Object -Property "CapacityGB" -eq -Value 4 | Remove-HardDisk -DeletePermanently -Confirm:$false
				if($podConfig.esxi.capacityDisk > 0) {
					New-HardDisk -VM $nestedESXiVM -Persistence persistent -SizeGB $podConfig.esxi.cacheDisk -StorageFormat Thin | Out-File -Append -LiteralPath $verboseLogFile
					New-AdvancedSetting -Entity $nestedESXiVM -Name 'scsi0:1.virtualSSD' -Value $true -Confirm:$false -Force | Out-File -Append -LiteralPath $verboseLogFile
				}

				Write-Log "$($nestedESXiName): Updating vSAN Capacity disk to $($podConfig.esxi.capacityDisk) GB"
				# Work around for VSAN issue with not enough disk space - delete and add new disk
				Get-HardDisk -VM $nestedESXiVM | Where-Object -Property "CapacityGB" -eq -Value 8 | Remove-HardDisk -DeletePermanently -Confirm:$false
				if($podConfig.esxi.capacityDisk > 0) {
					New-HardDisk -VM $nestedESXiVM -Persistence persistent -SizeGB $podConfig.esxi.capacityDisk -StorageFormat Thin | Out-File -Append -LiteralPath $verboseLogFile
					New-AdvancedSetting -Entity $nestedESXiVM -Name 'scsi0:2.virtualSSD' -Value $true -Confirm:$false -Force | Out-File -Append -LiteralPath $verboseLogFile
				}

				# Ensure the disks are marked as SSD
				New-AdvancedSetting -Entity $nestedESXiVM -Name 'scsi0:0.virtualSSD' -Value $true -Confirm:$false -Force | Out-File -Append -LiteralPath $verboseLogFile

				Write-Log "Moving $nestedESXiName to $($pFolder.Name) folder"
				Move-VM -VM $nestedESXiVM -InventoryLocation $pFolder | Out-File -Append -LiteralPath $verboseLogFile

				Write-Log "Powering On $nestedESXiName"
				Start-VM -VM $nestedESXiVM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

				$successTask = $_
				$deployTasks = $deployTasks | Where-Object $_.Id -ne ($successTask.Id)
				$taskCount--

			} elseif($_.State -eq "Error") {
				Write-Progress -Activity "Deploying ESXi ($($_.Result))" -Completed
				Write-Log -Message " failed to deploy" -Warning
				$failedTask = $_
				$deployTasks = $deployTasks | Where-Object $_.Id -ne ($failedTask.Id)
				$taskCount--
			}
		}
		Start-Sleep 5
	}
	Close-VcConnection -vcsaName $podConfig.physical.server
	Write-Log "#### Nested ESXi VMs Deployed ####"
}

if($deployVCSA) {
	Write-Log "#### Deploying vCenter Server Appliance(s) ####"
	$pVCSA = Get-VcConnection -vcsaName $podConfig.physical.server -vcsaUser $podConfig.physical.user -vcsaPassword $podConfig.physical.password
	$pCluster = Get-Cluster -Name $podConfig.physical.cluster -Server $pVCSA
	$pDatastore = Get-Datastore -Name $podConfig.physical.datastore -Server $pVCSA
	$pPortGroup = Get-VDPortgroup -Name $podConfig.physical.portgroup -Server $pVCSA
	$pFolder = Get-PodFolder -vcsaConnection $pVCSA -folderPath $podConfig.physical.folder

	Write-Log "Disabling DRS on $($podConfig.physical.cluster)"
	$pCluster | Set-Cluster -DrsEnabled:$false -Confirm:$false |  Out-File -Append -LiteralPath $verboseLogFile

	if($podConfig.psc -ne $null) {
		Write-Log "##### Deploying external PSC #####"
		$config = (Get-Content -Raw $externalPSCconfig) | convertfrom-json
		$config.'new.vcsa'.vc.hostname = $podConfig.physical.server
		$config.'new.vcsa'.vc.username = $podConfig.physical.user
		$config.'new.vcsa'.vc.password = $podConfig.physical.password
		$config.'new.vcsa'.vc.datacenter = @($podConfig.physical.datacenter)
		$config.'new.vcsa'.vc.datastore = $podConfig.physical.datastore
		$config.'new.vcsa'.vc.target = @($podConfig.physical.cluster)
		$config.'new.vcsa'.vc.'deployment.network' = $podConfig.physical.portgroup
		$config.'new.vcsa'.appliance.'thin.disk.mode' = $true
		$config.'new.vcsa'.appliance.'deployment.option' = $podConfig.psc.deploymentSize
		$config.'new.vcsa'.appliance.name = $podConfig.psc.name
		$config.'new.vcsa'.network.'system.name' = $podConfig.psc.hostname
		$config.'new.vcsa'.network.'ip.family' = "ipv4"
		$config.'new.vcsa'.network.mode = "static"
		$config.'new.vcsa'.network.ip = $podConfig.psc.ip
		$config.'new.vcsa'.network.'dns.servers'[0] = $podConfig.physical.network.dns
		$config.'new.vcsa'.network.prefix = $podConfig.physical.network.prefix
		$config.'new.vcsa'.network.gateway = $podConfig.physical.network.gateway
		$config.'new.vcsa'.os.'ssh.enable' = $podConfig.general.ssh
		$config.'new.vcsa'.os.password = $podConfig.psc.rootPassword
		$config.'new.vcsa'.sso.password = $podConfig.psc.sso.password
		$config.'new.vcsa'.sso.'domain-name' = $podConfig.psc.sso.domain
		$config.'new.vcsa'.sso.'site-name' = $podConfig.psc.sso.site
		if($podConfig.psc.sso.replicationPartner.length -gt 0) {
			# Join existing domain
			Write-Log "PSC will join replicate to $($podConfig.psc.sso.replicationPartner) "
			$config.'new.vcsa'.sso | Add-Member -Name "first-instance" -Value $false -MemberType NoteProperty
			$config.'new.vcsa'.sso | Add-Member -Name "sso.port" -Value "443" -MemberType NoteProperty
			$config.'new.vcsa'.sso | Add-Member -Name "replication-partner-hostname" -Value $podConfig.psc.sso.replicationPartner -MemberType NoteProperty
		}
		Write-Log "Creating PSC JSON Configuration file for deployment"
		$config | ConvertTo-Json | Set-Content -Path "$($temp)\psctemplate.json"

		if((Get-VM | Where-Object -Property Name -eq -Value $podConfig.psc.name) -eq $null) {
			Write-Log "Deploying OVF, this may take a while..."
			Invoke-Expression "$($vcsaDeploy) install --no-esx-ssl-verify --accept-eula --acknowledge-ceip $($temp)\psctemplate.json"| Out-File -Append -LiteralPath $verboseLogFile
			$vcsaDeployOutput | Out-File -Append -LiteralPath $verboseLogFile
			Write-Log "Moving $($podConfig.psc.name) to $($podConfig.physical.folder)"
			if((Get-VM | Where-Object {$_.name -eq $podConfig.psc.name}) -eq $null) {
				throw "Could not find VCSA VM. The script was unable to find the deployed VCSA"
			}
			Get-VM -Name $podConfig.psc.name | Move-VM -InventoryLocation $pFolder |  Out-File -Append -LiteralPath $verboseLogFile
		} else {
			Write-Log "PSC exists, skipping" -Warning
		}

	}
	if($podConfig.vcsa -ne $null) {
		if($podConfig.psc -ne $null) {
			Write-Log "##### Deploying VCSA with external PSC #####"
			$config = (Get-Content -Raw $externalVCSAconfig) | convertfrom-json
			# External PSC Specific config
			$config.'new.vcsa'.sso.'sso.port' = "443"
			$config.'new.vcsa'.sso.'platform.services.controller' = $podConfig.psc.ip
		} else {
			Write-Log "##### Deploying VCSA with embedded PSC #####"
			$config = (Get-Content -Raw $embeddedVCSAconfig) | convertfrom-json
			# Embedded PSC Specific config
			$config.'new.vcsa'.sso.'site-name' = $podConfig.vcsa.sso.site
		}
		$config.'new.vcsa'.vc.hostname = $podConfig.physical.server
		$config.'new.vcsa'.vc.username = $podConfig.physical.user
		$config.'new.vcsa'.vc.password = $podConfig.physical.password
		$config.'new.vcsa'.vc.datacenter = @($podConfig.physical.datacenter)
		$config.'new.vcsa'.vc.datastore = $podConfig.physical.datastore
		$config.'new.vcsa'.vc.target = @($podConfig.physical.cluster)
		$config.'new.vcsa'.vc.'deployment.network' = $podConfig.physical.portgroup
		$config.'new.vcsa'.os.'ssh.enable' = $podConfig.general.ssh
		$config.'new.vcsa'.os.password = $podConfig.vcsa.rootPassword
		$config.'new.vcsa'.appliance.'thin.disk.mode' = $true
		$config.'new.vcsa'.appliance.'deployment.option' = $podConfig.vcsa.deploymentSize
		$config.'new.vcsa'.appliance.name = $podConfig.vcsa.name
		$config.'new.vcsa'.network.'system.name' = $podConfig.vcsa.hostname
		$config.'new.vcsa'.network.'ip.family' = "ipv4"
		$config.'new.vcsa'.network.mode = "static"
		$config.'new.vcsa'.network.ip = $podConfig.vcsa.ip
		$config.'new.vcsa'.network.'dns.servers'[0] = $podConfig.physical.network.dns
		$config.'new.vcsa'.network.prefix = $podConfig.physical.network.prefix
		$config.'new.vcsa'.network.gateway = $podConfig.physical.network.gateway
		$config.'new.vcsa'.sso.password = $podConfig.vcsa.sso.password
		$config.'new.vcsa'.sso.'domain-name' = $podConfig.vcsa.sso.domain
		Write-Log "Creating VCSA JSON Configuration file for deployment"
		$config | ConvertTo-Json | Set-Content -Path "$($temp)vctemplate.json"
		if((Get-VM | Where-Object -Property Name -eq -Value $podConfig.vcsa.name) -eq $null) {
			Write-Log "Deploying OVF, this may take a while..."
			Write-Log "$($vcsaDeploy) install --no-esx-ssl-verify --accept-eula --acknowledge-ceip $($temp)vctemplate.json"  -Warning
			Invoke-Expression "$($vcsaDeploy) install --no-esx-ssl-verify --accept-eula --acknowledge-ceip $($temp)vctemplate.json" | Out-File -Append -LiteralPath $verboseLogFile
			$vcsaDeployOutput | Out-File -Append -LiteralPath $verboseLogFile
			Write-Log "Moving $($podConfig.vcsa.name) to $($podConfig.physical.folder)"
			if((Get-VM | Where-Object {$_.name -eq $podConfig.vcsa.name}) -eq $null) {
				throw "Could not find VCSA VM. The script was unable to find the deployed VCSA"
			}
			Get-VM -Name $podConfig.vcsa.name | Move-VM -InventoryLocation $pFolder |  Out-File -Append -LiteralPath $verboseLogFile
		} else {
			Write-Log "VCSA exists, skipping" -Warning
		}
		Write-Log "Enabling DRS on $($podConfig.physical.cluster)"
		$pCluster | Set-Cluster -DrsEnabled:$true -Confirm:$false |  Out-File -Append -LiteralPath $verboseLogFile
	}
	Close-VcConnection -vcsaName $podConfig.physical.server
}


if($configureVCSA) {
	Write-Log "#### Configuring VCSA ####"
	$nVCSA = Get-VcConnection -vcsaName $podConfig.vcsa.ip -vcsaUser "administrator@$($podConfig.vcsa.sso.domain)" -vcsaPassword $podConfig.vcsa.sso.password

	Write-Log "## Configuring Datacenter and Cluster ##"
	Write-Log "Creating Datacenter $($podConfig.vcsa.datacenter)" -Info
	$nDatacenter = (Get-Datacenter -Server $nVCSA | Where-Object -Property Name -eq -Value $podConfig.vcsa.datacenter)
	if($nDatacenter -eq $null) {
		$nDatacenter = New-Datacenter -Server $nVCSA -Name $podConfig.vcsa.datacenter -Location (Get-Folder -Type Datacenter -Server $nVCSA)
	} else {
		Write-Log "Datacenter exists, skipping" -Warning
	}
	Write-Log "Creating Cluster $($podConfig.vcsa.cluster)" -Info
	$nCluster = Get-Cluster -Server $nVCSA | Where-object -Property Name -eq -Value $podConfig.vcsa.cluster
	if($nCluster -eq $null) {
		$nCluster = New-Cluster -Server $nVCSA -Name $podConfig.vcsa.cluster -Location $nDatacenter -DrsEnabled
	} else {
		Write-Log "Cluster exists, skipping" -Warning
	}
	Write-Log "Enabling VMotion on vmkernel ports" -Info
	Get-VMHostNetworkAdapter -Server $nVCSA -VMkernel | Set-VMHostNetworkAdapter -VMotionEnabled:$true -Confirm:$false |  Out-File -Append -LiteralPath $verboseLogFile

	if($licenseVCSA) {
		Write-Log "Licensing vSphere"
		$serviceInstance = Get-View ServiceInstance -Server $nVCSA
		$licenseManagerRef=$serviceInstance.Content.LicenseManager
		$licenseManager=Get-View $licenseManagerRef
		$licenseManager.AddLicense($podConfig.license.vcenter,$null) |  Out-File -Append -LiteralPath $verboseLogFile
		$licenseManager.AddLicense($podConfig.license.vsphere,$null) |  Out-File -Append -LiteralPath $verboseLogFile
		$licenseManager.AddLicense($podConfig.license.vsan,$null) |  Out-File -Append -LiteralPath $verboseLogFile
		$licenseManager.AddLicense($podConfig.license.nsx,$null) |  Out-File -Append -LiteralPath $verboseLogFile
		$licenseAssignmentManager = Get-View $licenseManager.LicenseAssignmentManager
		Write-Log "Assigning vCenter Server License" -Info
		try {
			$licenseAssignmentManager.UpdateAssignedLicense($nVCSA.InstanceUuid, $podConfig.license.vcenter, $null) | Out-File -Append -LiteralPath $verboseLogFile
		}
		catch {
			$ErrorMessage = $_.Exception.Message
			Write-Log $ErrorMessage -Warning
		}
	}

	Write-Log "## Adding hosts to cluster ##"
	$nCluster = Get-Cluster -Name $podConfig.vcsa.cluster -Server $nVCSA
	$podConfig.esxi.hosts | ForEach-Object {
		$nestedESXiIPAddress = $_.ip
		Write-Log "Adding ESXi host $($_.name) to Cluster" -Info
		if((Get-VMHost -Server $nVCSA | Where-Object -Property Name -eq -Value $nestedESXiIPAddress) -eq $null) {
			Add-VMHost -Server $nVCSA -Location $nCluster -User "root" -Password $podConfig.general.password -Name $nestedESXiIPAddress -Force | Set-VMHost -LicenseKey $podConfig.license.vsphere -State "Maintenance" | Out-File -Append -LiteralPath $verboseLogFile
		} else {
			Write-Log "Host exists, skipping" -Warning
		}
	}

	if($podConfig.nfs.count -gt 0) {
		Write-Log "## Adding NFS shares to hosts ##"
		$nHosts = Get-VMHost -Server $nVCSA -Location $nCluster
		foreach($nfs in $podConfig.nfs) {
			Write-Log "Adding NFS share $($nfs.name)" -Info
			if(Get-Datastore -Name $nfs.name -ErrorAction SilentlyContinue) {
				Write-Log "Datastore $($nfs.name) exists, skipping" -Warning
			} else {
				$nHosts | New-Datastore -Nfs -Name $nfs.name -NfsHost $nfs.server -Path $nfs.path | Out-File -Append -LiteralPath $verboseLogFile
			}
		}
	}

	if($configureVSAN) {
		Write-Log "## Configuring VSAN ##"
		$VSANCluster = Get-Cluster -Name $podConfig.vcsa.cluster -Server $nVCSA | Out-File -Append -LiteralPath $verboseLogFile
		if($VSANCluster.VsanEnabled) {
			Write-Log "VSAN is enabled, skipping" -Warning
		} else {
			Set-Cluster -Cluster $podConfig.vcsa.cluster -VsanEnabled:$true -VsanDiskClaimMode Automatic -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
			Write-Log "Assigning VSAN License" -Info
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

		# $nHosts = Get-VMHost -Server $nVCSA -Location $podConfig.vcsa.cluster
		# foreach ($nHost in $nHosts) {
		# 	$luns = $nHost | Get-ScsiLun | Select-Object CanonicalName, CapacityGB
		# 	if((Get-VsanDiskGroup -VMHost $nHost) -eq $null) {
		# 		Write-Log "Querying ESXi host disks to create VSAN Diskgroups"
		# 		foreach ($lun in $luns) {
		# 			if(([int]($lun.CapacityGB)).toString() -eq "$($podConfig.esxi.cacheDisk)") {
		# 				$vsanCacheDisk = $lun.CanonicalName
		# 			}
		# 			if(([int]($lun.CapacityGB)).toString() -eq "$($podConfig.esxi.capacityDisk)") {
		# 				$vsanCapacityDisk = $lun.CanonicalName
		# 			}
		# 		}
		# 		Write-Log "Creating VSAN DiskGroup for $nHost"
		# 		New-VsanDiskGroup -Server $nVCSA -VMHost $nHost -SsdCanonicalName $vsanCacheDisk -DataDiskCanonicalName $vsanCapacityDisk | Out-File -Append -LiteralPath $verboseLogFile
		# 	}
		# }
	}
	
	if($configureVDSwitch) {
		Write-Log "## Configuring Distributed Switching ##"
		$nHosts = Get-VMHost -Location $podConfig.vcsa.cluster -Server $nVCSA
		$nDatacenter = Get-Datacenter -Name $podConfig.vcsa.datacenter -Server $nVCSA
		$distributedSwitch = Get-VDSwitch -Server $nVCSA | Where-Object -Property Name -eq -Value $podConfig.vcsa.distributedSwitch
		Write-Log "Creating distributed switch" -Info
		if($distributedSwitch -eq $null) {
			$distributedSwitch = New-VDSwitch -Name $podConfig.vcsa.distributedSwitch -Location $nDatacenter -Server $nVCSA -NumUplinkPorts 2
			Start-Sleep -Seconds 3
		} else {
			Write-Log "Distributed switch exists, skipping" -Warning
		}
		Write-Log "Adding hosts to distributed switch" -Info
		foreach ($nHost in $nHosts) {
			if(($distributedSwitch | Get-VMHost | Where-Object {$_.Name -eq $nHost.Name}) -eq $null) {
				Add-VDSwitchVMHost -VDSwitch $distributedSwitch -VMHost $nHost
				#Start-Sleep -Seconds 10
			} else {
				Write-Log "$($nHost) is already added to VDS" -Warning
			}
		}
		$dvPortGroup = Get-VDPortgroup | Where-Object -Property Name -eq -Value $podConfig.vcsa.portgroup
		Write-Log "Creating distributed port group" -Info
		if($dvPortGroup -eq $null) {
			$dvPortGroup = New-VDPortgroup -Name $podConfig.vcsa.portgroup -NumPorts 1000 -VDSwitch $distributedSwitch
			Start-Sleep -Seconds 3
		} else {
			Write-Log "Distributed port group exists, skipping" -Warning
		}

		foreach($nHost in $nHosts) {
			$networkAdapters = Get-VMHostNetworkAdapter -VMHost $nHost -Physical
			$vmkernelAdapter = Get-VMHostNetworkAdapter -VMHost $nHost -VMKernel
			Write-Log "Migrating NICs and VMkernel adapter to distributed switch" -Info
			if($vmkernelAdapter.PortGroupName -ne $podConfig.vcsa.portgroup) {
				Add-VDSwitchPhysicalNetworkAdapter -DistributedSwitch $distributedSwitch -VMHostPhysicalNic $networkAdapters -VMHostVirtualNic $vmkernelAdapter -VirtualNicPortgroup $dvPortGroup -Confirm:$false
			} else {
				Write-Log "NICs and VMKernel adapter are already assigned to the distributed switch, skipping" -Warning
			}

		}
		Start-Sleep -Seconds 5
		Write-Log "Removing standard vSwitches" -Info
		Get-VirtualSwitch -Server $nVCSA -Standard | Remove-VirtualSwitch -Confirm:$false
	}
}

Close-VcConnection

$EndTime = Get-Date
$duration = [math]::Round((New-TimeSpan -Start $StartTime -End $EndTime).TotalMinutes,2)

Write-Log "Pod Deployment Tasks Completed in $($duration) minutes"