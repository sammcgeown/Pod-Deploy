param(
	[Parameter(Mandatory=$true)] [String]$PodID,
	[string]$replicationPartnerHostname,
	[switch]$deployNestedESXiVMs = $true,
	[switch]$deployVCSA = $true,
	[switch]$setupNewVC = $true,
	[switch]$configureDCandCluster = $true,
	[switch]$configureLicensing = $true,
	[switch]$configureHosts = $true,
	[switch]$configureDistributedSwitch = $true,
	[switch]$configureVSANDiskGroups = $true,
	[switch]$clearVSANHealthCheckAlarm = $true,
	#[switch]$DeployvRealizeAutomationAppliance = $true
	[switch]$DeployNSXManager = $true,
	[switch]$ConfigureNSX = $true
)
Get-Module -ListAvailable VMware*,PowerNSX | Import-Module
if ( !(Get-Module -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) ) {
	throw "PowerCLI must be installed"
}
# Hat tips and thanks go to...
# William Lam http://www.virtuallyghetto.com/2016/11/vghetto-automated-vsphere-lab-deployment-for-vsphere-6-0u2-vsphere-6-5.html
# Rawlinson Riviera http://www.punchingclouds.com/2016/03/24/vmware-virtual-san-automated-deployments-powercli/
# Brian Graf http://www.vtagion.com/automatically-deploy-nsx-connect-vcenter/

# Physical vCenter Server to deploy vSphere 6.0 lab
$VIServer		=   "vcsa.lab.local"
$VIUsername	 	=   "administrator@vsphere.local"
$VIPassword	 	=   "v5phere!SS0"
$VIDatacenter   =   "Lab"
$VICluster	 	=   "Workload"

# Full Path to both the Nested ESXi 6.0 VA + extracted VCSA 6.0 ISO
$ScriptLocation = Split-Path -Parent $PSCommandPath
$VCSAInstaller  = "$($ScriptLocation)\VMware-VCSA-all-6.0.0-3634788"
$ESXiAppliance  = "$($ScriptLocation)\ESXi\Nested_ESXi6.x_Appliance_Template_v5.ova"
$NSXAppliance   = "$($ScriptLocation)\NSX\VMware-NSX-Manager-6.2.4-4292526.ova"
$vRAAppliance   = "$($ScriptLocation)\vRA\VMware-vR-Appliance-7.2.0.381-4660246_OVF10.ova"

# Nested ESXi VMs to deploy
$NestedESXiHostnameToIPs = @{
"pod-$($PodID)-esxi-1" = "192.168.$($PodID).20"
"pod-$($PodID)-esxi-2" = "192.168.$($PodID).21"
"pod-$($PodID)-esxi-3" = "192.168.$($PodID).22"
}

# Nested ESXi VM Resources
$NestedESXivCPU = "4"
$NestedESXivMEM = "12" # 12GB required once VSAN eats your breakfast...
$NestedESXiCachingvDisk = "100" #GB
$NestedESXiCapacityvDisk = "200" #GB

# VCSA Deployment Configuration
$VCSADeploymentSize = "tiny"
$VCSADisplayName = "pod-$($PodID)-vcsa"
$VCSAIPAddress = "192.168.$($PodID).10"
$VCSAHostname = "192.168.$($PodID).10" #IP if you don't have valid DNS
$VCSASSODomainName = "vsphere.local"
$VCSASSOSiteName = "Pod$($PodID)-Site"
$VCSASSOPassword = "VMware1!"
$VCSARootPassword = "VMware1!"


# General Deployment Configuration for both Nested ESXi VMs + VCSA
$VMNetwork = "$($PodID)-Pod-$($PodID)-Nested" # Ensure this network has Promiscuous Mode and Forged Transmits enabled http://www.virtuallyghetto.com/2013/11/why-is-promiscuous-mode-forged.html
$VMDatastore = "vsanDatastore"
$VMNetmask = "255.255.255.0"
$VMGateway = "192.168.$($PodID).1"
$VMPrefix = "24"
$VMDNS = "192.168.1.1"
$VMNTP = "192.168.1.1"
$VMPassword = "VMware1!"
$VMDomain = "definit.local"
$VMSyslog = "192.168.1.26"
$VMFolder = "Pod$($PodID)"

# Applicable to Nested ESXi only
$VMSSH = $true
$VMVMFS = $false

# Name of new vSphere Datacenter/Cluster when VCSA is deployed
$NewVCDatacenterName = "Pod$($PodID)-Datacenter"
$NewVCVSANClusterName = "Pod$($PodID)-Cluster-1"

# NSX Manager Deployment
$NSXName = "pod-$($PodID)-nsx"
$NSXIP = "192.168.$($PodID).11"
$NSXPass = "VMware1!"
$NSXControllerIPStart = "192.168.$($PodID).12"
$NSXControllerIPEnd = "192.168.$($PodID).14"
$NSXControllerPassword = ""

# vRealize Automation Configuration
$vRAAppIpAddress = "192.168.1.224"
$vRAAppName = "pod-1-vra"

# Licenses
$vCenterLicense = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
$vSphereLicense = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
$vsanLicense = "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"

#### DO NOT EDIT BEYOND HERE ####
# Log File
$verboseLogFile = "pod-$($PodID)-deploy.log"

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

if($deployNestedESXiVMs) {
	Write-Log "#### Deploying Nested ESXi VMs ####"
	Write-Log "Getting connection for $($VIServer)"
	$pVCSA = Get-VCSAConnection -vcsaName $VIServer -vcsaUser $VIUsername -vcsaPassword $VIPassword
	$pCluster = Get-Cluster -Name $VICluster -Server $pVCSA
	$pDatastore = Get-Datastore -Name $VMDatastore -Server $pVCSA
	$pPortGroup = Get-VDPortgroup -Name $VMNetwork -Server $pVCSA
	$pFolder = Get-Folder -Name $VMFolder -Type VM -Server $pVCSA

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

	$NestedESXiHostnameToIPs.GetEnumerator() | Sort-Object -Property Value | ForEach-Object {
		Write-Log "Selecting a host from $($VICluster)"
		$pESXi = $pCluster | Get-VMHost -Server $pVCSA | Get-Random
		Write-Log "Selected $($pESXi)"

		$nestedESXiName = $_.Key
		$nestedESXiIPAddress = $_.Value

		if((Get-VM | Where-Object -Property Name -eq -Value $nestedESXiName) -eq $null) {
			$ovfConfig = Get-ovfConfiguration -Ovf $ESXiAppliance
			$ovfConfig.Common.guestinfo.hostname.Value = $nestedESXiName
			$ovfConfig.Common.guestinfo.ipaddress.Value = $nestedESXiIPAddress
			$ovfConfig.Common.guestinfo.netmask.Value = $VMNetmask
			$ovfConfig.Common.guestinfo.gateway.Value = $VMGateway
			$ovfConfig.Common.guestinfo.dns.Value = $VMDNS
			$ovfConfig.Common.guestinfo.domain.Value = $VMDomain
			$ovfConfig.Common.guestinfo.ntp.Value = $VMNTP
			$ovfConfig.Common.guestinfo.syslog.Value = $VMSyslog
			$ovfConfig.Common.guestinfo.password.Value = $VMPassword
			$ovfConfig.Common.guestinfo.ssh.Value = $VMSSH
			$ovfConfig.Common.guestinfo.createvmfs.Value = $VMVMFS
			$ovfConfig.NetworkMapping.VM_Network.Value = $pPortGroup

			Write-Log "Deploying Nested ESXi VM $($nestedESXiName)"
			$importedVApp = Import-VApp -Server $pVCSA -VMHost $pESXi -Source $ESXiAppliance -ovfConfiguration $ovfConfig -Name $nestedESXiName -Location $pCluster -Datastore $pDatastore -DiskStorageFormat thin

			sleep 20

			$nestedESXiVM = Get-VM -Name $nestedESXiName -Server $pVCSA

			Write-Log "Updating vCPU Count to $NestedESXivCPU & vMEM to $NestedESXivMEM GB"
			$nestedESXiVM | Set-VM -NumCpu $NestedESXivCPU -MemoryGB $NestedESXivMEM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile

			Write-Log "Updating vSAN Caching VMDK size to $NestedESXiCachingvDisk GB"
			# Work around for VSAN issue reporting not enough disk space - delete and add new disk
			Get-HardDisk -VM $nestedESXiVM | where-object -Property "CapacityGB" -eq -Value 4 | Remove-HardDisk -DeletePermanently -Confirm:$false
			New-HardDisk -VM $nestedESXiVM -Persistence persistent -SizeGB $NestedESXiCachingvDisk -StorageFormat Thin | Out-File -Append -LiteralPath $verboseLogFile

			Write-Log "Updating vSAN Capacity VMDK size to $NestedESXiCapacityvDisk GB"
			# Work around for VSAN issue reporting not enough disk space - delete and add new disk
			Get-HardDisk -VM $nestedESXiVM | where-object -Property "CapacityGB" -eq -Value 8 | Remove-HardDisk -DeletePermanently -Confirm:$false
			New-HardDisk -VM $nestedESXiVM -Persistence persistent -SizeGB $NestedESXiCapacityvDisk -StorageFormat Thin | Out-File -Append -LiteralPath $verboseLogFile

			# Ensure the disks are marked as SSD
			New-AdvancedSetting -Entity $nestedESXiVM -Name 'scsi0:0.virtualSSD' -Value $true -Confirm:$false -Force | Out-File -Append -LiteralPath $verboseLogFile
			New-AdvancedSetting -Entity $nestedESXiVM -Name 'scsi0:1.virtualSSD' -Value $true -Confirm:$false -Force | Out-File -Append -LiteralPath $verboseLogFile
			New-AdvancedSetting -Entity $nestedESXiVM -Name 'scsi0:2.virtualSSD' -Value $true -Confirm:$false -Force | Out-File -Append -LiteralPath $verboseLogFile

			Write-Log "Moving $nestedESXiName to $VMFolder folder"
			Move-VM -VM $nestedESXiVM -Destination $pFolder | Out-File -Append -LiteralPath $verboseLogFile

			Write-Log "Powering On $nestedESXiName"
			Start-VM -VM $nestedESXiVM -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
		} else {
			Write-Log "Nested ESXi host exists, skipping" -Warning
		}
	}
}

if($deployVCSA) {
	Write-Log "#### Deploying VCSA ####"
	Write-Log "Getting connection for $($VIServer)"
	$pVCSA = Get-VCSAConnection -vcsaName $VIServer -vcsaUser $VIUsername -vcsaPassword $VIPassword
	$pCluster = Get-Cluster -Name $VICluster -Server $pVCSA
	$pDatastore = Get-Datastore -Name $VMDatastore -Server $pVCSA
	$pPortGroup = Get-VDPortgroup -Name $VMNetwork -Server $pVCSA
	$pFolder = Get-Folder -Name $VMFolder -Type VM -Server $pVCSA

	$config = (Get-Content -Raw "$($VCSAInstaller)\vcsa-cli-installer\templates\install\embedded_vCSA_on_VC.json") | convertfrom-json
	$config.'target.vcsa'.vc.hostname = $VIServer
	$config.'target.vcsa'.vc.username = $VIUsername
	$config.'target.vcsa'.vc.password = $VIPassword
	$config.'target.vcsa'.vc.datacenter = @($VIDatacenter)
	$config.'target.vcsa'.vc.datastore = $VMDatastore
	$config.'target.vcsa'.vc.target = @($VICluster)
	$config.'target.vcsa'.appliance.'deployment.network' = $VMNetwork
	$config.'target.vcsa'.appliance.'thin.disk.mode' = $true
	$config.'target.vcsa'.appliance.'deployment.option' = $VCSADeploymentSize
	$config.'target.vcsa'.appliance.name = $VCSADisplayName
	$config.'target.vcsa'.network.'ip.family' = "ipv4"
	$config.'target.vcsa'.network.mode = "static"
	$config.'target.vcsa'.network.ip = $VCSAIPAddress
	$config.'target.vcsa'.network.'dns.servers'[0] = $VMDNS
	$config.'target.vcsa'.network.'dns.servers'[1] = $null
	$config.'target.vcsa'.network.prefix = $VMPrefix
	$config.'target.vcsa'.network.gateway = $VMGateway
	$config.'target.vcsa'.network.hostname = $VCSAHostname
	$config.'target.vcsa'.os.password = $VCSARootPassword
	$config.'target.vcsa'.sso.password = $VCSASSOPassword
	$config.'target.vcsa'.sso.'domain-name' = $VCSASSODomainName
	$config.'target.vcsa'.sso.'site-name' = $VCSASSOSiteName
	if($replicationPartnerHostname.length -gt 0) {
		# Join existing domain
		$config.'target.vcsa'.sso | Add-Member -Name "first-instance" -Value $false -MemberType NoteProperty
		$config.'target.vcsa'.sso | Add-Member -Name "replication-partner-hostname" -Value $replicationPartnerHostname -MemberType NoteProperty
	}

	Write-Log "Creating VCSA JSON Configuration file for deployment"
	$config | ConvertTo-Json | Set-Content -Path "$($ENV:Temp)\jsontemplate.json"


	Write-Log "Deploying the VCSA"
	if((Get-VM | Where-Object -Property Name -eq -Value $VCSADisplayName) -eq $null) {
		Write-Log "Disabling DRS on $VICluster"
		$pCluster | Set-Cluster -DrsEnabled:$false -Confirm:$false |  Out-File -Append -LiteralPath $verboseLogFile
		Invoke-Expression "$($VCSAInstaller)\vcsa-cli-installer\win32\vcsa-deploy.exe install --no-esx-ssl-verify --accept-eula $($ENV:Temp)\jsontemplate.json" -ErrorVariable vcsaDeployOutput 2>&1
		$vcsaDeployOutput | Out-File -Append -LiteralPath $verboseLogFile
		Write-Log "Moving $VCSADisplayName to $VMFolder"
		Get-VM -Name $VCSADisplayName | Move-VM -Destination $pFolder |  Out-File -Append -LiteralPath $verboseLogFile
		Write-Log "Enabling DRS on $VICluster"
		$pCluster | Set-Cluster -DrsEnabled:$true -Confirm:$false |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "VCSA exists, skipping" -Warning
	}

}


if($setupNewVC) {
	Write-Log "#### Configuring VCSA ####"
	Write-Log "Getting connection to the new VCSA"
	$nVCSA = Get-VCSAConnection -vcsaName $VCSAIPAddress -vcsaUser "administrator@$($VCSASSODomainName)" -vcsaPassword $VCSASSOPassword

	if($configureDCandCluster) {
		Write-Log "## Configuring Datacenter and Cluster ##"
		Write-Log "Creating Datacenter $($NewVCDatacenterName)"
		if((Get-Datacenter | Where-Object -Property Name -eq -Value $NewVCDatacenterName) -eq $null) {
			$nDatacenter = New-Datacenter -Server $nVCSA -Name $NewVCDatacenterName -Location (Get-Folder -Type Datacenter -Server $nVCSA)
		} else {
			Write-Log "Datacenter exists, skipping" -Warning
		}
		Write-Log "Creating VSAN Cluster $($NewVCVSANClusterName)"
		if((Get-Cluster | Where-object -Property Name -eq -Value $NewVCVSANClusterName) -eq $null) {
			$nCluster = New-Cluster -Server $nVCSA -Name $NewVCVSANClusterName -Location $nDatacenter -DrsEnabled
		} else {
			Write-Log "Cluster exists, skipping" -Warning
		}
	}

	if($configureLicensing) {
		Write-Log "Licensing vSphere"
		$serviceInstance = Get-View ServiceInstance -Server $nVCSA
		$licenseManagerRef=$serviceInstance.Content.LicenseManager
		$licenseManager=Get-View $licenseManagerRef
		$licenseManager.AddLicense($vCenterLicense,$null) |  Out-File -Append -LiteralPath $verboseLogFile
		$licenseManager.AddLicense($vSphereLicense,$null) |  Out-File -Append -LiteralPath $verboseLogFile
		$licenseManager.AddLicense($vsanLicense,$null) |  Out-File -Append -LiteralPath $verboseLogFile
		$licenseAssignmentManager = Get-View $licenseManager.LicenseAssignmentManager
		Write-Log "Assigning vCenter Server License"
		try {
			$licenseAssignmentManager.UpdateAssignedLicense($nVCSA.InstanceUuid, $vCenterLicense, $null) | Out-File -Append -LiteralPath $verboseLogFile
		}
		catch {
			$ErrorMessage = $_.Exception.Message
			Write-Log $ErrorMessage -Warning
		}
	}


	if($configureHosts) {
		Write-Log "## Adding hosts to cluster ##"
		$nCluster = Get-Cluster -Name $NewVCVSANClusterName
		$NestedESXiHostnameToIPs.GetEnumerator() | sort -Property Value | ForEach-Object {
			$nestedESXiName = $_.Key
			$nestedESXiIPAddress = $_.Value
			Write-Log "Adding ESXi host $nestedESXiIPAddress to Cluster"
			if((Get-VMHost | Where-Object -Property Name -eq -Value $nestedESXiIPAddress) -eq $null) {
				Add-VMHost -Server $nVCSA -Location $nCluster -User "root" -Password $VMPassword -Name $nestedESXiIPAddress -Force | Set-VMHost -LicenseKey $vSphereLicense | Out-File -Append -LiteralPath $verboseLogFile
			} else {
				Write-Log "Host exists, skipping" -Warning
			}
		}
	}

	if($configureDistributedSwitch) {
		Write-Log "## Configuring Distributed Switching ##"
		$nHosts = Get-VMHost -Location $NewVCVSANClusterName -Server $nVCSA
		$nDatacenter = Get-Datacenter -Name $NewVCDatacenterName -Server $nVCSA
		Write-Log "Creating distributed switch"
		$distributedSwitch = Get-VDSwitch -Server $nVCSA | Where-Object -Property Name -eq -Value $VMFolder
		if($distributedSwitch -eq $null) {
			$distributedSwitch = New-VDSwitch -Name $VMFolder -Location $nDatacenter
			Write-Log "Adding hosts to distributed switch"
			Add-VDSwitchVMHost -VDSwitch $distributedSwitch -VMHost $nHosts
		} else {
			Write-Log "Distributed switch exists, skipping" -Warning
		}
		$dvPortGroup = Get-VDPortgroup | Where-Object -Property Name -eq -Value "VLAN$($PodID)"
		if($dvPortGroup -eq $null) {
			Write-Log "Creating distributed port group"
			$dvPortGroup = New-VDPortgroup -Name "VLAN$($PodID)" -NumPorts 1000 -VDSwitch $distributedSwitch
		} else {
			Write-Log "Distributed port group exists, skipping" -Warning
		}
		Write-Log "Adding vmnic1 to distributed switch"
		Add-VDSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter (Get-VMHostNetworkAdapter -Name "vmnic1" -VMHost $nHosts) -DistributedSwitch $distributedSwitch -Confirm:$false
		Write-Log "Migrating VMKernel to distributed switch"
		foreach($nHost in $nHosts) {
			$VMHNA = Get-VMHostNetworkAdapter -VMHost $nHost -Name vmk0
			if($VMHNA.PortGroupName -eq "VLAN$($PodID)") {
				Write-Log "vmk0 on $($nHost.Name) is already assigned to the port group $($dvPortGroup)" -Warning
			} else {
				Set-VMHostNetworkAdapter -PortGroup $dvPortGroup -VirtualNic (Get-VMHostNetworkAdapter  -Name vmk0 -VMHost $nHost) -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
			}
		}
		Write-Log "Moving vmnic0 to distributed switch"
		Add-VDSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter (Get-VMHostNetworkAdapter -Name "vmnic0" -VMHost $nHosts) -DistributedSwitch $distributedSwitch -Confirm:$false
		Write-Log "Removing standard vSwitches"
		Get-VirtualSwitch -Server $nVCSA -Standard | Remove-VirtualSwitch -Confirm:$false
	}

	if($configureVSANDiskGroups) {
		Write-Log "## Configuring VSAN ##"
		$VSANCluster = Get-Cluster -Name $NewVCVSANClusterName -Server $nVCSA
		if($VSANCluster.VsanEnabled) {
			Write-Log "VSAN is enabled, skipping" -Warning
		} else {
			$VSANCluster | Set-Cluster -VsanEnabled:$true -VsanDiskClaimMode Manual -Confirm:$false
			Write-Log "Assigning VSAN License"
			$serviceInstance = Get-View ServiceInstance -Server $nVCSA
			$licenseManagerRef=$serviceInstance.Content.LicenseManager
			$licenseManager=Get-View $licenseManagerRef
			$licenseAssignmentManager = Get-View $licenseManager.LicenseAssignmentManager
			$clusterRef = (Get-Cluster -Server $nVCSA -Name $NewVCVSANClusterName | get-view).MoRef
			try {
				$licenseAssignmentManager.UpdateAssignedLicense(($clusterRef.value), $vsanLicense, $null) | Out-File -Append -LiteralPath $verboseLogFile
			}
			catch {
				$ErrorMessage = $_.Exception.Message
				Write-Log $ErrorMessage -Warning
			}

			$nHosts = Get-VMHost -Server $nVCSA -Location $NewVCVSANClusterName
			foreach ($nHost in $nHosts) {
				$luns = $nHost | Get-ScsiLun | Select-Object CanonicalName, CapacityGB
				if((Get-VsanDiskGroup -VMHost $nHost) -ne $null) {
					Write-Log "Querying ESXi host disks to create VSAN Diskgroups"
					foreach ($lun in $luns) {
						if(([int]($lun.CapacityGB)).toString() -eq "$NestedESXiCachingvDisk") {
							$vsanCacheDisk = $lun.CanonicalName
						}
						if(([int]($lun.CapacityGB)).toString() -eq "$NestedESXiCapacityvDisk") {
							$vsanCapacityDisk = $lun.CanonicalName
						}
					}
					Write-Log "Creating VSAN DiskGroup for $nHost"
					New-VsanDiskGroup -Server $nVCSA -VMHost $nHost -SsdCanonicalName $vsanCacheDisk -DataDiskCanonicalName $vsanCapacityDisk | Out-File -Append -LiteralPath $verboseLogFile
				}
			}
		}
	}
}

if($DeployNSXManager) {
	Write-Log "#### Deploying NSX Manager ####"
	Write-Log "Getting connection for $($VIServer)"
	$pVCSA = Get-VCSAConnection -vcsaName $VIServer -vcsaUser $VIUsername -vcsaPassword $VIPassword
	$pCluster = Get-Cluster -Name $VICluster -Server $pVCSA
	$pDatastore = Get-Datastore -Name $VMDatastore -Server $pVCSA
	$pPortGroup = Get-VDPortgroup -Name $VMNetwork -Server $pVCSA
	$pFolder = Get-Folder -Name $VMFolder -Type VM -Server $pVCSA
	$pESXi = $pCluster | Get-VMHost -Server $pVCSA | Get-Random

	if((Get-VM -Server $pVCSA | Where-Object -Property Name -eq -Value $NSXName) -eq $null) {
		$ovfconfig = @{
			"vsm_cli_en_passwd_0" = "$NSXPass"
			"NetworkMapping.VSMgmt" = "$VMNetwork"
			"vsm_gateway_0" = "$VMGateway"
			"vsm_cli_passwd_0" = "$NSXPass"
			"vsm_isSSHEnabled" = "True"
			"vsm_netmask_0" = "$VMNetmask"
			"vsm_hostname" = "$NSXName.$VMDomain"
			"vsm_ntp_0" = "$VMNTP"
			"vsm_ip_0" = "$NSXIP"
			"vsm_dns1_0" = "$VMDNS"
			"vsm_domain_0" = "$VMDomain"
		}

		$importedVApp = Import-VApp -Server $pVCSA -VMhost $pESXi -Source $NSXAppliance -OVFConfiguration $ovfconfig -Name $NSXName -Datastore $pDatastore -DiskStorageFormat thin
		$NSX = Get-VM -Name $NSXName -Server $pVCSA
		Write-Log "Moving $NSXName to $VMFolder folder"
		Move-VM -VM $NSX -Destination $pFolder |  Out-File -Append -LiteralPath $verboseLogFile
		Write-Log "Powering On $NSXName"
		Start-VM -Server $pVCSA -VM $NSX -Confirm:$false | Out-File -Append -LiteralPath $verboseLogFile
		do {
			Sleep -Seconds 20
			$VM_View = Get-VM $NSXName -Server $pVCSA | Get-View
			$toolsStatus = $VM_View.Summary.Guest.ToolsRunningStatus
		} Until ($toolsStatus -eq "guestToolsRunning")
		Write-Log "$NSXName has booted up successfully, waiting for API"
		$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f "admin",$NSXPass)))
		$header = @{Authorization=("Basic {0}" -f $base64AuthInfo)}
		$uri = "https://$NSXIP/api/2.0/vdn/controller"
		do {
			Start-Sleep -Seconds 20
			$result = try { Invoke-WebRequest -Uri $uri -Headers $header -ContentType "application/xml"} catch { $_.Exception.Response}
		} Until ($result.statusCode -eq "200")
		Write-Log "Connected to $NSXIP API successfully"
	} else {
		Write-Log "NSX manager exists, skipping" -Warning
	}


}

if($ConfigureNSX) {
	Write-Log "#### Configuring NSX Manager ####"
	Write-Log "Getting connection to the new VCSA"
	$nVCSA = Get-VCSAConnection -vcsaName $VCSAIPAddress -vcsaUser "administrator@$($VCSASSODomainName)" -vcsaPassword $VCSASSOPassword
	Write-Log "Attempting to connect NSX Manager to vCenter"
	Connect-NSXServer $NSXIP -Username admin -Password $NSXPass -DisableVIAutoConnect |  Out-File -Append -LiteralPath $verboseLogFile
	$NSXVC = Get-NsxManagerVcenterConfig
	if($NSXVC.Connected -ne $true) {
		Set-NsxManager -vcenterusername "administrator@$($VCSASSODomainName)" -vcenterpassword $VCSASSOPassword -vcenterserver $VCSAIPAddress |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "NSX Manager connected to vCenter"
	}
	$NSXSSO = Get-NsxManagerSsoConfig
	if($NSXSSO.Connected -ne $true) {
		Set-NsxManager -ssousername "administrator@$($VCSASSODomainName)" -ssopassword $VCSASSOPassword -ssoserver $VCSAIPAddress |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "NSX Manager connected to SSO"
	}
	Disconnect-NsxServer
	Connect-NSXServer $NSXIP -Username admin -Password $NSXPass -VIUserName "administrator@$($VCSASSODomainName)" -VIPassword $VCSASSOPassword | Out-Null
	if((Get-NsxIpPool -Name "Controllers") -eq $null) {
		New-NsxIPPool -Name Controllers -Gateway $VMGateway -SubnetPrefixLength $VMPrefix -StartAddress $NSXControllerIPStart -EndAddress $NSXControllerIPEnd -DnsServer1 $VMDNS -DnsSuffix $VMDomain |  Out-File -Append -LiteralPath $verboseLogFile
	} else {
		Write-Log "NSX IP Pool Controllers exists, skipping"
	}
	$NSXPool = Get-NSXIPPool "Controllers"
	$NSXPortGroup = Get-VDPortGroup -Name "VLAN$($PodID)" -Server $nVCSA
	$NSXDatastore = Get-Datastore -Name "vsanDatastore" -Server $nVCSA
	$NSXCluster = Get-Cluster $NewVCVSANClusterName -Server $nVCSA
	Write-Log "Deploying NSX Controller"
	$NSXController = New-NsxController -Cluster $NSXCluster -datastore $NSXDatastore -PortGroup $NSXPortGroup -IpPool $NSXPool -Password $NSXControllerPassword -Confirm:$false
	do {
		Sleep -Seconds 20
		$ControllerStatus = (Get-NSXController -ObjectId $NSXController.id).status
	} Until (($ControllerStatus -eq "RUNNING") -or ($ControllerStatus -eq $null))
	Write-Log "$($ControllerStatus)"
}

# if($DeployvRealizeAutomationAppliance) {
# 	Write-Log "Deploying vRealize Automation Appliance"
# 	$ovfConfig = Get-ovfConfiguration $vRAAppliance
# 	$ovfConfig.NetworkMapping.Network_1.value = $Network
# 	$ovfConfig.IpAssignment.IpProtocol.value = "IPv4"
# 	$ovfConfig.vami.VMware_vRealize_Appliance.ip0.value = $vRAAppIpAddress
# 	$ovfConfig.vami.VMware_vRealize_Appliance.netmask0.value = $VMNetmask
# 	$ovfConfig.vami.VMware_vRealize_Appliance.gateway.value = $VMGateway
# 	$ovfConfig.vami.VMware_vRealize_Appliance.DNS.value = $VMDNS
# 	$ovfConfig.vami.VMware_vRealize_Appliance.domain.value  = $VMDomain
# 	$ovfConfig.vami.VMware_vRealize_Appliance.searchpath.value = $VMDomain
# 	$ovfConfig.common.varoot_password.value = $VMPassword
# 	$ovfConfig.common.va_ssh_enabled.value = $VMSSH
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

Write-Log "Pod Deployment Complete!"
Write-Log "StartTime: $StartTime"
Write-Log "  EndTime: $EndTime"
Write-Log " Duration: $duration minutes"
