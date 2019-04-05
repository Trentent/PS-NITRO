#Get PS-Nitro from GitHub with GetPSGet
#(new-object Net.WebClient).DownloadString("http://psget.net/GetPsGet.ps1") | iex   # -- this line fails for whatever reason.  Appears the cert was not applied to the correct domain.
(new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/psget/psget/master/GetPsGet.ps1") | iex
install-module PsUrl

#Install PS Nitro
install-module -ModuleUrl https://raw.githubusercontent.com/Trentent/PS-NITRO/master/NitroConfigurationFunctions/NITROConfigurationFunctions.psm1

#original Citrix module is next line...  just using as a reference
#install-module -moduleUrl https://raw.githubusercontent.com/santiagocardenas/netscaler-configuration/master/Modules/NetScalerConfiguration/NetScalerConfiguration.psm1

#Import-Module NetScalerConfiguration
import-module NITROConfigurationFunctions

#Variables!
#the domain you want to secure with the certificate
$domain =                           "trentent.ddns.me"                                              #The domain for which you want to get a certificate
$TimeZone =                         "GMT-07:00-MST-America/Edmonton"                                #The timezone to set on your netscaler
$LicenseFile =                      "C:\Users\amttye\Downloads\FID_018e8976_23ae_4954_884a_9cfa18714abb.lic"  #The license file for your netscaler (get a free license at "https://www.citrix.com/lp/try/netscaler-vpx-express.html#/email" -- good for one year, works with this script!) -- this has changed.  May need to get the ADC license (only good for 90 days)
$mailto =                           "mailto:trententtye@hotmail.com"                                #your email for LetsEncrypt
$ACMERefId =                        "BTDomain"                                                      #friendly name for your ACME vault to refer to your request
$ACMEAlias =                        "bottheory"                                                     #alias name
$issuerName =                       "LEissuer.crt"                                                  #filename used to export the issuer certificate
$certName =                         "LEcert.pem"                                                    #filename for your certificate for your domain
$keyName =                          "LEkey.pem"                                                     #filename for your certificates key-pair
$NSIP =                             "192.168.1.160"                                                 #NetScaler IP Address  -->  must boot up Netscaler virtual appliance first
$NTPServer =                        "192.168.1.3"                                                   #Network Time Protocol Server (NTP Server)
$SubNetIP =                         "192.168.1.161"                                                 #Netscaler Subnet IP --> must be your local network IP space
$SubnetMask =                       "255.255.255.0"                                                 #Subnet Mask for your Netscaler Subnet IP
$HostName =                         "NetscalerVPX"                                                  #The hostname you want to give your Netscaler
$DNSServer =                        "192.168.1.3"                                                   #DNS Server IP address
$CSIpAddr =                         "192.168.1.162"                                                 #IP Address of the Content Switch that will host the challenge response --> you will have to make this 'public' facing!

## I use a internal CA and have issued a web server ceritficate for use with Netscaler/Storefront
$VPNVServerCert    =                 "Storefront_Cert.pfx"                                          #Storefront Certificate with private key
$CARootCert        =                 "Root.cer"                                                     #CA Cert for the Storefront Certificate (if it was issued by a CA in a domain)
$pfxprivatekey =                     "pfxPassword1234"                                              #the pfx password/private key for decrypting
$serverCertName =                    "Storefront_Certificate"                                       #When the pfx cert gets imported, Netscaler will save it on the appliance under a new name.  This is that name.
$storefrontServer1 =                 "SF01"                                                         #Name of the first Storefront Server
$storefrontServer2 =                 "SF02"                                                         #Name of the second Storefront Server
$storefrontServer1IPAddress =        "192.168.0.27"                                                 #IP Address of the first Storefront Server
$storefrontServer2IPAddress =        "192.168.0.28"                                                 #IP Address of the second Storefront Server
$storefrontLoadBalancerIPAddress =   "192.168.1.150"                                                #The IP Address of the load balancer

$LDAPIPAddress =                     "192.168.1.2"                                                  #IP Address of Domain Controller
$LDAPBaseDN =                        "DC=bottheory,DC=local"                                        #Base Distinguished Name
$LDAPBindDN =                        "svc_ns@bottheory.local"                                       #UPN of user account to do AD lookups
$LDAPBindDNPassword =                "ThisIsAComplexPassword1234567"                                #password of user account
$LDAPLoginName =                     "sAMAccountName"                                               #Attribute to lookup

$UnifiedGatewayName =                "myUnifiedGateway"                                             #whatever you want to name the UnifiedGateway
$STAServerURL =                      "http://ddc1.bottheory.local"                                  #the STA server URL

$VerbosePreference =                 "silentlycontinue"                                             #enables verbose output in the prompt, set to "Continue" for verbose output


#starting with HTTP
Set-NSMgmtProtocol http

#Login to the Netscaler
Write-Host "Logging in to Netscaler"
$NSSession = Connect-NSAppliance -NSAddress $NSIP -NSUserName nsroot -NSPassword nsroot             #specify username/password for connecting to the Netscaler


#Set NTP time servers
Write-Host "Setting NTP Time Servers"
if (-not(Get-NSNTPServer -NSSession $NSSession)) {
    Add-NSNTPServer -NSSession $NSSession -ServerIP $NTPServer
}

#Add the subnet IP
Write-Host "Set the Subnet IP"
Add-NSIPResource -NSSession $NSSession -IPAddress $SubNetIP -SubnetMask $SubnetMask -Type SNIP

#set the host name
Write-Host "Setting the host name..."
Set-NSHostName -NSSession $NSSession -HostName $HostName

#sets a DNS server for lookups
Write-Host "Setting DNS Server..."
Add-NSDnsNameServer -NSSession $NSSession -DNSServerIPAddress $DNSServer

#sets the timezone...
Write-Host "Setting the TimeZone..."
Set-NSTimeZone -NSSession $NSSession -TimeZone $TimeZone

#add License file to Netscaler
Write-Host "Uploading and assigning the license file..."
Send-NSLicense -NSSession $NSSession -PathToLicenseFile $LicenseFile

#reduce CPU consumption (eg, enable CPU Yield) -> https://twitter.com/cstalhood/status/889824490083037184?lang=en
Write-Host "Reducing CPU utilization..."
if ((Get-NSVPXConfiguration -NSSession $NSSession).cpuyield -ne "YES") {
    Set-NSVPXConfiguration -NSSession $NSSession -CPUYield "YES"
}


#Reboot to take effect
Write-Host "Rebooting Netscaler..."
Restart-NSAppliance -NSSession $NSSession -SaveNSConfig -Wait -ErrorAction SilentlyContinue
pause
#LetsEncrypt!  Using this guide from Citrix:
#https://www.citrix.com/blogs/2015/12/09/using-lets-encrypt-for-free-ssl-certs-with-netscaler/

Write-Host "Sleeping another 60 seconds... Sometimes the Netscaler responds when it's not ready"
sleep 60 # give enough time for the netscaler to come back on

#we logged off on reboot, we need to logon again.
Write-Host "Logging back into the netscaler..."
$NSSession = Connect-NSAppliance -NSAddress $NSIP -NSUserName nsroot -NSPassword nsroot

#enable the required features...
Write-Host "Enabling ContentSwitching"
Enable-NSFeature -NSSession $NSSession -Feature CS
Write-Host "Enabling Responder"
Enable-NSFeature -NSSession $NSSession -Feature RESPONDER

#connecting to ACME for LetsEncrypt
Write-Host "Let's Encrypt!"
Write-Host "Getting Let's Encrypt!"
Install-PackageProvider NuGet -Force
#If ACMESharp is not installed then install it
if (-not(Get-InstalledModule -Name ACMESharp)) {
    if (find-module ACMESharp) {
        Install-Module ACMESharp -AllowClobber -Repository PSGallery -Verbose
        ipmo ACMESharp
    }
    else {
        Write-Host -ForegroundColor Red "Unable to find Module ACMESharp.  Exiting"
    }
}

Write-Host "Initialzing Let's Encrypt! vault..."
#Initialize-ACMEVault -BaseUri "https://acme-staging.api.letsencrypt.org/" -Force
Initialize-ACMEVault -BaseUri "https://acme-v01.api.letsencrypt.org" -Force
Write-Host "Creating new Let's Encrypt! registration"
New-ACMERegistration -Contacts $mailto -AcceptTos
Write-Host "Creating new Let's Encrypt! identifier"
New-ACMEIdentifier -Dns $domain -Alias $ACMERefId
Write-Host "Requesting the Let's Encrypt! challenge to validate we own this (sub)domain"
$ACMEresult = Complete-ACMEChallenge $ACMERefId -ChallengeType http-01 -Handler manual -Regenerate

#create temporary responder page
#Need to create HTML Page Import now with response from ACME.  Let's check to see if we already have an existing LetsEncrypt setup on the Netscaler

#region CleanUp Policies
$NSContentSwitchvServer = Get-NSContentSwitchVirtualServer -NSSession $NSSession
$NSResponderPolicies = Get-NSResponderPolicy -NSSession $NSSession
$NSResponderActions = Get-NSResponderAction -NSSession $NSSession
$NSHTMLResponderWebPages = Get-NSHTMLResponderWebPages -NSSession $NSSession

if ($NSContentSwitchvServer) {
    foreach ($response in $NSContentSwitchvServer.Name) {
        if ($response.Contains(("LetsEncrypt"))) {
            $result = $response
            Remove-NSContentSwitchVirtualServer -NSSession $NSSession -Name $result -Verbose
        }
    }
}

if ($NSResponderPolicies) {
    foreach ($response in $NSResponderPolicies.Name) {
        if ($response.Contains(("LetsEncrypt"))) {
            $result = $response
            Remove-NSResponderPolicy -NSSession $NSSession -Name $result -Verbose
        }
    }
}

if ($NSResponderActions) {
    foreach ($response in $NSResponderActions.Name) {
        if ($response.Contains(("LetsEncrypt"))) {
            $result = $response
            Remove-NSResponderAction -NSSession $NSSession -ActionName $result -Verbose
        }
    }
}

foreach ($response in $NSHTMLResponderWebPages.responderhtmlpage.response) {
    if ($response.Contains("LetsEncrypt")) {
        #found an existing LetsEncrypt responder.  We need to delete it.  The response output is plain text not in any clean parseable way.  I'm sorry.
        $result = (($response.split("`t") | Select-String "Name").ToString().Split(":").Trim() | Select-String -NotMatch "Name").ToString().Replace("`"","")
        Delete-NSHTMLResponderWebPage -NSSession $NSSession -ResponderName $result
    }
}

#endregion

#get the specific challenge from ACME.
Write-Host "This script only validates on an HTTP Let's Encrypt! challenge.  Getting the result to put on the web..."$ACMEresult = $ACMEresult.Challenges | where {$_.type -eq "http-01"}$fileName = "LetsEncryptResponder"
if (Get-NSSystemFile  -NSSession $NSSession -NetScalerFolder "/var/tmp" -FileName $fileName -ErrorAction SilentlyContinue) {
    Remove-NSSystemFile -NSSession $NSSession -NetScalerFolder "/var/tmp" -FileName $fileName
}
Add-NSContentSwitchVirtualServer -NSSession $NSSession -Name LetsEncrypt -ServiceType HTTP -IPv46 $CSIpAddr -Port 80
Add-NSHTMLResponderWebPageFromText -NSSession $NSSession -ResponderName $fileName -Text "$($ACMEresult.Challenge.FileContent)"
Add-NSResponderAction -NSSession $NSSession -ActionName LetsEncryptAction -ActionType "respondwithhtmlpage" -HTMLPage LetsEncryptResponder -ResponseStatusCode 200
Add-NSResponderPolicy -NSSession $NSSession -Name LetsEncryptPolicy -Rule true -Action LetsEncryptAction 
Add-ContentSwitchTovServerBinding -NSSession $NSSession  -Name LetsEncrypt -PolicyName LetsEncryptPolicy -GoToPriorityExpression END -Priority 100

Write-Host "Validating the URL we gave Let's Encrypt to see if WE can access it..."
$validateURL = Invoke-WebRequest -Uri $ACMEresult.Challenge.FileURL -UseBasicParsing

#ensure it's ready
sleep 15

if ($validateURL.Content -like "*$($ACMEresult.Challenge.FileContent)*") {
    #we successfully tested that our content is available externally.  We can finish the ACME request
    Submit-ACMEChallenge $ACMERefId -ChallengeType http-01

    do {
        Write-Host "Waiting for domain to validate..." -ForegroundColor Yellow
        sleep 30
    } until (((Update-ACMEIdentifier $ACMERefId -ChallengeType http-01).Challenges | Where-Object {$_.Type -eq "http-01"}).Status -like "valid")
    Write-Host "Domain Validated!" -ForegroundColor Green
}

Write-Host "Generating new certificate"
New-ACMECertificate $ACMERefId -Generate -Alias $ACMEAlias
Submit-ACMECertificate $ACMEAlias

do {
    Write-Host "Waiting for Certificate to be issued"...
    sleep 30
} until ((Update-ACMECertificate $ACMEAlias).KeyPemFile -ne $null)

#region Certificates!
Write-Host "Certificate Issued!"
Write-Host "Exporting Certificates for use on Netscaler..."

if (test-path "$env:temp\$issuerName") { Remove-Item -Path "$env:temp\$issuerName" }
Get-ACMECertificate $ACMEAlias -ExportIssuerPEM "$env:temp\$issuerName" 

if (test-path "$env:temp\$certName") { Remove-Item -Path "$env:temp\$certName" }
Get-ACMECertificate $ACMEAlias -ExportCertificatePEM  "$env:temp\$certName"

if (test-path "$env:temp\$keyName") { Remove-Item -Path "$env:temp\$keyName"}
Get-ACMECertificate $ACMEAlias -ExportKeyPEM "$env:temp\$keyName"

#upload certificates to Netscaler
Write-Host "Uploading Let's Encrypt Certificates..."
Add-NSSystemFile -NSSession $NSSession -PathToFile "$env:temp\$issuerName" -NetScalerFolder "/nsconfig/ssl/"
Add-NSSystemFile -NSSession $NSSession -PathToFile "$env:temp\$certName" -NetScalerFolder "/nsconfig/ssl/"
Add-NSSystemFile -NSSession $NSSession -PathToFile "$env:temp\$keyName" -NetScalerFolder "/nsconfig/ssl/"
Add-NSSSLCertKey -NSSession $NSSession -CertKeyName $issuerName -CertPath "/nsconfig/ssl/$issuerName" -CertKeyFormat PEM
Add-NSSSLCertKey -NSSession $NSSession -CertKeyName $keyName -CertPath "/nsconfig/ssl/$certName" -KeyPath "/nsconfig/ssl/$keyName" -CertKeyFormat PEM
Write-Host "Linking Let's Encrypt Certificates"
Add-NSSSLCertKeyLink -NSSession $NSSession -CertKeyName $keyName -LinkCertKeyName "$issuerName"

#upload certificate authority cert for the server cert
Write-Host "Uploading internal certificates for Storefront/CA"
Add-NSSystemFile -NSSession $NSSession -PathToFile "$CARootCert" -NetScalerFolder "/nsconfig/ssl/"
Add-NSSystemFile -NSSession $NSSession -PathToFile "$VPNVServerCert" -NetScalerFolder "/nsconfig/ssl/"
Write-Host "Importing pfx certificate"
Import-NSSSLPKCS12Cert -NSSession $NSSession -pfxFile $VPNVServerCert -privateKey $pfxprivatekey  -OutputName $serverCertName
Write-Host "Installing certificate into server certificate store"
Install-NSServerCert -NSSession $NSSession -Cert $serverCertName

#endregion Certificates!

Save-NSConfig -NSSession $NSSession

#region Configure Load Balancing on Storefront - https://support.citrix.com/article/CTX202400
#Enable Load Balancing
Write-Host "Enabling Load Balancing Feature"
Enable-NSFeature -NSSession $NSSession -Feature LoadBalancing

#Add Storefront Servers to Traffic Management > Load Balancing > Servers (Steps 1-5)
Write-Host "Creating Storefront server objects for use with Load Balancing"
Add-NSServer -NSSession $NSSession -Name $storefrontServer1 -IPAddress $storefrontServer1IPAddress 
Add-NSServer -NSSession $NSSession -Name $storefrontServer2 -IPAddress $storefrontServer2IPAddress 

#Add LB Monitor to Traffic Management > Load Balancing > Monitors (Steps 6-8)
Write-Host "Creating Storefront Load Balance Monitor"
Add-NSLBMonitor -NSSession $NSSession -Name LB-StoreFront -Type STOREFRONT -StoreName Store

#Add LB Service to Traffic Management > Load Balancing > Services (Steps 9-12)
Write-Host "Creating Storefront Load Balance Services"
Add-NSService -NSSession $NSSession -Name "LB_SRV_$storefrontServer1" -ServerName $storefrontServer1 -Type SSL -Port 443 -InsertClientIPHeader -ClientIPHeader "X-Forwarded-For"
Add-NSService -NSSession $NSSession -Name "LB_SRV_$storefrontServer2" -ServerName $storefrontServer2 -Type SSL -Port 443 -InsertClientIPHeader -ClientIPHeader "X-Forwarded-For"

#Add LB Virtual Server to Traffic Management > Load Balancing > Virtual Servers (Step 14 & 16)
Write-Host "Creating Storefront Load Balance vServer"
Add-NSLBVServer -NSSession $NSSession -Name LB_VS_Storefront -IPAddress $storefrontLoadBalancerIPAddress -ServiceType SSL -Port 443 -PersistenceType SOURCEIP
 
#Set the LB Balancing Virtual Server Service Binding and bind both StoreFront services (Step 15)
Write-Host "Binding Storefront Load Balance Services to the Storefront Load Balancer vServer"
New-NSLBVServerServiceBinding -NSSession $NSSession -Name "LB_VS_Storefront" -ServiceName "LB_SRV_$storefrontServer1" -Weight 1
New-NSLBVServerServiceBinding -NSSession $NSSession -Name "LB_VS_Storefront" -ServiceName "LB_SRV_$storefrontServer2" -Weight 1

#Bind server certificate to the LB Virtual Server (Step 17 & 18)
Write-Host "Binding Storefront Certificate to the storefront load balancer"
New-NSSSLVServerCertKeyBinding -NSSession $NSSession -CertKeyName $serverCertName -VirtualServerName "LB_VS_Storefront"

#endregion


#region Configure Unified Gateway
#adds LDAP connection to AD
Write-Host "Creating LDAP Authencation Action"
Add-NSAuthLDAPAction -NSSession $NSSession  -LDAPActionName "$LDAPIPAddress_LDAP" -LDAPServerIP $LDAPIPAddress -LDAPBaseDN $LDAPBaseDN -LDAPBindDN $LDAPBindDN -LDAPBindDNPassword $LDAPBindDNPassword -LDAPLoginName $LDAPLoginName
Write-Host "Creating LDAP Authencation Policy"
Add-NSAuthLDAPPolicy -NSSession $NSSession  -Action "$LDAPIPAddress_LDAP" -Name $LDAPIPAddress_LDAP_pol

#Creates Citrix Gateway Virtual Server
Write-Host "Creating Citrix Gateway Virtual Server"
Add-NSVPNVServer -NSSession $NSSession -Name "UG_VPN_$UnifiedGatewayName" -NonAddressable

#bind LDAP to the Citrix Gateway Virtual Server
Write-Host "Binding LDAP to the Citrix Gateway Virtual Server"
New-NSVPNVServerAuthLDAPPolicyBinding -NSSession $NSSession -VirtualServerName "UG_VPN_$UnifiedGatewayName" -LDAPPolicyName "$LDAPIPAddress_LDAP_pol"

#bind STA server to Citrix Gatway Virtual Server
Write-Host "Binding STA to the Citrix Gateway Virtual Server"
New-NSVPNVServerSTAServerBinding -NSSession $NSSession -VirtualServerName "UG_VPN_$UnifiedGatewayName" -STAServerURL $STAServerURL

#Sets portal theme
Write-Host "Setting Portal Theme to X1"
New-NSVPNVServerPortalTheme -NSSession $NSSession -VirtualServerName "UG_VPN_$UnifiedGatewayName"  -PortalTheme "X1"

#Assigns server certificate to the UnifiedGateway
Write-Host "Assigning certificate to the UnifiedGateway"
New-NSSSLVServerCertKeyBinding -NSSession $NSSession -CertKeyName $serverCertName -VirtualServerName "UG_VPN_$UnifiedGatewayName"

#region Session Action and Session Policy creation and binding
#creates UG Session Action and Policy
Write-Host "Creating UnifiedGateway Session Action and Policy"
Add-NSVPNSessionAction -NSSession $NSSession -SessionActionName "UG_VPN_SAct_$CSIpAddr" -TransparentInterception ON -ClientlessVpnMode ON -SSO ON -DefaultAuthorizationAction ALLOW -ClientChoices ON
Add-NSVPNSessionPolicy -NSSession $NSSession -SessionActionName "UG_VPN_SAct_$CSIpAddr" -SessionPolicyName "UG_VPN_SPol_$CSIpAddr" -SessionRuleExpression "true"

#creates Session Action (Store Service?)
Write-Host "Creating UnifiedGateway Store Action and Policy"
Add-NSVPNSessionAction -NSSession $NSSession -SessionActionName "AC_OS_$CSIpAddr" -TransparentInterception Off -ClientlessVpnMode Off -DefaultAuthorizationAction ALLOW -IcaProxy ON -ClientChoices ON -WIHome "https://storefront.bottheory.local/Citrix/StoreWeb" -NTDomain "BOTTHEORY.LOCAL" -StoreFrontUrl "https://storefront.bottheory.local" -SSO ON
Add-NSVPNSessionPolicy -NSSession $NSSession -SessionActionName "AC_OS_$CSIpAddr" -SessionPolicyName "PL_OS_$CSIpAddr" -SessionRuleExpression 'HTTP.REQ.HEADER("User-Agent").CONTAINS("CitrixReceiver") && HTTP.REQ.HEADER("User-Agent").CONTAINS("CitrixVPN").NOT && HTTP.REQ.HEADER("User-Agent").CONTAINS("NSGiOSplugin").NOT'

#creates Session Action (Web Service?)
Write-Host "Creating UnifiedGateway Web Action and Policy"
Add-NSVPNSessionAction -NSSession $NSSession -SessionActionName "AC_WB_$CSIpAddr" -TransparentInterception Off -ClientlessVpnMode Off -DefaultAuthorizationAction ALLOW -IcaProxy ON -ClientChoices ON -WIHome "https://storefront.bottheory.local/Citrix/StoreWeb" -NTDomain "BOTTHEORY.LOCAL" -SSO ON
Add-NSVPNSessionPolicy -NSSession $NSSession -SessionActionName "AC_WB_$CSIpAddr" -SessionPolicyName "PL_WB_$CSIpAddr" -SessionRuleExpression 'HTTP.REQ.HEADER("User-Agent").CONTAINS("CitrixReceiver").NOT'
#endregion

#Bind Session Policies to UG Gateway
Write-Host "Binding Policies to the Unified Gateway"
New-NSVPNVServerSessionPolicyBinding -NSSession $NSSession -VirtualServerName "UG_VPN_$UnifiedGatewayName" -SessionPolicyName "UG_VPN_SPol_$CSIpAddr" -Priority 58000
New-NSVPNVServerSessionPolicyBinding -NSSession $NSSession -VirtualServerName "UG_VPN_$UnifiedGatewayName" -SessionPolicyName "PL_OS_$CSIpAddr" -Priority 100
New-NSVPNVServerSessionPolicyBinding -NSSession $NSSession -VirtualServerName "UG_VPN_$UnifiedGatewayName" -SessionPolicyName "PL_WB_$CSIpAddr" -Priority 110

#configure Content Switch to support UG
#Create Content Switch
Write-Host "Creating Unified Gateway Content Switch vServer"
Add-NSContentSwitchVirtualServer -NSSession $NSSession -Name "$UnifiedGatewayName" -ServiceType SSL -IPv46 $CSIpAddr -Port 443
Write-Host "Creating Unified Gateway Content Switch Action"
Add-NSContentSwitchAction -NSSession $NSSession -Name "UG_CSAct_$UnifiedGatewayName" -TargetVServer "UG_VPN_$UnifiedGatewayName"
Write-Host "Creating Unified Gateway Content Switch Policy"
Add-NSContentSwitchPolicy -NSSession $NSSession -policyName "UG_CSPOL_$UnifiedGatewayName" -action "UG_CSAct_$UnifiedGatewayName" -rule 'is_vpn_url || HTTP.REQ.URL.PATH.SET_TEXT_MODE(IGNORECASE).STARTSWITH("/Citrix/Store")'
Write-Host "Binding Unified Gateway Content Switch Policy to the Unified Gateway"
Add-NSContentSwitchToContentSwitchServerBinding -NSSession $NSSession -Name "$UnifiedGatewayName" -PolicyName "UG_CSPOL_$UnifiedGatewayName" -Priority 63000 -GoToPriorityExpression "END"
Write-Host "Binding Lets Encrypt to the Unified Gateway"
New-NSSSLVServerCertKeyBinding -NSSession $NSSession -CertKeyName "$keyName" -VirtualServerName "$UnifiedGatewayName"


#New
#endregion

Save-NSConfig -NSSession $NSSession




Write-Host "Script is done!  Hopefully, you have a new LetsEncrypt Certificate!"