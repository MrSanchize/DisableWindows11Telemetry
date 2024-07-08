If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
  Exit	
}

# TELEMETRY
# disable telemetry
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v 'AllowTelemetry' /t REG_DWORD /d '0' /f
Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v 'MaxTelemetryAllowed' /t REG_DWORD /d '0' /f
# disable autologger diagtrack listener
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
# disable customer experience improvement program
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f

# MISCELLANEOUS
# disable advertising & promotional
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f

# SYSTEM
# disable storage sense
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "StoragePoliciesChanged" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "StoragePoliciesNotified" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d "0" /f
# disable nearby sharing
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "NearShareChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d "0" /f
# disable device portal
Reg.exe add "HKLM\System\ControlSet001\Services\WebManagement" /v "Start" /t REG_DWORD /d "4" /f
# disable device discovery
Reg.exe add "HKLM\System\ControlSet001\Services\debugregsvc\Parameters" /v "DebugState" /t REG_DWORD /d "0" /f
# disable remote desktop
Reg.exe add "HKLM\System\ControlSet001\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\ControlSet001\Control\Terminal Server" /v "updateRDStatus" /t REG_DWORD /d "0" /f
# disable clipboard
Reg.exe add "HKCU\Software\Microsoft\Clipboard" /v "EnableClipboardHistory" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" /v "Disabled" /t REG_DWORD /d "1" /f

# NETWORK & INTERNET
# disable allow other network users to control or disable the shared internet connection
Reg.exe add "HKLM\System\ControlSet001\Control\Network\SharedAccessConnection" /v "EnableControl" /t REG_DWORD /d "0" /f

# APPS
# disable share across devices
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "RomeSdkChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f
# disable archive apps
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\InstallService\Stubification\S-1-5-21-2296936333-280572394-256428770-1000" /v "EnableAppOffloading" /t REG_DWORD /d "0" /f
# disable auto map updates
Reg.exe add "HKLM\System\Maps" /v "AutoUpdateEnabled" /t REG_DWORD /d "0" /f

# PRIVACY & SECURITY
# disable let apps show me personalized ads by using my advertising id
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\AdvertisingInfo" /v "Value" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
# disable let websites show me locally relevant content by accesing my language list
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
# disable let windows improve start and search results by tracking app launches
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartPage" /v "StartMenu_Start_Time" /t REG_BINARY /d "5D7AFA8B53D1DA01" /f
# disable online speech recognition
Reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
# disable inking & typing personalization
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization" /v "Value" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
# disable improve inking & typing
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\ImproveInkingAndTyping" /v "Value" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
# disable send optional diagnostic data
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
# disable tailored experiences
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
# disable feedback frequency
Reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
Reg.exe delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
# disable cloud content search
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsMSACloudSearchEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsAADCloudSearchEnabled" /t REG_DWORD /d "0" /f
# disable search history
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "0" /f
# disable find my device
Reg.exe add "HKLM\Software\Microsoft\MdmCommon\SettingValues" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f
# disable location
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\NonPackaged" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "ShowGlobalPrompts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\UserLocationOverridePrivacySetting" /v "Value" /t REG_DWORD /d "0" /f
# disable voice activation
Reg.exe add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationEnabled" /t REG_DWORD /d "0" /f
# disable notifiactions
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f
# disable account info
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f
# disable contacts
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
# disable calendar
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f
# disable phone calls
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f
# disable call history
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f
# disable email
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
# disable tasks
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f
# disable messaging
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f
# disable radios
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f
# disable communicate with unpaired devices
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f
# disable app diagnostics
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f
# disable documents
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f
# disable downloads folder
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f
# disable music libary
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v "Value" /t REG_SZ /d "Deny" /f
# disable pictures
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f
# disable videos
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f
# disable file system
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f

# WINDOWS UPDATE
# disable delivery optimization
Reg.exe add "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f
# disable receive updates for other microsoft products
Reg.exe add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "AllowMUUpdateService" /t REG_DWORD /d "0" /f
# disable get me up to date
Reg.exe add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "IsExpedited" /t REG_DWORD /d "0" /f
# disable download updates over metered connections
Reg.exe add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" /t REG_DWORD /d "0" /f
# disable windows update restart notifiaction
Reg.exe add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "RestartNotificationsAllowed2" /t REG_DWORD /d "0" /f

# WINDOWS SEARCH
# disable safe search mode
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "SafeSearchMode" /t REG_DWORD /d "0" /f
# disable device search history
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "0" /
# disable cloud search
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsAADCloudSearchEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsMSACloudSearchEnabled" /t REG_DWORD /d "0" /f
# disable web search
Reg.exe add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f

# WINDOWS DEFENDER
# disable spynet reporting
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f
# disable automatic sample submission
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f

# SERVICES
# disable connected user experiences and telemetry service
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
# disable wap push message routing service
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f

# SCHEDULED TASKS
# disable customer experience improvement program features
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\Consolidator' -ErrorAction SilentlyContinue
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' -ErrorAction SilentlyContinue
# disable application experience features
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' -ErrorAction SilentlyContinue
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp' -ErrorAction SilentlyContinue
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\ProgramDataUpdater' -ErrorAction SilentlyContinue
# disable disk diagnostic data collector
Disable-ScheduledTask -TaskName 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' -ErrorAction SilentlyContinue
# disable autochk proxy
Disable-ScheduledTask -TaskName 'Microsoft\Windows\Autochk\Proxy' -ErrorAction SilentlyContinue
Clear-Host

# HOSTS
# define windows telemetry domains to block
$domainsToBlock = @(
"in.appcenter.ms"
"applicationinsights.azure.com",
"aimon.applicationinsights.azure.com",
"in.aimon.applicationinsights.azure.com",
"westcentralus-global.in.aimon.applicationinsights.azure.com",
"api.applicationinsights.azure.com",
"dc.applicationinsights.azure.cn",
"dc.applicationinsights.azure.com",
"dc.applicationinsights.azure.us",
"www.dc.applicationinsights.azure.com",
"in.applicationinsights.azure.cn",
"in.applicationinsights.azure.com",
"in.applicationinsights.azure.us",
"australiaeast-0.in.applicationinsights.azure.com",
"australiaeast-1.in.applicationinsights.azure.com",
"australiaeast-global.in.applicationinsights.azure.com",
"australiasoutheast-0.in.applicationinsights.azure.com",
"brazilsouth-0.in.applicationinsights.azure.com",
"brazilsouth-1.in.applicationinsights.azure.com",
"canadacentral-0.in.applicationinsights.azure.com",
"canadacentral-1.in.applicationinsights.azure.com",
"canadaeast-0.in.applicationinsights.azure.com",
"centralindia-0.in.applicationinsights.azure.com",
"centralus.in.applicationinsights.azure.com",
"centralus-0.in.applicationinsights.azure.com",
"centralus-2.in.applicationinsights.azure.com",
"centralus-3.in.applicationinsights.azure.com",
"chinaeast2-0.in.applicationinsights.azure.cn",
"chinaeast3-global.in.applicationinsights.azure.cn",
"chinanorth3-0.in.applicationinsights.azure.cn",
"eastasia-0.in.applicationinsights.azure.com",
"eastus-0.in.applicationinsights.azure.com",
"eastus-1.in.applicationinsights.azure.com",
"eastus-2.in.applicationinsights.azure.com",
"eastus-3.in.applicationinsights.azure.com",
"eastus-4.in.applicationinsights.azure.com",
"eastus-5.in.applicationinsights.azure.com",
"eastus-6.in.applicationinsights.azure.com",
"eastus-8.in.applicationinsights.azure.com",
"eastus-global.in.applicationinsights.azure.com",
"eastus2-0.in.applicationinsights.azure.com",
"eastus2-3.in.applicationinsights.azure.com",
"eastus2-4.in.applicationinsights.azure.com",
"francecentral-1.in.applicationinsights.azure.com",
"germanywestcentral-0.in.applicationinsights.azure.com",
"germanywestcentral-1.in.applicationinsights.azure.com",
"japaneast-0.in.applicationinsights.azure.com",
"japaneast-1.in.applicationinsights.azure.com",
"japanwest-0.in.applicationinsights.azure.com",
"northcentralus-0.in.applicationinsights.azure.com",
"northeurope-0.in.applicationinsights.azure.com",
"northeurope-2.in.applicationinsights.azure.com",
"northeurope-3.in.applicationinsights.azure.com",
"northeurope-4.in.applicationinsights.azure.com",
"northeurope-5.in.applicationinsights.azure.com",
"northeurope-global.in.applicationinsights.azure.com",
"norwayeast-0.in.applicationinsights.azure.com",
"qatarcentral-0.in.applicationinsights.azure.com",
"southafricanorth-0.in.applicationinsights.azure.com",
"southafricanorth-1.in.applicationinsights.azure.com",
"southcentralus-0.in.applicationinsights.azure.com",
"southcentralus-3.in.applicationinsights.azure.com",
"southeastasia-0.in.applicationinsights.azure.com",
"southeastasia-1.in.applicationinsights.azure.com",
"swedencentral-0.in.applicationinsights.azure.com",
"switzerlandnorth-0.in.applicationinsights.azure.com",
"uksouth-0.in.applicationinsights.azure.com",
"uksouth-1.in.applicationinsights.azure.com",
"ukwest-0.in.applicationinsights.azure.com",
"usgovarizona-0.in.applicationinsights.azure.us",
"usgovarizona-global.in.applicationinsights.azure.us",
"usgovtexas-0.in.applicationinsights.azure.us",
"usgovvirginia-0.in.applicationinsights.azure.us",
"usgovvirginia-1.in.applicationinsights.azure.us",
"usgovvirginia-global.in.applicationinsights.azure.us",
"westeurope.in.applicationinsights.azure.com",
"westeurope-0.in.applicationinsights.azure.com",
"westeurope-1.in.applicationinsights.azure.com",
"westeurope-2.in.applicationinsights.azure.com",
"westeurope-3.in.applicationinsights.azure.com",
"westeurope-4.in.applicationinsights.azure.com",
"westeurope-5.in.applicationinsights.azure.com",
"westeurope-global.in.applicationinsights.azure.com",
"westus-0.in.applicationinsights.azure.com",
"westus2-0.in.applicationinsights.azure.com",
"westus2-1.in.applicationinsights.azure.com",
"westus2-2.in.applicationinsights.azure.com",
"westus2-4.in.applicationinsights.azure.com",
"westus2-5.in.applicationinsights.azure.com",
"westus2-global.in.applicationinsights.azure.com",
"westus3-1.in.applicationinsights.azure.com",
"live.applicationinsights.azure.cn",
"live.applicationinsights.azure.com",
"collector.azure.cn",
"js.monitor.azure.com",
"location-microsoft-com.b-0005.b-msedge.net",
"a4.bing.com",
"ads.bing.com",
"adserver.bing.com",
"bat.bing.com",
"r.bat.bing.com",
"2539951.r.bat.bing.com",
"c.bing.com",
"www.c.bing.com",
"commerce.bing.com",
"g.bing.com",
"r.g.bing.com",
"raka.bing.com",
"measure.office.net.edgesuite.net",
"nel.measure.office.net.edgesuite.net",
"nelsdf.measure.office.net.edgesuite.net",
"collector.azure.eaglex.ic.gov",
"analytics.live.com",
"digg.analytics.live.com",
"ms.analytics.live.com",
"c.live.com",
"location.live.net",
"agps.location.live.net",
"collection.location.live.net",
"inference.location.live.net",
"nexusrules.live.com",
"auc-visio-telemetry.officeapps.live.com",
"brc-visio-telemetry.officeapps.live.com",
"cac-visio-telemetry.officeapps.live.com",
"dec-visio-telemetry.officeapps.live.com",
"euc-excel-telemetry.officeapps.live.com",
"euc-onenote-telemetry.officeapps.live.com",
"euc-powerpoint-telemetry.officeapps.live.com",
"euc-visio-telemetry.officeapps.live.com",
"euc-word-telemetry.officeapps.live.com",
"eurffc-word-telemetry.officeapps.live.com",
"eurppc-excel-telemetry.officeapps.live.com",
"eurppc-powerpoint-telemetry.officeapps.live.com",
"eurppc-word-telemetry.officeapps.live.com",
"excel-telemetry.officeapps.live.com",
"ffc-excel-telemetry.officeapps.live.com",
"ffc-word-telemetry.officeapps.live.com",
"frc-visio-telemetry.officeapps.live.com",
"inc-visio-telemetry.officeapps.live.com",
"nexus.officeapps.live.com",
"nexusrules.officeapps.live.com",
"noc-visio-telemetry.officeapps.live.com",
"pgteu1-excel-telemetry-vip.officeapps.live.com",
"pgteu1-powerpoint-telemetry-vip.officeapps.live.com",
"pgteu1-word-telemetry-vip.officeapps.live.com",
"pgteu2-excel-telemetry-vip.officeapps.live.com",
"pgteu2-powerpoint-telemetry-vip.officeapps.live.com",
"pgteu2-word-telemetry-vip.officeapps.live.com",
"pgteu3-excel-telemetry-vip.officeapps.live.com",
"pgteu3-powerpoint-telemetry-vip.officeapps.live.com",
"pgteu3-word-telemetry-vip.officeapps.live.com",
"pgteu4-excel-telemetry-vip.officeapps.live.com",
"pgteu4-powerpoint-telemetry-vip.officeapps.live.com",
"pgtus1-excel-telemetry-vip.officeapps.live.com",
"pgtus1-powerpoint-telemetry-vip.officeapps.live.com",
"pgtus1-word-telemetry-vip.officeapps.live.com",
"pgtus2-excel-telemetry-vip.officeapps.live.com",
"pgtus2-powerpoint-telemetry-vip.officeapps.live.com",
"pgtus2-word-telemetry-vip.officeapps.live.com",
"pgtus3-excel-telemetry-vip.officeapps.live.com",
"pgtus3-powerpoint-telemetry-vip.officeapps.live.com",
"pgtus3-word-telemetry-vip.officeapps.live.com",
"pgtus4-excel-telemetry-vip.officeapps.live.com",
"pgtus4-powerpoint-telemetry-vip.officeapps.live.com",
"pgtus4-word-telemetry-vip.officeapps.live.com",
"pgtus5-excel-telemetry-vip.officeapps.live.com",
"pgtus5-powerpoint-telemetry-vip.officeapps.live.com",
"pgtus5-word-telemetry-vip.officeapps.live.com",
"pgtus6-excel-telemetry-vip.officeapps.live.com",
"pgtus6-powerpoint-telemetry-vip.officeapps.live.com",
"pgtus6-word-telemetry-vip.officeapps.live.com",
"powerpoint-telemetry.officeapps.live.com",
"ppc-excel-telemetry.officeapps.live.com",
"ppc-onenote-telemetry.officeapps.live.com",
"ppc-powerpoint-telemetry.officeapps.live.com",
"ppc-word-telemetry.officeapps.live.com",
"sgtus1-excel-telemetry-vip.officeapps.live.com",
"sgtus1-powerpoint-telemetry-vip.officeapps.live.com",
"sgtus1-word-telemetry-vip.officeapps.live.com",
"tgtus1-excel-telemetry-vip.officeapps.live.com",
"tgtus1-powerpoint-telemetry-vip.officeapps.live.com",
"tgtus1-word-telemetry-vip.officeapps.live.com",
"ukc-onenote-telemetry.officeapps.live.com",
"ukc-visio-telemetry.officeapps.live.com",
"usc-onenote-telemetry.officeapps.live.com",
"usc-visio-telemetry.officeapps.live.com",
"visio-telemetry.officeapps.live.com",
"word-telemetry.officeapps.live.com",
"outlookads.live.com",
"rad.live.com",
"ssw.live.com",
"ds.ssw.live.com",
"watson.live.com",
"ads.microsoft.com",
"about.ads.microsoft.com",
"learninglab.about.ads.microsoft.com",
"about-test.ads.microsoft.com",
"about-test-deploy.ads.microsoft.com",
"adlibrary.ads.microsoft.com",
"bcp.ads.microsoft.com",
"beta.ads.microsoft.com",
"api.beta.ads.microsoft.com",
"developers.ads.microsoft.com",
"dmc.ads.microsoft.com",
"help.ads.microsoft.com",
"mmcapi.ads.microsoft.com",
"smetric.ads.microsoft.com",
"status.ads.microsoft.com",
"ucm.ads.microsoft.com",
"ui.ads.microsoft.com",
"adsdk.microsoft.com",
"advertising.microsoft.com",
"community.advertising.microsoft.com",
"fp.advertising.microsoft.com",
"sts.advertising.microsoft.com",
"analyticspixel.microsoft.com",
"applicationinsights.microsoft.com",
"dc.applicationinsights.microsoft.com",
"rt.applicationinsights.microsoft.com",
"pipe.aria.microsoft.com",
"browser.pipe.aria.microsoft.com",
"eu.pipe.aria.microsoft.com",
"mobile.pipe.aria.microsoft.com",
"office.pipe.aria.microsoft.com",
"pf.pipe.aria.microsoft.com",
"server1.pipe.aria.microsoft.com",
"server2.pipe.aria.microsoft.com",
"server3.pipe.aria.microsoft.com",
"server4.pipe.aria.microsoft.com",
"server5.pipe.aria.microsoft.com",
"server6.pipe.aria.microsoft.com",
"server7.pipe.aria.microsoft.com",
"server8.pipe.aria.microsoft.com",
"tb.pipe.aria.microsoft.com",
"us.pipe.aria.microsoft.com",
"collector.azure.microsoft.scloud",
"azurewatson.microsoft.com",
"azurewatsontest.microsoft.com",
"bingads.microsoft.com",
"adinquiry.bingads.microsoft.com",
"ads.bingads.microsoft.com",
"advertise.bingads.microsoft.com",
"api.bingads.microsoft.com",
"adinsight.api.bingads.microsoft.com",
"bulk.api.bingads.microsoft.com",
"campaign.api.bingads.microsoft.com",
"clientcenter.api.bingads.microsoft.com",
"partner.api.bingads.microsoft.com",
"reporting.api.bingads.microsoft.com",
"azure.bingads.microsoft.com",
"secure.azure.bingads.microsoft.com",
"bc.bingads.microsoft.com",
"secure.bc.bingads.microsoft.com",
"bcp.bingads.microsoft.com",
"ui.bcp.bingads.microsoft.com",
"beta.bingads.microsoft.com",
"ch1b.bingads.microsoft.com",
"community.bingads.microsoft.com",
"developers.bingads.microsoft.com",
"fd.bingads.microsoft.com",
"feedback.bingads.microsoft.com",
"help.bingads.microsoft.com",
"m.bingads.microsoft.com",
"reportingapi.bingads.microsoft.com",
"sandbox.bingads.microsoft.com",
"bulk.api.sandbox.bingads.microsoft.com",
"campaign.api.sandbox.bingads.microsoft.com",
"clientcenter.api.sandbox.bingads.microsoft.com",
"reporting.api.sandbox.bingads.microsoft.com",
"secure.sandbox.bingads.microsoft.com",
"secure.bingads.microsoft.com",
"si.bingads.microsoft.com",
"ui.si.bingads.microsoft.com",
"tip.bingads.microsoft.com",
"ucm.bingads.microsoft.com",
"ui.bingads.microsoft.com",
"www.bingads.microsoft.com",
"c1.microsoft.com",
"track.notif.careersppe.microsoft.com",
"clarity.microsoft.com",
"events.data.microsoft.com",
"adhs.events.data.microsoft.com",
"apac.events.data.microsoft.com",
"au-mobile.events.data.microsoft.com",
"au-v10.events.data.microsoft.com",
"au-v10c.events.data.microsoft.com",
"au-v20.events.data.microsoft.com",
"browser.events.data.microsoft.com",
"emea.events.data.microsoft.com",
"eu-ic3.events.data.microsoft.com",
"eu-mobile.events.data.microsoft.com",
"eu-office.events.data.microsoft.com",
"eu-teams.events.data.microsoft.com",
"eu-v10.events.data.microsoft.com",
"eu-v10c.events.data.microsoft.com",
"eu-v20.events.data.microsoft.com",
"eu-watsonc.events.data.microsoft.com",
"functional.events.data.microsoft.com",
"ic3.events.data.microsoft.com",
"in-mobile.events.data.microsoft.com",
"in-v20.events.data.microsoft.com",
"jp-mobile.events.data.microsoft.com",
"jp-v10.events.data.microsoft.com",
"jp-v10c.events.data.microsoft.com",
"jp-v20.events.data.microsoft.com",
"kmwatson.events.data.microsoft.com",
"kmwatsonc.events.data.microsoft.com",
"mobile.events.data.microsoft.com",
"noam.events.data.microsoft.com",
"nw-umwatson.events.data.microsoft.com",
"office.events.data.microsoft.com",
"office-c.events.data.microsoft.com",
"office-g.events.data.microsoft.com",
"pf.events.data.microsoft.com",
"self.events.data.microsoft.com",
"server.events.data.microsoft.com",
"tb.events.data.microsoft.com",
"teams.events.data.microsoft.com",
"uk-mobile.events.data.microsoft.com",
"uk-v20.events.data.microsoft.com",
"umwatson.events.data.microsoft.com",
"umwatsonc.events.data.microsoft.com",
"us-mesh.events.data.microsoft.com",
"us-mobile.events.data.microsoft.com",
"us-teams.events.data.microsoft.com",
"us-v10.events.data.microsoft.com",
"us-v10c.events.data.microsoft.com",
"us-v20.events.data.microsoft.com",
"us4-v20.events.data.microsoft.com",
"us5-v20.events.data.microsoft.com",
"v10.events.data.microsoft.com",
"v10c.events.data.microsoft.com",
"v20.events.data.microsoft.com",
"watson.events.data.microsoft.com",
"watsonc.events.data.microsoft.com",
"events-sandbox.data.microsoft.com",
"mobile.events-sandbox.data.microsoft.com",
"settings-sandbox.data.microsoft.com",
"settings-win-ppe.data.microsoft.com",
"vortex.data.microsoft.com",
"eu.vortex.data.microsoft.com",
"vortex-sandbox.data.microsoft.com",
"vortex-win.data.microsoft.com",
"au.vortex-win.data.microsoft.com",
"eu.vortex-win.data.microsoft.com",
"uk.vortex-win.data.microsoft.com",
"us.vortex-win.data.microsoft.com",
"v10.vortex-win.data.microsoft.com",
"v20.vortex-win.data.microsoft.com",
"vortex-win-sandbox.data.microsoft.com",
"api.edgeoffer.microsoft.com",
"location.microsoft.com",
"geover-prod.do.dsp.mp.microsoft.com",
"track.mp.microsoft.com",
"dm3.track.mp.microsoft.com",
"oca.microsoft.com",
"watson.officeint.microsoft.com",
"analytics.pstnhub.microsoft.com",
"rad.microsoft.com",
"i1.services.social.microsoft.com",
"spynet2.microsoft.com",
"spynetalt.microsoft.com",
"tar.microsoft.com",
"telecommandsvc.microsoft.com",
"www.telecommandsvc.microsoft.com",
"telemetry.microsoft.com",
"alpha.telemetry.microsoft.com",
"watson.alpha.telemetry.microsoft.com",
"df.telemetry.microsoft.com",
"responses.df.telemetry.microsoft.com",
"sqm.df.telemetry.microsoft.com",
"watson.df.telemetry.microsoft.com",
"wes.df.telemetry.microsoft.com",
"reports.wes.df.telemetry.microsoft.com",
"services.wes.df.telemetry.microsoft.com",
"oca.telemetry.microsoft.com",
"ppe.telemetry.microsoft.com",
"watson.ppe.telemetry.microsoft.com",
"sqm.telemetry.microsoft.com",
"telecommand.telemetry.microsoft.com",
"watson.telemetry.microsoft.com",
"uhf.microsoft.com",
"telemetry.urs.microsoft.com",
"watson.microsoft.com",
"cab.watson.microsoft.com",
"survey.watson.microsoft.com",
"statsfe1.ws.microsoft.com",
"statsfe2.ws.microsoft.com",
"gateway.bingviz.microsoftapp.net",
"msads.net",
"ads1.msads.net",
"a.ads1.msads.net",
"ads2.msads.net",
"a.ads2.msads.net",
"b.ads2.msads.net",
"global.msads.net",
"a.global.msads.net",
"www.msads.net",
"ad.msn.com",
"adevents.msn.com",
"ads.msn.com",
"ads1.msn.com",
"a.ads1.msn.com",
"b.ads1.msn.com",
"ads2.msn.com",
"adsyndication.msn.com",
"images.adsyndication.msn.com",
"images-ppe.adsyndication.msn.com",
"analytics.msn.com",
"metric.appex-rf.msn.com",
"c.ar.msn.com",
"c.at.msn.com",
"c.be.msn.com",
"c.br.msn.com",
"c.ca.msn.com",
"c.cl.msn.com",
"confiant.msn.com",
"events.data.msn.cn",
"events.data.msn.com",
"browser.events.data.msn.cn",
"browser.events.data.msn.com",
"events-sandbox.data.msn.com",
"c.de.msn.com",
"c.dk.msn.com",
"c.es.msn.com",
"ads.eu.msn.com",
"rmads.eu.msn.com",
"c.fi.msn.com",
"flex.msn.com",
"c.fr.msn.com",
"g00.msn.com",
"c-5uwzmx78pmca09x24aiux2euavx2ekwu.g00.msn.com",
"c.gr.msn.com",
"h.msn.com",
"h1.msn.com",
"h2.msn.com",
"h6.msn.com",
"c.hk.msn.com",
"c.id.msn.com",
"c.ie.msn.com",
"c.il.msn.com",
"c.in.msn.com",
"c.it.msn.com",
"ads.jp.msn.com",
"advertising.jp.msn.com",
"c.jp.msn.com",
"utm.sankei.jp.msn.com",
"c.latam.msn.com",
"mobileads.msn.com",
"mobileleads.msn.com",
"analytics.msnbc.msn.com",
"c.my.msn.com",
"c.nl.msn.com",
"c.no.msn.com",
"c.ph.msn.com",
"popup.msn.com",
"preview.msn.com",
"c.prodigy.msn.com",
"c.pt.msn.com",
"r.msn.com",
"bat.r.msn.com",
"rads.msn.com",
"live.rads.msn.com",
"rel.msn.com",
"rmads.msn.com",
"c.ru.msn.com",
"sam.msn.com",
"c.se.msn.com",
"auto.search.msn.com",
"c.sg.msn.com",
"srtb.msn.com",
"stjjp.msn.com",
"c.th.msn.com",
"toolbar.msn.com",
"beta.toolbar.msn.com",
"install.toolbar.msn.com",
"c.tr.msn.com",
"c.tw.msn.com",
"udc.msn.com",
"c.uk.msn.com",
"c.za.msn.com",
"zmetrics.msn.com",
"measure.office.com",
"measure.office.net",
"fp.measure.office.com",
"66ed06ba24d0447d99be625dc7a80b00.fp.measure.office.com",
"ce2617d2a3a1a6b03e6b908e5fde808f.fp.measure.office.com",
"config.fp.measure.office.com",
"graph-next.fp.measure.office.com",
"ns1.fp.measure.office.com",
"ns2.fp.measure.office.com",
"upload.fp.measure.office.com",
"upload2.fp.measure.office.com",
"nel.measure.office.net",
"ecs.nel.measure.office.net",
"excelonline.nel.measure.office.net",
"exo.nel.measure.office.net",
"identity.nel.measure.office.net",
"m365cdn.nel.measure.office.net",
"officehub.nel.measure.office.net",
"onenoteonline.nel.measure.office.net",
"spo.nel.measure.office.net",
"teams.nel.measure.office.net",
"tfl.nel.measure.office.net",
"visioonline.nel.measure.office.net",
"wordonline.nel.measure.office.net",
"nelsdf.measure.office.net",
"exo.nelsdf.measure.office.net",
"m365cdn.nelsdf.measure.office.net",
"powerpointonline.nelsdf.measure.office.net",
"sdwan.measure.office.com",
"wan.measure.office.com",
"hubblecontent.osi.office.net",
"analytics.trafficmanager.net",
"hub.analytics.trafficmanager.net",
"geo.hub.analytics.trafficmanager.net",
"analytics-listener.trafficmanager.net",
"beacons.trafficmanager.net",
"bf-analytics-tracker-tm.trafficmanager.net",
"bf-tracker-release-tm.trafficmanager.net",
"cas-telemetry.trafficmanager.net",
"collector-main.trafficmanager.net",
"tracker.flightview.com.trafficmanager.net",
"events.data.trafficmanager.net",
"apac.events.data.trafficmanager.net",
"aria.events.data.trafficmanager.net",
"eu.aria.events.data.trafficmanager.net",
"global.aria.events.data.trafficmanager.net",
"us.aria.events.data.trafficmanager.net",
"asimov.events.data.trafficmanager.net",
"global.asimov.events.data.trafficmanager.net",
"au.events.data.trafficmanager.net",
"blobcollector.events.data.trafficmanager.net",
"eu.blobcollector.events.data.trafficmanager.net",
"browser.events.data.trafficmanager.net",
"emea.events.data.trafficmanager.net",
"eu.events.data.trafficmanager.net",
"jp.events.data.trafficmanager.net",
"mobile.events.data.trafficmanager.net",
"noam.events.data.trafficmanager.net",
"pf.events.data.trafficmanager.net",
"l5.pf.events.data.trafficmanager.net",
"server.events.data.trafficmanager.net",
"tb.events.data.trafficmanager.net",
"l4.tb.events.data.trafficmanager.net",
"uk.events.data.trafficmanager.net",
"us.events.data.trafficmanager.net",
"dsp-ad-cache-tm.trafficmanager.net",
"telemetry.eastus.trafficmanager.net",
"eventservice.trafficmanager.net",
"fsad.trafficmanager.net",
"ghochv3eng.trafficmanager.net",
"glance-analytics.trafficmanager.net",
"hk-tracker.trafficmanager.net",
"ir-tracking.trafficmanager.net",
"irreverselookuptm.trafficmanager.net",
"ism-telemetry.trafficmanager.net",
"legacywatson.trafficmanager.net",
"o365diagtelemetry.trafficmanager.net",
"office-events-data.trafficmanager.net",
"oms-analytics.trafficmanager.net",
"pixel-sync.trafficmanager.net",
"rdm-trafficmanager-ticketscenter-metrics.trafficmanager.net",
"sconsentit9.trafficmanager.net",
"self-events-data.trafficmanager.net",
"settingsfd-geo.trafficmanager.net",
"sre-metrics-thanos-prod.trafficmanager.net",
"ssp-prod-eastus-nonmutt.trafficmanager.net",
"stats-partner.trafficmanager.net",
"teams-events-data.trafficmanager.net",
"telemetry-lcp.trafficmanager.net",
"telemetry-sdk-inmobi-comtm.trafficmanager.net",
"tenmax-ads.trafficmanager.net",
"tm-analytics-pr.trafficmanager.net",
"tm-enrollment-telemetry-datacore.trafficmanager.net",
"euc-excel-telemetry.wac.trafficmanager.net",
"euc-powerpoint-telemetry.wac.trafficmanager.net",
"euc-word-telemetry.wac.trafficmanager.net",
"excel-telemetry.wac.trafficmanager.net",
"powerpoint-telemetry.wac.trafficmanager.net",
"ppc-excel-telemetry.wac.trafficmanager.net",
"ppc-powerpoint-telemetry.wac.trafficmanager.net",
"ppc-word-telemetry.wac.trafficmanager.net",
"word-telemetry.wac.trafficmanager.net",
"win-global-asimov-leafs-events-data.trafficmanager.net",
"dc.services.visualstudio.com",
"activity.windows.com",
"assets.activity.windows.com",
"canary.activity.windows.com",
"edge.activity.windows.com",
"edge-enterprise.activity.windows.com",
"enterprise.activity.windows.com",
"enterprise-eudb.activity.windows.com",
"ppe.activity.windows.com",
"ceuswatcab01.blob.core.windows.net",
"ceuswatcab02.blob.core.windows.net",
"eaus2watcab01.blob.core.windows.net",
"eaus2watcab02.blob.core.windows.net",
"weus2watcab01.blob.core.windows.net",
"weus2watcab02.blob.core.windows.net",
"cache.datamart.windows.com",
"feedback.windows.com",
"sa.windows.com",
"adsdktelemetry-prod.servicebus.windows.net",
"ams-aase-1-bus-analytics-1-1.servicebus.windows.net",
"ams-euno-1-bus-analytics-1-1.servicebus.windows.net",
"ams-usea-1-bus-analytics-1-1.servicebus.windows.net",
"ams-usso-1-bus-analytics-1-1.servicebus.windows.net",
"ams-uswe-1-bus-analytics-1-1.servicebus.windows.net",
"analytics-dev-lleap-events.servicebus.windows.net",
"analytics-dev-simpad-events.servicebus.windows.net",
"analyticsehnwe.servicebus.windows.net",
"analyticsiot-prod-simpad-ehn.servicebus.windows.net",
"citrixanalyticseh.servicebus.windows.net",
"citrixanalyticseh-alias.servicebus.windows.net",
"citrixanalyticseh2.servicebus.windows.net",
"citrixanalyticseh2-alias.servicebus.windows.net",
"citrixanalyticsehaps.servicebus.windows.net",
"citrixanalyticsehaps-alias.servicebus.windows.net",
"citrixanalyticseheu.servicebus.windows.net",
"citrixanalyticseheu-alias.servicebus.windows.net",
"citrixtelemetryeh.servicebus.windows.net",
"citrixtelemetryeh-alias.servicebus.windows.net",
"citrixtelemetryeheu.servicebus.windows.net",
"citrixtelemetryeheu-alias.servicebus.windows.net",
"ffg-analyticsk3nvxfne4dp4s.servicebus.windows.net",
"hme-live-loganalytics-namespace.servicebus.windows.net",
"jetanalytics.servicebus.windows.net",
"nexxtv-events.servicebus.windows.net",
"ppm-licensingtelemetry.servicebus.windows.net",
"prod-eh-v1-analytics.servicebus.windows.net",
"prod-eventhub-analytics.servicebus.windows.net",
"production-jobactivity-analytics.servicebus.windows.net",
"rawtelemetry-east.servicebus.windows.net",
"rawtelemetry-west.servicebus.windows.net",
"ss-telemetry.servicebus.windows.net",
"wayfinderanalytics.servicebus.windows.net",
"c.xbox.com",
"o.xbox.com",
"beacons.xboxlive.com"
)

# path to hosts file
$hostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts"

# function to add domain entries to hosts file
function Add-HostsEntry {
    param (
        [string]$domain
    )
    $entry = "0.0.0.0 $domain"
    # check if domain entry already exists in hosts file
    if (-not (Get-Content $hostsFilePath | Select-String -Pattern "^$entry$")) {
        # append domain entry to hosts file
        Add-Content -Path $hostsFilePath -Value $entry
        Write-Host "Added $domain to hosts file."
    } else {
        Write-Host "$domain already exists in hosts file."
    }
}

# block telemetry domains
foreach ($domain in $domainsToBlock) {
    Add-HostsEntry -domain $domain
}

# flush dns cache to apply changes
ipconfig /flushdns
