[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$monitorTaskName = 'InternetRadar-Monitor'
$audioTaskName = 'InternetRadar-Audio'
$projectRoot = Split-Path -Parent $PSScriptRoot
$radarScript = Join-Path $PSScriptRoot 'radar.py'
$audioScript = Join-Path $PSScriptRoot 'audio_worker.py'
$python = (Get-Command python.exe -ErrorAction Stop).Source
$pythonw = Join-Path (Split-Path -Parent $python) 'pythonw.exe'
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name

foreach ($path in @($radarScript, $audioScript, $pythonw)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Arquivo necessario nao encontrado: $path"
    }
}

foreach ($name in @($monitorTaskName, $audioTaskName)) {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
        throw "A tarefa '$name' ja existe. Nenhuma tarefa foi alterada."
    }
}

$credential = Get-Credential -UserName $user -Message 'Informe a senha da sua conta Windows (nao o PIN) para iniciar o monitor antes do login.'
if ($null -eq $credential -or $credential.UserName -ne $user) {
    throw "Informe as credenciais da conta $user. Nenhuma tarefa foi criada."
}

$monitorAction = New-ScheduledTaskAction -Execute $pythonw -Argument ('-B "{0}" --no-audio' -f $radarScript) -WorkingDirectory $projectRoot
$audioAction = New-ScheduledTaskAction -Execute $pythonw -Argument ('-B "{0}"' -f $audioScript) -WorkingDirectory $projectRoot
$monitorTrigger = New-ScheduledTaskTrigger -AtStartup
$audioTrigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$audioPrincipal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited

$passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
$password = $null
$monitorRegistered = $false
try {
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    Register-ScheduledTask -TaskName $monitorTaskName -Action $monitorAction -Trigger $monitorTrigger -Settings $settings -User $user -Password $password -RunLevel Limited -Description 'Inicia monitoramento e servidor HTTP do Internet Radar no boot, sem janela.' | Out-Null
    $monitorRegistered = $true
    Register-ScheduledTask -TaskName $audioTaskName -Action $audioAction -Trigger $audioTrigger -Settings $settings -Principal $audioPrincipal -Description 'Toca os alertas pendentes na sessao do usuario, sem janela.' | Out-Null
} catch {
    if ($monitorRegistered) {
        Unregister-ScheduledTask -TaskName $monitorTaskName -Confirm:$false
    }
    throw
} finally {
    $password = $null
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
}

Write-Output "Tarefas instaladas: $monitorTaskName (boot) e $audioTaskName (login). Nenhum processo foi iniciado agora."
