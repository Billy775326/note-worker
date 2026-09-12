$ErrorActionPreference = 'Stop'
$securePassword = Read-Host '设置登录密码（建议至少 12 位）' -AsSecureString
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
try {
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    if ($plainPassword.Length -lt 12 -or $plainPassword.Length -gt 1024) { throw '密码长度必须为 12～1024 位' }
    $saltBytes = New-Object byte[] 32
    $sessionBytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($saltBytes)
    $rng.GetBytes($sessionBytes)
    $rng.Dispose()
    $salt = [BitConverter]::ToString($saltBytes).Replace('-', '').ToLowerInvariant()
    $session = [BitConverter]::ToString($sessionBytes).Replace('-', '').ToLowerInvariant()
    $md5 = [Security.Cryptography.MD5]::Create()
    $hash = [BitConverter]::ToString($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($salt + ':' + $plainPassword))).Replace('-', '').ToLowerInvariant()
    $md5.Dispose()
    $secrets = @{ PASSWORD_SALT = $salt; PASSWORD_HASH = $hash; SESSION_SECRET = $session }
    $outputPath = Join-Path $PSScriptRoot '.dev.vars'
    $lines = @("PASSWORD_SALT=$salt", "PASSWORD_HASH=$hash", "SESSION_SECRET=$session")
    [IO.File]::WriteAllLines($outputPath, $lines, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'secrets.json'), ($secrets | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    Write-Host '已生成本地 .dev.vars 和上传用 secrets.json，未保存明文密码。请勿分享这两个文件。'
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    $plainPassword = $null
    $securePassword.Dispose()
}
