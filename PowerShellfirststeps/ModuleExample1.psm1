# дополнительные валидации
function start-icmpscanner
{

Param (
    [ValidatePattern("\d{1,3}.\d{1,3}.\d{1,3}.")][ValidateLength(6,12)][string] $range = $(Throw "Set the Range parameter, Example: '19.168.0.'"), 
    [ValidateRange(1, 255)][int] $startIP = $(Throw "Set the StartIP parameter, Example: 1"), 
    [ValidateRange(1, 255)][int] $endIP = $(Throw "Set the endIP parameter, Example: 3"),  
    [ValidateRange(1, 10)][int] $callCount = $(Throw "Set the ICMP CALL COUNT parameter, Example: 1")
    )

    $tab = "`t" # табулятор
    for ($i = $startIP; $i -le $endIP; $i ++)
    {
        $ip = $range + $i
        $result = Test-Connection -ComputerName $ip -Count $callCount -Quiet
        Write-Host $ip -NoNewline
        Write-Host $tab -NoNewline
        if ($result -eq $false)
        {
            Write-Host $result -ForegroundColor Red
        }
        else
        {
            Write-Host $result -ForegroundColor Green
        }
    }
}

# реализуем обёртку над ошибкой
function Get-IPV4Address
{
<#
#>
Param([string] $ComputerName)
    $b = Test-Connection $ComputerName -Quiet
    if ($b -eq $true)
    {
        try
        {
            $a = Get-WmiObject -Query 'select * from win32_networkAdapterConfiguration where index = 4' -ComputerName $ComputerName
            $a | Select-Object -Property Description, IPAddress, IPSubnet, `
                DefaulIPGateway, DNSServerSearchOrder, DHCPServer, DNSHostName, DNSDomain
        }
        catch
        {
            Write-Host "Error credential on $ComputerName"
        }
    }
    else
    {
        Write-Host "Error RPC Access on $ComputerName"
    }
}