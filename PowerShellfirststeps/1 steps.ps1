cls
#получить список модулей
Get-Help "module"

#версия powershell
$PSVersionTable

<#
версия ОС
#>
Get-WmiObject -Class Win32_operatingSystem
Get-WmiObject -Class Win32_operatingSystem -Property caption


# получение даты
Get-Date

#получить ip сетевой адрес 
Get-NetIPAddress -AddressFamily ipv4 -InterfaceAlias wi-fi

#пайплайн для получения данных и дальнейшей их обработки
Get-Service | Sort-Object -Property Status, name, DisplayName -Descending

#фильтрация данных
Get-Service | Where-Object -Property name -EQ 'some string value'
Get-Service | Where-Object -Property status -EQ 'running'
Get-Service | Where-Object -Property name -like 'win*'
Get-Service | Where-Object -Property name -like 'win*' | Where-Object -Property status -EQ 'running'

Get-Service | Where-Object -FilterScript {$_.Name -like 'win*' -or $psitem.Name -like 'a*'}
Get-Service | Where-Object -FilterScript {$_.Name -like 'win*' -and $_.status -EQ 'running'}
Get-Service | Where-Object -FilterScript {$_.Name -like 'win*' -and $_.status -like 'run*'}

#операторы сравнения
$a = 15
$b = 25
$a -eq $b # equals
$a -ne $b # not equals
$a -gt $b # greater then
$a -ge $b # greater or equal
$a -lt $b # lower then
$a -le $b # lower or equal
$a -le 44
'text1' -like 'text2'
'text1' -notlike 'text2'
'text1' -like 'text*' # * - сколько угодно символов, ? - каждый один символ, 
'text1' -like 'te???' # true
'text1' -like 'te??' # false

$d = 'text1', 'text2', 'text3'
$e = 'text2'
# -Match, -NotMatch соттоветствие на основе регулярных выражений. 
# -Contains, -NoContains
# -In, -NotIn
$d -eq $e # text2
$d -ne $e # text1 text3
$d -match $e # text2
$d -notmatch $e # text1 text3
$e -notmatch $d # true
$e -match $d # false
$d -match 'te' # text1 text2 text3
'te' -match $d # false
$d -match 'xt1' # text1
$d -notmatch 'xt1' # text2 text2
$e -notcontains $d # true
$e -in $d # true
$e -notin $d # false
$d -in $d # false
$d -in $d, 'text5' # true

update-help
Get-Help about_comparison_operators
Get-Help about_Operators
Get-Help about_Regular_Expressions
Get-Help about_Wildcards
Get-Help Compare-Object
Get-Help Foreach-Object
Get-Help Where-Object



# выборка данных Select-Object 
Get-Service | Select-Object -Property name, status
Get-Service -Name wuauserv
Get-Service -Name wuauserv | Select-Object -Property *
# задать новое свойство для объекта
Get-Service | Select-Object -Property name, status, @{name  ='Description'; expression={$_.     displayname }}
Get-Service | Select-Object -Property name, status, @{n     ='Description'; expression={$_.     displayname }}
Get-Service | Select-Object -Property name, status, @{table ='Description'; e         ={$psitem.displayname }}
Get-Service | Select-Object -Property name, status, @{l     ='Description'; e         ={$psitem.displayname }}
# последующая выборка с переносом на новую строку
Get-Service | Select-Object -Property name, status, @{l     ='Description'; e         ={$psitem.displayname }} | `
    Sort-object -Property Description
# в переменную загрузим контент из папки c\windows\System32
$a = Get-ChildItem C:\Windows\System32
$a
$a[0]
$a[0] | Select-Object -p *
$a[0] | Select-Object -p psiscontainer # true - нужно избавиться от контенйнеров
$a | Where-Object -Property psiscontainer -eq $true
$a | Where-Object -Property psiscontainer -eq $false | Select-Object -Property name, @{name='size';e={$PSItem.length/1MB}}

# арифметические операторы
# +
# -
# *
# / деление
# % деление нацело
$a = 15
$a + 2
$a / 2
# форматирование
"{0:F2}" -f ($a) # фикс число знаков после запятой
"{0:N2}" -f ($a) # десятичное число
"{0:C2}" -f ($a) # currency
"{0:P2}" -f ($a/100) #  percents
"{0:P2}" -f (0.25) #  percents
"{0:X2}" -f ($a) # 16-ричная
$a = Get-ChildItem C:\Windows\System32
$a | Where-Object -Property psiscontainer -eq $false | `
    Select-Object -Property name, @{name='size';e={"{0:N2}" -f ($PSItem.length/1KB)}}
$a | Where-Object -Property psiscontainer -eq $false | `
    Select-Object -Property name, @{name='size';e={"{0:F2}" -f ($PSItem.length/1KB)}}
$a = 89145407878
"{0:#(###) ###-##-##}" -f $a #8(914) 540-78-78

# форматирование вывода
# format-list
# format-table
# format-wide
# format-custom
get-service -name wuauserv | format-list -property *
get-service -name win*
get-service -name win* | Select-Object -Property *
get-service -name win* | Select-Object -Property * | ft # таблица
get-service -name win* | Select-Object -Property name `
    ,CanPauseAndContinue, CanShutdown,  status| ft # таблица
get-service -name win* | Select-Object -Property name `
    ,CanPauseAndContinue, CanShutdown,  status # default is table format
get-service -name win* | Select-Object -Property name `
    ,CanPauseAndContinue, CanShutdown,  status| fl # список

# ведение журнала
# start-transcript -Path c:\log.txt # указание файла журнала
# start-transcript -Path c:\log.txt -Append # добавление данных
# stop-transcript
# 
Clear-Host

start-transcript
$a = Get-WmiObject -Class win32_operatingsystem
$a | Select-Object -Property *
$a.Caption
Stop-Transcript

powershell_ise.exe C:\Users\nisto\Documents\PowerShell_transcript.NIKITAROG1.I+utaLaS.20190317221015.txt
# убрать лишний output
# оставить только вызываемые комманды
<#
$a = Get-WmiObject -Class win32_operatingsystem
$a.Caption
#>



# функциии
function Start-ICMPScanner
{
<#
.Synopsis
    Start ICMP Echo Scanner
.Description
    Start ICMP Echo Scanner for 10.0.0.1 - 10.0.0.3
.Example
    Start-ICMPScanner

    Basic Syntax
.Example
    $a = Start-ICMPScanner; &$a 
    
    Выполнить команду
.Notes
    Made by Nikita Temnikov for developing purposes
.Link
    http://nikitatemnikov.com
#>
    $tab = "`t" # табулятор
    for ($i = 1; $i -le 3; $i ++)
    {
        $ip = '10.0.0.' + $i
        $result = Test-Connection -ComputerName $ip -Count 1 -Quiet
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
Start-ICMPScanner


# список комманд
Get-Command
# список функций
Get-Command -CommandType Function
# Get-Command -CommandType Function | Select-Object -Property *
get-help Write-VolumeCache
# с примерами
get-help Write-VolumeCache -Examples
# описание собственной функции
get-help Start-ICMPScanner
get-help Start-ICMPScanner -Examples
# добавление описательного комментария
<#
.Synopsis
    Start ICMP Echo Scanner
.Description
    Start ICMP Echo Scanner for 10.0.0.1 - 10.0.0.3
.Example
    Start-ICMPScanner

    Basic Syntax
.Example
    $a = Start-ICMPScanner; &$a 
    
    Выполнить команду
.Notes
    Made by Nikita Temnikov for developing purposes
.Link
    http://nikitatemnikov.com
#>

# функции с переменными
function Start-ICMPScanner
{
<#
.Synopsis
    Start ICMP Echo Scanner
.Description
    Start ICMP Echo Scanner for 10.0.0.1 - 10.0.0.3
.Example
    Start-ICMPScanner

    Basic Syntax
.Example
    $a = Start-ICMPScanner; &$a 
    
    Выполнить команду
.Notes
    Made by Nikita Temnikov for developing purposes
.Link
    http://nikitatemnikov.com
#>
Param (
    [string] $Range, 
    [int] $StartIP, 
    [int] $EndIP, 
    [int] $CallCount
    )

    $tab = "`t" # табулятор
    for ($i = $StartIP; $i -le $EndIP; $i ++)
    {
        $ip = $Range + $i
        $result = Test-Connection -ComputerName $ip -Count $CallCount -Quiet
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

Start-ICMPScanner -Range '10.0.0.' -StartIP 1 -EndIP 2 -CallCount 2
Start-ICMPScanner -Range '192.168.137.' -StartIP 1 -EndIP 3 -CallCount 1
Start-ICMPScanner # приводит к ошибке


# функции с переменными и ошибкаим для плохих типов
function Start-ICMPScanner
{
<#
.Synopsis
    Start ICMP Echo Scanner
.Description
    Start ICMP Echo Scanner for 10.0.0.1 - 10.0.0.3
.Example
    Start-ICMPScanner

    Basic Syntax
.Example
    $a = Start-ICMPScanner; &$a 
    
    Выполнить команду
.Notes
    Made by Nikita Temnikov for developing purposes
.Link
    http://nikitatemnikov.com
#>
Param (
    [string] $Range = $(Throw "Set the Range parameter, Example: '19.168.0.'"), 
    [int] $StartIP = $(Throw "Set the StartIP parameter, Example: 1"), 
    [int] $EndIP = $(Throw "Set the EndIP parameter, Example: 3"),  
    [int] $CallCount = $(Throw "Set the ICMP CALL COUNT parameter, Example: 1")
    )

    $tab = "`t" # табулятор
    for ($i = $StartIP; $i -le $EndIP; $i ++)
    {
        $ip = $Range + $i
        $result = Test-Connection -ComputerName $ip -Count $CallCount -Quiet
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

Start-ICMPScanner # Exception
<# 
Set the Range parameter, Example: '19.168.0.'
At line:22 char:25
+ ... g] $Range = $(Throw "Set the Range parameter, Example: '19.168.0.'"),
+                   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : OperationStopped: (Set the Range p...le: '19.168.0.':String) [], RuntimeException
    + FullyQualifiedErrorId : Set the Range parameter, Example: '19.168.0.'
#>



# дополнительные валидации
function Start-ICMPScanner
{

Param (
    [ValidatePattern("\d{1,3}.\d{1,3}.\d{1,3}.")][ValidateLength(6,12)][string] $Range = $(Throw "Set the Range parameter, Example: '19.168.0.'"), 
    [ValidateRange(1, 255)][int] $StartIP = $(Throw "Set the StartIP parameter, Example: 1"), 
    [ValidateRange(1, 255)][int] $EndIP = $(Throw "Set the EndIP parameter, Example: 3"),  
    [ValidateRange(1, 10)][int] $CallCount = $(Throw "Set the ICMP CALL COUNT parameter, Example: 1")
    )

    $tab = "`t" # табулятор
    for ($i = $StartIP; $i -le $EndIP; $i ++)
    {
        $ip = $Range + $i
        $result = Test-Connection -ComputerName $ip -Count $CallCount -Quiet
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
# валидные запросы
Start-ICMPScanner -Range '192.168.137.' -StartIP 1 -EndIP 3 -CallCount 1
Start-ICMPScanner -Range '10.0.0.' -StartIP 1 -EndIP 3 -CallCount 1
# невалидные запросы
Start-ICMPScanner -Range '10.0.0' -StartIP 1 -EndIP 3 -CallCount 1



# другая функция
function Get-IPV4Address
{
<#
#>
    Param([string] $ComputerName)
    # Get-WmiObject -Class win32_networkAdapterConfiguration
    $a = Get-WmiObject -Query 'select * from win32_networkAdapterConfiguration where index = 4' -ComputerName $ComputerName
    #$a | Select-Object -Property * # много свойств
    $a | Select-Object -Property Description, IPAddress, IPSubnet, `
        DefaulIPGateway, DNSServerSearchOrder, DHCPServer, DNSHostName, DNSDomain
}
Get-IPV4Address -ComputerName localhost

# try catch ...
Get-IPV4Address -ComputerName iis01 # такой машины нет
# попробуем предварительно машину пингануть
Test-Connection -ComputerName iis01 # Exception
Test-Connection -ComputerName adds01 # Exception
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
Test-Connection -ComputerName iis01
Test-Connection -ComputerName adds01


# права на исполнение сценариев
Test-Connection -ComputerName localhost

# установить состояние исполенния скриптов на дефолтное
Set-ExecutionPolicy Undefined # powershell должен быть запущен режиме администратора
Set-ExecutionPolicy AllSigned
# получить текущие права
Get-ExecutionPolicy
# запустить сценарии с разрешением на исполнение скриптов
powershell.exe -executionpolicy unrestricted # запускает экземпляр poowershell с правами на исполнение кода


# подписание сценариев
Get-AuthenticodeSignature
Set-AuthenticodeSignature
# для подписания скриптов потребуется шаблон сертификата: Code signing, он находится в Active Directory -> Certificate Service
###
# поиск своих сертификатов
Get-ChildItem Cert:\CurrentUser\My # выводится список сертификатов
# поиск своего сертификата для подписания скриптов от своего имени
Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
# сертификат можно положить в переменную
$a = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
# посмотреть список файлов в папке
ls
# задаём сертификат для скрипта
Set-AuthenticodeSignature .\scripts\ScriptExample1.ps1 -Certificate $a # добавляется хэш в конце файла
# посмотреть сертификат файла
Get-AuthenticodeSignature .\scripts\ScriptExample1.ps1 # Выводится ID сертификата, которым был подписан файл и его валидность


# модули
Get-Module # список загруженных модулей
Get-Module -ListAvailable # список доступных моделей
Import-Module
New-Module
Remove-Module
# расширение файлов *.psm1
# синтаксис
Import-Module C:\pspath\PSModule1.psm1
# ПОДГОТОВКА:
    # сохраним свои методы в файл ModuleExample1.psm1
# загрузим свой модуль
cd D:\OneDrive\Work\PowerShellfirststeps
Import-Module .\ModuleExample1.psm1 # получаем ошибку, т.к. модуль не подписан.
# можно подписать модуль и использовать его функции 


# ПРОФИЛИ (разобраться опдробнее зачем они нужны)
# смотрим оригинальный список загруженных модулей
Get-Module
# попробуем вызвать функцию незагруженного, но доступного модуля
Get-NetAdapter
# смотрим изменённый список модулей
Get-Module # пополнился список модулей
# создаём профиль
New-Item -ItemType file -Path $profile # создался профиль в указанном в "Directory: " каталоге
# откроем приложение с этой директорией
powershell_ise.exe $profile # откроется окно с указанным профилем
# # профиль можно подписать
# удалить профиль
Remove-Item $profile



# производительность команд
Measure-Command -Expression {Function1}
Measure-Command -Expression {Get-IPV4Address -ComputerName localhost}
Measure-Command -Expression {Get-NetIPAddress -AddressFamily ipv4 -IncludeAllCompartments -InterfaceAlias ethernet5}
Get-Command Get-NetIPAddress | Select-Object -Property *

# запомним время до начала команды + выполним команду - посмотрим разницу во времени
$t1 = Get-Date
Get-IPV4Address -ComputerName localhost
(Get-date) - $t1



# фоновы задачи работа с командами, которые работают очень долго
# например, есть такая команда
Start-ICMPScanner -Range '10.0.0.' -StartIP 1 -EndIP 254 -CallCount 1
# уберем эту команду в фоновую обработку
Start-Job -ScriptBlock {Start-ICMPScanner -Range '10.0.0.' -StartIP 1 -EndIP 254 -CallCount 1}
Start-Job -ScriptBlock {Start-ICMPScanner -Range '10.0.0.' -StartIP 1 -EndIP 254 -CallCount 1}
# запустили комнанду дважды и смотрим состояние работ
Get-Job # все работы провалислиь, т.к. в работы не был импортирован модуль, в которых есть эти функции
# импортируем модули
Start-Job -ScriptBlock {Import-Module D:\OneDrive\Work\PowerShellfirststeps\ModuleExample1.psm1; Start-ICMPScanner -Range '10.0.0.' -StartIP 1 -EndIP 254 -CallCount 1}
Start-Job -ScriptBlock {Import-Module D:\OneDrive\Work\PowerShellfirststeps\ModuleExample1.psm1; Start-ICMPScanner -Range '10.0.0.' -StartIP 1 -EndIP 254 -CallCount 1}
Get-Job # два работают и два завалились
# удаляем проваленные работы
Remove-Job -Id 11, 13
Get-Job
# посмотреть состояние какой-то работы
Receive-Job -Id 15
Receive-Job -Id 15 # если повторить результат, то увидим только то, что изменилось с последнего вывода
# чтобы сохранить последний вывод добавим ключ -keep
Receive-Job -Id 17 -Keep
Suspend-Job -Id 17 # операция может не поддерживаться функцией, находящейся в работе
Stop-Job -Id 17
Remove-Job -Id 17

Get-Job | Stop-Job # остановили все задания
Get-Job | Remove-Job # удалили все задания


# как создаются команды
ls C:\Windows\System32\WindowsPowerShell\v1.0\Modules\Appx\