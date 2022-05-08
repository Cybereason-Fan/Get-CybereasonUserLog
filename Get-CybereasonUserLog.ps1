Function global:Get-CybereasonUserLog {

    <#
.SYNOPSIS
Fetches the contents of the Cybereason 'User Actions Log' and returns a parsable array

.DESCRIPTION
Fetches the contents of the Cybereason 'User Actions Log' and returns a parsable array. The output will be an array of various types of log entry types. It will be up to you what to do next!

Warning #1: Any log entries without 'auditSyslogLogger' will be ignored by this script. This is mainly due to the presence of uncontrolled "test" messages that can be added to the log by administrators.
Warning #2: You will still need to do some parsing of the output but it is significantly more manageable than what the console gives us out of the box.

Hint #1: Isolate & uniqueify 'type' of log entry in order to inform your tools

.PARAMETER server_fqdn
Required string - This is the fully qualified domain name of the Cybereason console. There is no error-checking on this. Make sure you have it correct!

.PARAMETER session_id
Required String - This is the 32-character string (session id) that you received when you authenticated to the console (See Get-CybereasonCookie)

.PARAMETER DebugMode
Optional Switch that will verbosely display additional information

.EXAMPLE
Get-CybereasonUserLog -server_fqdn server.domain.com -session_id 53A09D960B8D553AEFDD73C1B4F55087

.LINK
https://git.dhl.com/miksimps/Get-CybereasonUserLog
#>

    Param(
        [OutputType([array])]
        [Parameter(Mandatory = $true)]
        [string]$session_id,
        [Parameter(Mandatory = $true)]
        [string]$server_fqdn,
        [Parameter(Mandatory = $false)]
        [switch]$debug_mode
    )
    Function Format-CybereasonLogEntry {
        [Cmdletbinding()]
        Param(
            [string]$log_entry
        )
        Function New-LogEntryObject {
            [OutputType([PSCustomObject])]
            [CmdletBinding()]
            Param(
                [datetime]$log_entry_date_object,
                [string]$log_entry_server_name,
                [string]$log_entry_collector, 
                [string]$log_entry_type,
                [int32]$log_entry_status,
                [array]$log_entry_array,
                [int32]$log_entry_array_count
            )
            [System.Collections.Specialized.OrderedDictionary]$log_entry_fields = [System.Collections.Specialized.OrderedDictionary]@{}
            For ($i = 0; $i -lt $log_entry_array_count; $i = $i + 4) {
                [string]$item_name = $log_entry_array[$i + 1]
                [string]$item_value = $log_entry_array[$i + 3]
                [void]$log_entry_fields.Add($item_name, $item_value)
            }
            [PSCustomObject]$log_entry_object = [PSCustomObject]@{ 'log_entry_date_object' = $log_entry_date_object; 'log_entry_server_name' = $log_entry_server_name; 'log_entry_collector' = $log_entry_collector; 'log_entry_type' = $log_entry_type; 'log_entry_status' = $log_entry_status; 'log_entry_fields' = $log_entry_fields; }
            Return $log_entry_object
        }
        [int32]$log_entry_length = $log_entry.Length
        If ( $log_entry_length -lt 32) {
            Write-Host "Error: How can a log entry be less than 32 bytes? Please look into this [$log_entry]"
            Return
        }
        [string]$log_entry_date_utc_string = $log_entry.SubString(0, 6)
        If ( $log_entry_date_utc_string -notmatch '^[A-Za-z]{3} [ \d]{2}$') {
            Write-Host "Error: Somehow [$log_entry_date_utc_string] is not a valid date string"
            Return
        }
        [string]$log_entry_time_utc_string = $log_entry.SubString(7, 8)
        Try {
            [datetime]$log_entry_date_object = Get-Date -Date ($log_entry_date_utc_string + ', ' + $current_year + ' ' + $log_entry_time_utc_string)    
        }
        Catch {
            [array]$error_clone = $Error.Clone()
            [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
            Write-Host "Error: The expected datetime value could not be processed due to [$error_message] [$log_entry]"
            Return
        }    
        [string]$log_entry_b = $log_entry.SubString(16, ($log_entry_length - 16))
        [array]$log_entry_b_split = $log_entry_b -split ' '
        [string]$log_entry_server_name = $log_entry_b_split | Select-Object -Skip 0 -First 1
        [string]$log_entry_collector = $log_entry_b_split | Select-Object -Skip 1 -First 1
        [string]$log_entry_c = ($log_entry_b -split ' ' | Select-Object -Skip 2) -join ' ' -replace 'CEF:0\|Cybereason\|Cybereason\|\|UserAction\|' -replace 'cs1=/', 'cs1='
        [array]$log_entry_c_split = $log_entry_c -split '\|'
        [string]$log_entry_type = $log_entry_c_split | Select-Object -Skip 0 -First 1
        Try {
            [int32]$log_entry_status = $log_entry_c_split | Select-Object -Skip 1 -First 1
        }
        Catch {
            [array]$error_clone = $Error.Clone()
            [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
            Write-Host "Error: The expected integer value could not be processed due to [$error_message] [$log_entry]"
            Return
        }    
        [string]$log_entry_d = ($log_entry_c_split | Select-Object -Skip 2)
        [array]$log_entry_array = $log_entry_d -split '(cs[\d]{0,}\d[Label]{0,}=|cn[\d]{0,}\d[Label]{0,}=|deviceCustomDate1Label=|deviceCustomDate1=)' -replace '=' | Select-Object -Skip 1
        [int32]$log_entry_array_count = $log_entry_array.Count
        If ( $log_entry_array_count -eq 0) {
            Write-Host "Error: Somehow the details array for this log entry is empty? Please look into this log entry [$log_entry]."
            Return
        }
        ElseIf ( $log_entry_array_count % 4 -gt 0 ) {
            Write-Host "Error: Somehow the number of log details in this entry array [$log_entry_array_count] is not an even number. Please look into this log entry [$log_entry]."
            Return
        }
        [hashtable]$parameters = @{}
        $parameters.Add('log_entry_date_object', $log_entry_date_object)
        $parameters.Add('log_entry_server_name', $log_entry_server_name)
        $parameters.Add('log_entry_collector', $log_entry_collector)
        $parameters.Add('log_entry_type', $log_entry_type)
        $parameters.Add('log_entry_status', $log_entry_status)
        $parameters.Add('log_entry_array', $log_entry_array)
        $parameters.Add('log_entry_array_count', $log_entry_array_count)
        Try {
            [PSCustomObject]$log_entry_object = New-LogEntryObject @parameters
        }
        Catch {
            [array]$error_clone = $Error.Clone()
            [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
            Write-Host "Error: Custom function New-LogEntryObject failed due to [$error_message] [$log_entry]"
            Return
        }
        Return $log_entry_object
    }
    [string]$current_year = Get-Date -Format 'yyyy'    
    Try {
        If( $null -eq (Get-Module -Name Microsoft.PowerShell.Utility) )
        {
		Import-Module Microsoft.Powershell.Utility
        }
    }
    Catch {
        [array]$error_clone = $Error.Clone()
        [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
        Write-Host "Error: Import-Module failed to load Microsoft.PowerShell.Utility due to [$error_message]"
        Return        
    }
    Try {
        Add-Type -AssemblyName System.IO.Compression
    }
    Catch {
        [array]$error_clone = $Error.Clone()
        [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
        Write-Host "Error: Add-Type failed to load the assembly System.IO.Compression due to [$error_message]"
        Return
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [string]$regex_jsessionid = '^[0-9A-F]{32}$'
    [string]$api_url = "https://$server_fqdn/rest/"
    [string]$api_command = 'monitor/global/userAuditLog'
    [string]$command_url = ($api_url + $api_command)
    [string]$server_name = $server_fqdn -replace 'http[s]{0,}://'
    If ( $session_id -cnotmatch $regex_jsessionid ) {
        Write-Host "Error: The session id must be a case-sensitive 32 character long string of 0-9 and A-F."
        Return
    }
    $Error.Clear()
    Try {
        [Microsoft.PowerShell.Commands.WebRequestSession]$web_session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    }
    Catch {
        [array]$error_clone = $Error.Clone()
        [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
        Write-Host "Error: New-Object failed to create a web request session object due to [$error_message]"
        Return
    }
    $Error.Clear()
    Try {
        [System.Net.Cookie]$cookie = New-Object System.Net.Cookie
        $cookie.Name = 'JSESSIONID'
        $cookie.Value = $session_id
        $cookie.Domain = $server_name
    }
    Catch {
        [array]$error_clone = $Error.Clone()
        [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
        Write-Host "Error: New-Object failed to create a cookie object due to [$error_message]"
        Return
    }
    $Error.Clear()
    Try {
        $web_session.Cookies.Add($cookie)
    }
    Catch {
        [array]$error_clone = $Error.Clone()
        [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
        Write-Host "Error: Failed to add the cookie object to the web request session object due to [$error_message]"
        Return
    }
    [hashtable]$parameters = @{}
    $parameters.Add('Uri', $command_url)
    $parameters.Add('Method', 'GET')    
    $parameters.Add('WebSession', $web_session)
    If ( $debug_mode -eq $true) {
        [string]$parameters_display = $parameters | ConvertTo-Json -Compress -Depth 4
        Write-Host "Debug: Sending parameters to Invoke-WebRequest $parameters_display"
    }
    $ProgressPreference = 'SilentlyContinue'
    $Error.Clear()
    Try {    
        [Microsoft.PowerShell.Commands.WebResponseObject]$response = Invoke-WebRequest @parameters
    }
    Catch {
        [array]$error_clone = $Error.Clone()
        [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
        Write-Host "Error: Invoke-WebRequest failed due to [$error_message]"
        Return
    }
    $ProgressPreference = 'Continue'
    If ( $response.StatusCode -isnot [int]) {
        Write-Host "Error: Somehow there was no numerical response code"
        Return
    }
    [int]$response_statuscode = $response.StatusCode
    If ( $response_statuscode -ne 200) {
        Write-Host "Error: Received numerical status code [$response_statuscode] instead of 200 'OK'. Please look into this."
        Return
    }
    $Error.Clear()
    Try {
        [byte[]]$downloaded_bytes = $response.Content
    }
    Catch {
        [array]$error_clone = $Error.Clone()
        [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
        Write-Host "Error: Not able to create byte array from downloaded content"
        Return
    }
    [int32]$total_bytes_count = $downloaded_bytes.Count
    If ( $total_bytes_count -eq 0) {
        Write-Host "Error: Somehow there are no downloaded bytes"
        Return
    }
    $Error.Clear()
    Try {
        [string]$downloaded_filename = $response.headers.'Content-Disposition' -split '"' | Select-Object -skip 1 -First 1
    }
    Catch {
        [array]$error_clone = $Error.Clone()
        [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
        Write-Host "Error: Not able to extract the filename from the downloaded response object"
        Return
    }    
    Try {
        [System.IO.Memorystream]$zip_stream = New-Object -TypeName System.IO.Memorystream
        $zip_stream.Write( $downloaded_bytes, 0, $total_bytes_count)
        [System.IO.Compression.ZipArchive]$zip_archive = New-Object -TypeName System.IO.Compression.ZipArchive($zip_stream)
        [System.IO.Compression.ZipArchiveEntry]$zip_entry = $zip_archive.GetEntry('userAuditSyslog.log')
        [System.IO.StreamReader]$entry_reader = New-Object -TypeName System.IO.StreamReader($zip_entry.Open())
        [string]$log_file_string = $entry_reader.ReadToEnd()
    }
    Catch {
        [array]$error_clone = $Error.Clone()
        [string]$error_message = $error_clone | Where-Object { $null -ne $_.Exception } | Select-Object -First 1 | Select-Object -ExpandProperty Exception
        Write-Host "Error: Not able to unzip the downloaded content due to [$error_message]"
        Return
    }
    [int32]$log_file_size = $log_file_string.Length
    [array]$log_file_array = $log_file_string -split "`n"
    [int32]$log_file_lines = $log_file_array.Count
    [string]$compression_ratio = "{0:P2}" -f ([decimal]1 - ([decimal]$total_bytes_count / [decimal]$log_file_size))
    If ( $debug_mode -eq $true) {
        Write-Host "Downloaded $downloaded_filename (line count: $log_file_lines) (bytes: $total_bytes_count) which inflated to $log_file_size bytes (ratio: $compression_ratio)"
    }
    [int32]$current_loop = 1
    [array]$log_file_formatted = ForEach ( $log_entry in $log_file_array) {
        If ( $log_entry -like '*auditSyslogLogger*') {
            [decimal]$percent_complete = ($current_loop / $log_file_lines)
            [string]$percent_complete_display = "{0:P2}" -f $percent_complete
            Write-Progress -Activity '   Processing Cybereason log: User Activity' -Status "Parsing line: [$current_loop/$log_file_lines] ($percent_complete_display)" -PercentComplete ($percent_complete * 100)
            Format-CybereasonLogEntry -log_entry $log_entry
            $current_loop++
        }
    }
    Write-Progress -Activity '   Processing Cybereason log: User Activity' -Completed
    Return $log_file_formatted
}
