# Function found on https://stackoverflow.com/a/42843058/119230
function setHostEntries([hashtable] $entries) {
    $hostsFile = "$env:windir\System32\drivers\etc\hosts"
    $newLines = @()

    $hostFileLines = Get-Content -Path $hostsFile

    foreach ($line in $hostFileLines) {
        $lineParts = [regex]::Split($line, "\s+")

        if ($lineParts.count -eq 2) {
            $match = $NULL

            foreach ($entry in $entries.GetEnumerator()) {
                if ($lineParts[1] -eq $entry.Key) {
                    $newLines += ($entry.Value + ' ' + $entry.Key)
                    Write-Host Replacing HOSTS entry for $entry.Key
                    $match = $entry.Key
                    break
                }
            }

            if ($NULL -eq $match) {
                $newLines += $line
            } else {
                $entries.Remove($match)
            }
        } else {
            $newLines += $line
        }
    }

    foreach ($entry in $entries.GetEnumerator()) {
        Write-Host Adding HOSTS entry for $entry.Key
        $newLines += $entry.Value + ' ' + $entry.Key
    }

    Write-Host Saving $hostsFile
    Clear-Content $hostsFile

    foreach ($line in $newLines) {
        $line | Out-File -encoding ASCII -append $hostsFile
    }
}

# Figure out the local IP address of the machine
$localIpAddress=((ipconfig | findstr [0-9].\.)[0]).Split()[-1]

# Update all the DNS entries we need to use the current local IP address
$entries = @{
    'auth.sample.local' = $localIpAddress
    #'auth-admin.sample.local' = $localIpAddress
};
setHostEntries($entries)
