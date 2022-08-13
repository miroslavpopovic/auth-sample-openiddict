# A convenient PowerShell script to run all web projects at once

# Get current directory path
$src = (Get-Item -Path ".\src\" -Verbose).FullName;

# Iterate all directories present in the current directory path
Get-ChildItem $src -directory | Where-Object { $_.PsIsContainer } | Select-Object -Property Name | ForEach-Object {
    $cdProjectDir = [string]::Format("cd /d {0}\{1}", $src, $_.Name);

    # Check if project folder has Controllers or Pages folders
    # We assume only web projects have that
    $controllersDir = [string]::Format("{0}\{1}\Controllers", $src, $_.Name);
    $controllersExists = Test-Path $controllersDir -PathType Container;
    $pagesDir = [string]::Format("{0}\{1}\Pages", $src, $_.Name);
    $pagesExists = Test-Path $pagesDir -PathType Container;

    # Check project having bundle config file
    if ($controllersExists -or $pagesExists) {
        # Start cmd process and execute 'dotnet run'
        $params = @("/C"; $cdProjectDir; " && dotnet run"; )
        Start-Process -Verb runas "cmd.exe" $params;
    }
}
