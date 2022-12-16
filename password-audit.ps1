# password audit script
## adapted from https://gist.github.com/JohnLBevan/8094f45176d2f3b1b830

<#

This script is intended to allow you to audit an AD domain for a given password/list of passwords.

It will collect a list of all users in the "domain users" group, and then try each of the supplied passwords for all of them.

*** BE CAREFUL ABOUT ACCOUNT LOCKOUT -- Don't put more passwords on list than lockout threshold. You can find this threshold via the following:

net accounts

This script is intended for benevolent purposes (authorized security auditing, testing, and education). I don't think you should use this on a network without the explicit permission of the owner or with malicious objectives, and if you do it isn't my fault

#>

## get domain users

$1=net group "domain users" /domain
$2=$1 -replace "The command completed successfully." | select -skip 8
$3=$2 -split " " | sort -unique -descending
$users=$3.trim() -ne ""
add-content -path .\all-users.txt -value $users

## initial loop setup

$passwords = @("Fall2022!")
$CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
$failures = @()

## auth test with password

foreach ($u in $users) {
	
	foreach ($p in $passwords) {

		$domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$u,$p)

		if ($domain.name) {
			$failures+="$u | $p"
			add-content -path .\failed-users.txt -value "$u | $p"
		}
	}
}
