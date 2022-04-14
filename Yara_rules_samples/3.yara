rule security_browser
{
	meta:
 		description ="This sample is browser security core file system"
	strings:
  		$a="http://www.microsoft.com/pki/certs/MicTimStaPCA_2010-07-01.crt0"
 		$b="http://www.microsoft.com/pki/certs/MicRooCerAut_2010-06-23.crt0"
		
 	condition:
  		$a and $b
	 
 }