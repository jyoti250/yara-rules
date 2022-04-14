rule cmderfile
{
	meta:
 		description="This sample is cmder file system"
 		author= "jyoti"
	strings:
  		$a= "LCMapStringEx"
		$b= "ConEmu-%COMPUTERNAME%.xml"
  		$c= "Cmder.exe"
	
	condition:
  		( $a or $b or $c)
}