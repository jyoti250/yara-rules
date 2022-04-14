import "hash"
rule xmlsign
{
	meta:
 		description="This sample is xml file system"
  		
 	
	condition:
  		hash.md5(0, filesize)== "4a24bad44bce8e1f086da0e75d15b7c7" 
}