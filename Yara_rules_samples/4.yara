import "hash"
rule worm
{
	meta:
 		description ="This sample is worm file system"
	strings:
  		$a="jnRAT/obj/Debug/DesignTimeResolveAssemblyReferences.cache"
 		$b="Stub Folder/Backup/Backup/E.v11.suo"
 	condition:
  		hash.md5(0, filesize)=="CF8F8E70DE39942A37B106140470BB45" and $a or $b
	 
 }