rule mirai_bot
{
	meta:
 		description ="This sample is bot file system"
	strings:
  		$a="mirai/tools/scanListen.go"
 		$b="mirai/bot/attack.h"
		$c="loader/src/headers/util.h"
		$d="mirai/bot/PK"
 	condition:
  		 $a and $b and $c and $d
	 
 }