import "console"
rule DanabotV1_Config_Extraction {
	meta:
		author = "Taha Y."
		danabot_samples = "https://github.com/f0wl/danaConfig"
		
	strings:
		$s1 = {4D0069006E00690049006E00690074003A004500780063006500700074000000}

	condition:
		$s1 and console.hex("[+] OFFSET ", @s1+214) 
			and console.log("[+] C2-#1:") and console.log("octet-1: ",uint8(@s1+214)) 
			and console.log("octet-2: ",uint8(@s1+215)) and console.log("octet-3: ",uint8(@s1+216)) and console.log("octet-4: ",uint8(@s1+217)) 

			and console.log("[+] C2-#2:") and console.log("octet-1: ",uint8(@s1+224)) 
			and console.log("octet-2: ",uint8(@s1+225)) and console.log("octet-3: ",uint8(@s1+226)) and console.log("octet-4: ",uint8(@s1+227)) 

			and console.log("[+] C2-#3:") and console.log("octet-1: ",uint8(@s1+234)) 
			and console.log("octet-2: ",uint8(@s1+235)) and console.log("octet-3: ",uint8(@s1+236)) and console.log("octet-4: ",uint8(@s1+237)) 

			and console.log("[+] C2-#4:") and console.log("octet-1: ",uint8(@s1+244)) 
			and console.log("octet-2: ",uint8(@s1+245)) and console.log("octet-3: ",uint8(@s1+246)) and console.log("octet-4: ",uint8(@s1+247)) 

}