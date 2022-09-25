import "console"
rule DanabotV2_Config_Extraction {

    meta:
        author = "Taha YILDIZ"
        danabot_samples = "https://yaraify.abuse.ch/search/yara/MALWARE_Win_DanaBot/"
        
        //c8f1ec2ef618dfcd254f5a9e397b70644b3ba070f0c327bae20a3054df0021c0
        //0abcf1b50c908693dc1f5e38e0ea4b00e6b4a6bb77dde445c60d4fe5d5697d1a
        //d85f98bbaf6a689437acd7b2e5a6b9c39b6aac0fb8f581712b7e6a196c100177
        
    strings:
        $s1 = {71 00 77 00 65 00 72 00 74 00 79 00 75 00 69 00 6F 00 70 00 61 00 73 00 64 00 66 00 67 00 68 00 6A 00 6B 00 6C 00 7A 00 78 00 63 00 76 00 62 00 6E 00 6D 00 71 77 65 72 74 79 75 69 6F 70 61 73 64 66 67 68 6A 6B 6C 7A 78 63 76 62 6E 6D}
        
    condition:
        $s1 and console.hex("[+] OFFSET ", @s1+698) 
            and console.log("[+] C2-#1:") and console.log("octet-1: ",uint8(@s1+698)) 
            and console.log("octet-2: ",uint8(@s1+699)) and console.log("octet-3: ",uint8(@s1+700)) and console.log("octet-4: ",uint8(@s1+701)) 

            and console.log("[+] C2-#2:") and console.log("octet-1: ",uint8(@s1+706)) 
            and console.log("octet-2: ",uint8(@s1+707)) and console.log("octet-3: ",uint8(@s1+708)) and console.log("octet-4: ",uint8(@s1+709)) 

            and console.log("[+] C2-#3:") and console.log("octet-1: ",uint8(@s1+714)) 
            and console.log("octet-2: ",uint8(@s1+715)) and console.log("octet-3: ",uint8(@s1+716)) and console.log("octet-4: ",uint8(@s1+717)) 

            and console.log("[+] C2-#4:") and console.log("octet-1: ",uint8(@s1+722)) 
            and console.log("octet-2: ",uint8(@s1+723)) and console.log("octet-3: ",uint8(@s1+724)) and console.log("octet-4: ",uint8(@s1+725)) 
}


