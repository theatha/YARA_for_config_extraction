import "console"
import "parseutils"
rule danabot_config_extractor {

    meta:
        author = "Taha Y."
        danabot_samples = "https://yaraify.abuse.ch/search/yara/MALWARE_Win_DanaBot/"
        
    strings:
        $s1 = {71 00 77 00 65 00 72 00 74 00 79 00 75 00 69 00 6F 00 70 00 61 00 73 00 64 00 66 00 67 00 68 00 6A 00 6B 00 6C 00 7A 00 78 00 63 00 76 00 62 00 6E 00 6D 00 71 77 65 72 74 79 75 69 6F 70 61 73 64 66 67 68 6A 6B 6C 7A 78 63 76 62 6E 6D}
        
    condition:
        $s1 and console.hex("OFFSET: ",@s1+698) and
            console.log("C2-ip1: ",parseutils.print_int_data(@s1+698,4)) and
            console.log("C2-ip2: ",parseutils.print_int_data(@s1+706,4)) and
            console.log("C2-ip3: ",parseutils.print_int_data(@s1+714,4)) and
            console.log("C2-ip4: ",parseutils.print_int_data(@s1+722,4))
}

