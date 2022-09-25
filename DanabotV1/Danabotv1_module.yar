import "console"
import "parseutils"

rule danabot_config_extractor {
	meta:
		author = "Taha Y."
		danabot_samples = "https://github.com/f0wl/danaConfig"
		
	strings:
		$s1 = {4D0069006E00690049006E00690074003A004500780063006500700074000000}
		$s2 = {2E6F6E696F6E} //.onion

	condition:
		$s1 and console.hex("OFFSET : ",@s1+224) and 
		 console.log("C2-ip1: ",parseutils.print_int_data(@s1+214,4)) and
		 console.log("C2-ip2: ",parseutils.print_int_data(@s1+224,4)) and
		 console.log("C2-ip3: ",parseutils.print_int_data(@s1+234,4)) and
		 console.log("C2-ip4: ",parseutils.print_int_data(@s1+244,4)) and
		 console.log("TOR: ",parseutils.print_string_data(@s2-56,62))

}


