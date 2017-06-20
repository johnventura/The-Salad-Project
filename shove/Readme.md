Introduction:

This tool functions as a MiTM utility for exploiting plaintext control 
channels. It sniffs for TCP segments with known values or "trigger". 
Once it observes these "triggers," it inserts other segments or "responses".

Configuration:

The primary configuraiton for this tool comes from an XML configuration file. 
It's format are as follows:


<doc>

	This tag defines the beginning and ending of the configuration data.

<console>

	This tag defines an IP address for a "listener." Many of the signatures
	are gonig to be "shellcode" or PIC assembly. The IP address defined
	in this tag is resolved as a 32 bit value, presumably by DNS.
	This 32 bit value is then written over whever the "magic" number
	0xb7b7b7b7 exists within the binary "responses."
	So, for example, this line:

		<console>10.0.0.1</console> 

	would cause any instance of 0xb7b7b7b7 to be replaced with 0x0a000001.

<sig>

	This tag defines a "signature" which includes a "trigger" and a 
	"response."  Once the "trigger" is observed within a TCP segment,
	the "response" is inserted into the data stream via packet spoofing.

<response>

	This tag defines the data that will be inserted into the data stream
	after the "trigger" is detected.

<rtype>

	This tag is currently unimplemented. In the future, users will be
	able to define responses with separate files instead of listing them
	within the configuration file.
 
<name>

	This tag allows users to "name" their signatures.
	This data may be used in alerting.

<direction>

	This value will be either "forward" or "reverse". Forward signatures
	will cause the response data to be appended to the data sent in the 
	"trigger". Reverse signatures will send their data as if they were
	reponses to the data sent in the "trigger."


Format:

	Much of the data in the configuration file will not be easily defined
	in text. "Binary" or "signed" input (or any bytes greater than 0x7f)
	can therefore be difficult to represent. The file format allows users
	to define values using "HTMLesque" escaping.  

	For example, the string "%41%43CD" will be understood as "ABCD", and
	the highest value single byte can be represented as "%ff". 


