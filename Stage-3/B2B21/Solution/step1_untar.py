#!/usr/bin/python

import os, sys, tarfile

extracted_files = []
path_delimeter = '/'

def get_folders(path):
	fullpath = os.path.join(path)
	dirs = [path+path_delimeter+fi+path_delimeter for fi in os.listdir(fullpath) if os.path.isdir(fullpath+path_delimeter+fi)]
	return dirs

def get_latest_file(path):
	"""Returns the name of the latest (most recent) file 
	of the joined path(s)"""
	fullpath = os.path.join(path)
	list_of_files = os.listdir(fullpath)
	#list_of_other_files = [ path+fi for fi in list_of_files if not fi.endswith(".tar") ]
	list_of_files = [ path+fi for fi in list_of_files if fi.endswith(".tar") and path+fi not in extracted_files]
	#for file_name in list_of_other_files:
	#	print(' File : '+file_name)
	if not list_of_files:
		return None
	latest_file = max(list_of_files, key=os.path.getctime)
	#_, filename = os.path.split(latest_file)
	return latest_file

#print(file)

challenge_folder = os.getcwd()+path_delimeter 

last_file = ""
while(1):
	file = get_latest_file(challenge_folder)
	#print(last_file, file)
	if last_file == file or file is None:
		break
	else:
		last_file = file
		try:
			print('Extracting : '+file)
			f = tarfile.open(file)
			f.extractall(challenge_folder)
			f.close()
			if len(last_file) > 0:
				os.remove(last_file)
			extracted_files.append(challenge_folder+file)
		except:
			print('     Error : '+file)
