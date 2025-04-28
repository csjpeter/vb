#!/usr/bin/python3
# Copyright Peter Csaszar (Császár Péter) 2021 <csjpeter@gmail.com>

import sys
if __file__ in sys.argv[0] :
	print (__file__ + " should not be executed directly")
	sys.exit(1)

import json
import time
import datetime
import subprocess
import fcntl
import os
import re
import getopt

"""
Trick might be necessary on a new base vm (to be cloned) :
    echo 'csjpeter ALL=(ALL) NOPASSWD:ALL' | tee -a /etc/sudoers
    echo -e "\nUseDNS no" >> /etc/ssh/sshd_config
    rm /etc/ssh/*key*;  ssh-keygen -A
    vboxmanage modifymedium disk ~/VirtualBox/ubuntu20/ubuntu20.vdi --compact
Tricks after clone:
    hostname NEW_HOSTNAME
    echo 'NEW_HOSTNAME' > /etc/hostname
    hostnamectl set-hostname NEW_HOSTNAME
Trick to set up new host for virtualbox machines :
    vboxmanage hostonlyif create
    vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.40.0 --netmask 255.255.255.0
    vboxmanage list hostonlyifs
"""

def parseRange(arg) : #{{{
	vmIds = []

	groups = arg.split(",")
	for group in groups :
		if "-" in group :
			beginend = group.split('-')
			begin = int(beginend[0])
			end = int(beginend[1])
			for i in range(begin,end+1) :
				vmIds.append(i)
		else :
			vmIds.append(int(group))
	return vmIds
#}}}

def parseVmNames(opts) : #{{{
	vmNamePrefix = None
	vmSingleId   = None
	vmIdRange    = []
	for opt, arg in opts :
		if opt in ("--name") :
			vmNamePrefix = arg
		elif opt in ("--id") :
			vmSingleId = int(arg)
		elif opt in ("--range") :
			vmIdRange = parseRange(arg)
	if vmNamePrefix is None :
		print("A value for --name have to be specified.")
		sys.exit(2)
	vmNames = []
	if vmSingleId is None and len(vmIdRange) == 0 :
		vmNames.append((vmNamePrefix, None))
	if vmSingleId is not None :
		vmNames.append((vmNamePrefix, vmSingleId))
	for vmId in vmIdRange :
		vmName = "%s%d" % (vmNamePrefix, vmId)
		vmNames.append((vmName, vmId))
	return vmNames
#}}}

def shell(#{{{
		command,
                echo = False,
		dry = False,
                pseudoTerm = True,
                timeout = 0,
                throwOnError = True) :

	pseudoTermArg = ""
	if pseudoTerm :
		pseudoTermArg = "t"
	if echo :
		print(command)
	if dry :
		return ""
	cmd = "bash -c " + command
	p = subprocess.Popen(["bash", "-c", command],
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)
	timedOut = False
	stdOut = ""
	stdErr = ""
	Out = ""
	Err = ""
	exitCode = None
	processStartTime = time.time()
	# set p.stdout non blocking io
	fd = p.stdout.fileno()
	fl = fcntl.fcntl(fd, fcntl.F_GETFL)
	fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
	# set p.stderr non blocking io
	fd = p.stderr.fileno()
	fl = fcntl.fcntl(fd, fcntl.F_GETFL)
	fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
	# loop to wait untill subprocess exit or timeout
	while exitCode == None :
		#time.sleep(1)
		try :
			out,err = p.communicate(timeout=1)
			Out += out.decode("utf-8")
			Err += err.decode("utf-8")
		except subprocess.TimeoutExpired :
			pass
		except IOError :
			pass
		exitCode = p.poll()
		#msg("timeout: %d spent time: %d" % (timeout, (time.time()-processStartTime)))
		if (0 < timeout) and (timeout < time.time() - processStartTime) :
			try :
				p.kill()
			except :
				pass
			timedOut = True
			break
		if len(Out) != 0 :
			#print (Out)
			stdOut += Out
			Out = ""
		if len(Err) != 0 :
			#print (Err)
			stdErr += Err
			Err = ""
	if len(Out) != 0 :
		#print (Out)
		stdOut += Out
	if len(Err) != 0 :
		#print (Err)
		stdErr += Err

	stdOut = stdOut.strip("\n\r\t ")
	stdErr = stdErr.strip("\n\r\t ")

	if timedOut == True :
		raise Exception("SHELL command timed out in %d seconds: %s" % (timeout, cmd))
	if p.returncode != 0 and throwOnError == True :
		raise Exception ("Command\n%s\nreturned with exit code %s.\n"
				#"StdOut:\n %s\n"
				"StdErr:\n %s" % (
				cmd,
				str(p.returncode),
				#stdOut,
				stdErr
				))
	return stdOut
#}}}

def ssh_ip(ip, #{{{
		command,
		echo = False,
		pseudoTerm = True,
		timeout = 0) :
	pseudoTermArg = ""
	if pseudoTerm :
		pseudoTermArg = "t"
	sshcmd = "ssh -q"+pseudoTermArg + " -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no " + ip + " " + command
	if echo :
		print ("SSH %s $ %s" % (ip, command))
	p = subprocess.Popen(
			[
				"ssh",
				"-q"+pseudoTermArg,
				"-o UserKnownHostsFile=/dev/null",
				"-o StrictHostKeyChecking=no",
				ip,
				command],
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)
	timedOut = False
	stdOut = ""
	stdErr = ""
	exitCode = None
	processStartTime = time.time()
	lastWarningTime = time.time()
	# set p.stdout non blocking io
	fd = p.stdout.fileno()
	fl = fcntl.fcntl(fd, fcntl.F_GETFL)
	fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
	# set p.stderr non blocking io
	fd = p.stderr.fileno()
	fl = fcntl.fcntl(fd, fcntl.F_GETFL)
	fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
	# loop to wait untill subprocess exit or timeout
	while exitCode == None :
		time.sleep(1)
		try :
			out,err = p.communicate(timeout=1)
			stdOut += out.decode("utf-8")
			stdErr += err.decode("utf-8")
		except subprocess.TimeoutExpired :
			pass
		except IOError :
			pass
		exitCode = p.poll()
		if 30 < (time.time()-lastWarningTime) :
			lastWarningTime = time.time()
		if (0 < timeout) and (timeout < time.time() - processStartTime) :
			try :
				p.kill()
			except :
				pass
			timedOut = True
			break
	stdOut = stdOut.strip("\n\r\t ")
	stdErr = stdErr.strip("\n\r\t ")
	if echo :
		if len(stdOut) != 0 :
			print (stdOut)
		if len(stdErr) != 0 :
			print (stdErr)
	if timedOut == True :
		raise Exception("SSH command timed out in %d seconds: %s" % (
				timeout, sshcmd))
	if p.returncode != 0 :
		raise Exception ("'" + sshcmd +
				"'; returned code " + str(p.returncode) +
				" with stdErr:\n" + stdErr +
				"\n and stdOut:\n" + stdOut + ".")
	return stdOut
#}}}

def genIp(vmId, netName) : #{{{
	ipPrefix = detectHostOnlyIpPrefix(netName)
	return "%s.%d" % (ipPrefix, vmId)
#}}}

def genMAC(vmId, netName, macPrefix="0E:00:") : #{{{
	ip = genIp(vmId, netName)
	ipNums = ip.split('.')
	macNums = []
	for n in ipNums :
		macNums.append("%02X" % int(n))
	return "%s%s" % (macPrefix , ":".join(macNums))
#}}}

def vboxmanage (args = "", echo=True) : #{{{
	command = "vboxmanage %s" % args
	if echo :
		print(command)
	return shell (command)
#}}}

def detectHostOnlyIpPrefix(netName) : #{{{
	stdOut = vboxmanage("list hostonlyifs", echo=False)
	stdOutLines = stdOut.split('\n')

	prefix = ""

	sectionFound = False
	for line in stdOutLines :
		if sectionFound == False :
			match = re.match("^Name:[ \t]*([a-zA-Z][^ \t\n]*)",
					line)
			if match == None :
				continue
			if netName == match.group(1) :
				sectionFound = True
			continue
		#if sectionFound == True :
		match = re.match("^IPAddress:[ \t]*([0-9][^ \t\n]*)",
				line)
		if match == None :
			continue
		prefix = match.group(1)[0:-2]
		break

	if prefix == "" :
		print("Failed to query network ip "
				"for hostonly interface '%s'." % netName)
		sys.exit(2)

	return prefix
#}}}

def vmInfoLines(vmName) : #{{{
	vmInfo = vboxmanage("showvminfo "+vmName, echo=False)
	vmInfoLines = vmInfo.split('\n')
	return vmInfoLines
#}}}

def vmPropertyLines(vmName) : #{{{
	vmProperties = vboxmanage("guestproperty enumerate "+vmName, echo=False)
	vmPropertiesLines = vmProperties.split('\n')
	return vmPropertiesLines
#}}}

def detectMac(vmName, vmInfoLines) : #{{{
	mac1=""
	for line in vmInfoLines :
		match = re.match("^NIC 1: +MAC: ([^,]+), Attachment: ([^,]*),",
				line)
		if match != None :
			mac1 = match.group(1)
			return mac1
	raise Exception("Failed to find MAC for vmName '%s'." % vmName)
#}}}

def ipFromMac(mac) : #{{{
	prefix = str(mac[0:4])
	if prefix != "0E00" :
		raise Exception("The received mac '%s' does not start with "
				"'0E00', can not convert to ip." % mac)
	ips = []
	ips.append("%d" % int(mac[4:6], 16))
	ips.append("%d" % int(mac[6:8], 16))
	ips.append("%d" % int(mac[8:10], 16))
	ips.append("%d" % int(mac[10:12], 16))
	return ".".join(ips)
#}}}

def restoreSnapshot (vmName, snapshotName) : #{{{
	stdOut = vboxmanage("snapshot %s restore %s" %  (vmName, snapshotName))
	if stdOut != "" :
		print(stdOut)
#}}}

def takeSnapshot (vmName, snapshotName) : #{{{
	stdOut = vboxmanage("snapshot %s take %s" %  (vmName, snapshotName))
	if stdOut != "" :
		print(stdOut)
#}}}

def deleteSnapshot (vmName, snapshotName) : #{{{
	stdOut = vboxmanage("snapshot %s delete %s" %  (vmName, snapshotName))
	if stdOut != "" :
		print(stdOut)
#}}}

def startvm (vmName) : #{{{
	stdOut = vboxmanage("startvm %s --type headless" % vmName)
	if stdOut != "" :
		print(stdOut)
#}}}

def startvmGui (vmName) : #{{{
	stdOut = vboxmanage("startvm %s --type gui" % vmName)
	if stdOut != "" :
		print(stdOut)
#}}}

def waitForStarted(vmName) : #{{{
	print("Waiting for working ssh connection to %s ..." % vmName)

	ip = ipFromMac(detectMac(vmName, vmInfoLines(vmName)))
	started = False
	while started == False :
		try :
			ssh_ip(ip, "true", echo = True)
			started = True
		except :
			time.sleep(1)
			pass
#}}}

def waitForManyStarted(vmNames) : #{{{
	vmIps = {}
	waitCount = 0
	for vmName,vmId in vmNames :
		print("Waiting for working ssh connection to %s ..." % vmName)
		vmIp = ipFromMac(detectMac(vmName, vmInfoLines(vmName)))
		vmIps[vmIp] = False
		waitCount += 1

	while 0 < waitCount :
		for vmIp in vmIps :
			if not vmIps[vmIp] :
				try :
					ssh_ip(vmIp, "true", echo = True)
					vmIps[vmIp] = True
					waitCount -= 1
				except Exception as e :
					#print("%s" % e.error)
					pass
		time.sleep(1)
#}}}

def savevm (vmName) : #{{{
	stdOut = vboxmanage("controlvm %s savestate" % vmName)
	if stdOut != "" :
		print(stdOut)
#}}}

def stopvm (vmName) : #{{{
	stdOut = vboxmanage("controlvm %s acpipowerbutton" % vmName)
	if stdOut != "" :
		print(stdOut)
#}}}

def poweroff (vmName) : #{{{
	stdOut = vboxmanage("controlvm %s poweroff" % vmName)
	if stdOut != "" :
		print(stdOut)
#}}}

def modifyvm (vmName, args = "") : #{{{
	stdOut = vboxmanage("modifyvm " + vmName + " " + args)
	if stdOut != "" :
		print(stdOut)
#}}}

def clonevm (sourceVmName, vmName) : #{{{
	stdOut = vboxmanage("clonevm " + sourceVmName +
			" --mode all --name " + vmName + " --register")
	if stdOut != "" :
		print(stdOut)

	modifyvm(vmName, "--cpus 1")
	modifyvm(vmName, "--cpuexecutioncap 80")
	modifyvm(vmName, "--hwvirtex on")
	modifyvm(vmName, "--memory 1024")
#}}}

def delete (vmName) : #{{{
	stdOut = vboxmanage("unregistervm " + vmName + " --delete")
	if stdOut != "" :
		print(stdOut)
#}}}

def configNIC (vmName, vmId, netName = "vboxnet0", nicId = 1) : #{{{
	modifyvm(vmName, "--nic%d hostonly" % nicId)
	modifyvm(vmName, "--hostonlyadapter%d %s" % (
			nicId, netName))
	modifyvm(vmName, "--macaddress%d %s" % (
			nicId, genMAC(vmId, netName).replace(":", "")))
#}}}

def generateIscDhcpConfig (vmNames, netName) : #{{{
	ipPrefix = detectHostOnlyIpPrefix(netName)
	print("subnet %s.0 netmask 255.255.255.0 {"
			"\n\trange %s.2 %s.253;"
			"\n\toption routers %s.1;"
			"\n}\n" % (
				ipPrefix,
				ipPrefix,
				ipPrefix,
				ipPrefix))
	for vmName,vmId in vmNames :
		mac = genMAC(vmId, netName)
		name = "host_%s" % mac.replace(":", "")
		ip = "%s.%d" % (ipPrefix, vmId)
		print("host %s {"
				"\n\thardware ethernet %s;"
				"\n\tfixed-address %s;"
				"\n}\n" % (
					name,
					mac,
					ip))
#}}}

def generateHostsFile (vmNames, netName) : #{{{
	ipPrefix = detectHostOnlyIpPrefix(netName)
	for vmName,vmId in vmNames :
		print("%s	v%d.g" % (
				"%s.%d" % (ipPrefix, vmId),
				vmId))
#}}}

def modifyRam (vmName, ram) : #{{{
	modifyvm(vmName, " --memory %d" % ram)
#}}}

def modifyCpuNum (vmName, cpuNum) : #{{{
	modifyvm(vmName, " --cpus %d" % cpuNum)
#}}}

def modifyCpuExecCap (vmName, cpuExecCap) : #{{{
	modifyvm(vmName, " --cpuexecutioncap %d" % cpuExecCap)
#}}}

def exportvm (vmName) : #{{{
	stdOut = vboxmanage("export %s --output=%s.ova --ovf20" % (vmName, vmName))
	if stdOut != "" :
		print(stdOut)
#}}}

def importvm (fileName, vmName) : #{{{
	stdOut = vboxmanage("import %s --vmname %s" % (fileName, vmName))
	if stdOut != "" :
		print(stdOut)
#}}}

def listCameras () : #{{{
	stdOut = vboxmanage("list webcams")
	if stdOut != "" :
		print(stdOut)
#}}}

def attachCamera (vmName) : #{{{
	stdOut = vboxmanage("controlvm %s webcam attach /dev/video0" % vmName)
	if stdOut != "" :
		print(stdOut)
#}}}

def detachCamera (vmName) : #{{{
	stdOut = vboxmanage("controlvm %s webcam detach /dev/video0" % vmName)
	if stdOut != "" :
		print(stdOut)
#}}}

