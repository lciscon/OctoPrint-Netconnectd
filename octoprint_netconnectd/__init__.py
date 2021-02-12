# coding=utf-8
from __future__ import absolute_import

__author__ = "Gina Häußge <osd@foosel.net>"
__license__ = 'GNU Affero General Public License http://www.gnu.org/licenses/agpl.html'
__copyright__ = "Copyright (C) 2014 The OctoPrint Project - Released under terms of the AGPLv3 License"


import logging
from flask import jsonify, make_response

import octoprint.plugin
import os
import subprocess

from octoprint.server import admin_permission

class NetconnectdSettingsPlugin(octoprint.plugin.SettingsPlugin,
                                octoprint.plugin.TemplatePlugin,
                                octoprint.plugin.SimpleApiPlugin,
                                octoprint.plugin.AssetPlugin):

	def __init__(self):
		self.address = None

	def initialize(self):
		self.address = self._settings.get(["socket"])

	@property
	def hostname(self):
		r = self._exec_cmd("hostname")
		return(r)


#	@property
#	def hostname(self):
#		hostname = self._settings.get(["hostname"])
#		if hostname:
#			return hostname
#		else:
##			import socket
##			return socket.gethostname() + ".local"

	##~~ SettingsPlugin

	def on_settings_save(self, data):
		octoprint.plugin.SettingsPlugin.on_settings_save(self, data)
		self.address = self._settings.get(["socket"])

	def get_settings_defaults(self):
		return dict(
			socket="/var/run/netconnectd.sock",
			hostname="octopi",
			timeout=10
		)

	##~~ TemplatePlugin API

	def get_template_configs(self):
		return [
			dict(type="settings", name="Network connection")
		]

	##~~ SimpleApiPlugin API

	def get_api_commands(self):
		return dict(
			get_hostname=[],
			get_ssid=[],
			get_address=[],
			set_hostname=["newname"],
			refresh_wifi=[],
			list_wifi=[],
			configure_wifi=[],
			forget_wifi=[],
			reset=[]
		)

	def is_api_adminonly(self):
		return True

	def on_api_get(self, request):
		try:
			hostname = self._get_hostname()
			status = "online"
			wifis = self._get_wifi_list()
#			status = self._get_status()
#			if status["wifi"]["present"]:
#				wifis = self._get_wifi_list()
#			else:
#				wifis = []
		except Exception as e:
			return jsonify(dict(error=str(e)))

		return jsonify(dict(
			wifis=wifis,
			status=status,
			hostname=hostname
		))

	def on_api_command(self, command, data):
		if command == "list_wifi":
			return jsonify(dict(wifis=self._get_wifi_list(force=True)))

		if command == "get_hostname":
			self._logger.info("Returning hostname "+ self._get_hostname())
			return jsonify(dict(hostname=str(self._get_hostname())))

		elif command == "set_hostname":
			self._logger.info("Setting hostname to "+ data["newname"])
			self._set_hostname(data["newname"])
			return;

		elif command == "get_ssid":
			self._logger.info("Returning ssid "+ self._get_ssid())
			return jsonify(dict(ssid=str(self._get_ssid())))

		elif command == "get_address":
			self._logger.info("Returning address "+ self._get_address())
			return jsonify(dict(address=str(self._get_address())))

		# any commands processed after this check require admin permissions
		if not admin_permission.can():
			return make_response("Insufficient rights", 403)

		if command == "configure_wifi":
			if data["psk"]:
				self._logger.info("Configuring wifi {ssid} and psk...".format(**data))
			else:
				self._logger.info("Configuring wifi {ssid}...".format(**data))

			self._configure_and_select_wifi(data["ssid"], data["psk"], force=data["force"] if "force" in data else False)

		elif command == "forget_wifi":
			self._forget_wifi()

		elif command == "reset":
			self._reset()

	##~~ AssetPlugin API

	def get_assets(self):
		return dict(
			js=["js/netconnectd.js"],
			css=["css/netconnectd.css"],
			less=["less/netconnectd.less"]
		)

	##~~ Private helpers

	def _get_hostname(self):
		result = self.hostname
		return result

	def _set_hostname(self, newname):
		self._exec_cmd("sudo sethostname " + newname)

	def _get_ssid(self):
		r = self._exec_cmd("sudo netcmd ssid")
		self._logger.info("Returning ssid " + r)
		return r

	def _get_address(self):
		r = self._exec_cmd("sudo netcmd address")
		return r

	def _get_wifi_list(self, force=False):

		r = self._exec_cmd("sudo netcmd wifis")
		lines = r.split('\n')
#		self._logger.info("wifi list lines:" + str(lines))

		result = []
		cur_signal = "0"
		cur_encrypted = False
		cur_address = "0"
		cur_ssid = ""
		for rowval in lines:
			row = rowval.lstrip()
			if row.startswith("Cell"):
				sub1 = row.split('-')
				if (sub1[1]):
					row = sub1[1].lstrip();

#			self._logger.info("scanning row:" + str(row))
			if row.startswith("Quality"):
				sub1 = row.split(' ')
				cur_signal = 0
				if sub1[0]:
					sub2 = sub1[0].split('=')
					sub3 = sub2[1].split('/')
					cur_signal = sub3[0]
			elif row.startswith("Encryption"):
				sub1 = row.split(':')
				encryptstr = "off"
				if (sub1[1]):
					encryptstr = sub1[1]
				if encryptstr == "on":
					cur_encrypted = True
				else:
					cur_encrypted = False
			elif row.startswith("Address"):
				sub1 = row.split(': ')
				if (sub1[1]):
					cur_address = sub1[1]
			elif row.startswith("ESSID"):
				sub1 = row.split('"')
#				self._logger.info("scanning ssid:" + str(sub1))
				if (sub1[1]):
					if len(sub1[1]) > 0:
						cur_ssid = sub1[1]
#						self._logger.info("found ssid:" + str(cur_ssid))
						result.append(dict(ssid=cur_ssid, address=cur_address, quality=cur_signal, encrypted=cur_encrypted))

#		self._logger.info("Returning wifi list " + str(result))

		return result

	def _get_wifi_list2(self, force=False):
		payload = dict()
		if force:
			self._logger.info("Forcing wifi refresh...")
			payload["force"] = True

		flag, content = self._send_message("list_wifi", payload)
		if not flag:
			raise RuntimeError("Error while listing wifi: " + content)

		result = []
		for wifi in content:
			result.append(dict(ssid=wifi["ssid"], address=wifi["address"], quality=wifi["signal"], encrypted=wifi["encrypted"]))
		return result

	def _get_status(self):
		payload = dict()

		flag, content = self._send_message("status", payload)
		if not flag:
			raise RuntimeError("Error while querying status: " + content)

		return content

	def _configure_and_select_wifi(self, ssid, psk, force=False):
		runstr = "sudo changewifi \"" + ssid + "\" \"" + psk + "\""
		self._logger.info("Executing: " + runstr)
		self._exec_cmd(runstr)

	def _configure_and_select_wifi2(self, ssid, psk, force=False):
		payload = dict(
			ssid=ssid,
			psk=psk,
			force=force
		)

		flag, content = self._send_message("config_wifi", payload)
		if not flag:
			raise RuntimeError("Error while configuring wifi: " + content)

		flag, content = self._send_message("start_wifi", dict())
		if not flag:
			raise RuntimeError("Error while selecting wifi: " + content)

	def _forget_wifi(self):
		payload = dict()
		flag, content = self._send_message("forget_wifi", payload)
		if not flag:
			raise RuntimeError("Error while forgetting wifi: " + content)

	def _reset(self):
		payload = dict()
		flag, content = self._send_message("reset", payload)
		if not flag:
			raise RuntimeError("Error while factory resetting netconnectd: " + content)

	def _exec_cmd(self, cmd_line):
		self._logger.debug("Executing command: %s" % (cmd_line))
		try:
#			r = os.system(cmd_line)
#			Python 3
#			process = subprocess.run(cmd_line, check=True, stdout=subprocess.PIPE, universal_newlines=True)
#			r = process.stdout
#			Python 2
#			r = subprocess.check_output(cmd_line).decode()
			r = subprocess.check_output(cmd_line, shell=True).decode()
		except Exception as e:
			output = "Error while executing command: {}" + str(e)
			self._logger.warn(output)
			return (None,)

#		self._logger.info("Command %s returned: %s" % (cmd_line, r))
		return(r)

# TESTTEST BUGBUG HACKHACK
	def _send_message(self, message, data):
		return True, response["result abc"]


__plugin_name__ = "Network Setup"
__plugin_pythoncompat__ = ">=2.7,<4"

def __plugin_check__():
	import sys
	if sys.platform == 'linux2':
		return True

	logging.getLogger("octoprint.plugins." + __name__).warn("The netconnectd plugin only supports Linux")
	return False

def __plugin_load__():
	# since we depend on a Linux environment, we instantiate the plugin implementation here since this will only be
	# called if the OS check above was successful
	global __plugin_implementation__
	__plugin_implementation__ = NetconnectdSettingsPlugin()
	return True
