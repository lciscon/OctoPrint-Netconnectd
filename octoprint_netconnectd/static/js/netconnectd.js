$(function() {
    function NetconnectdViewModel(parameters) {
        var self = this;

        self.loginState = parameters[0];
        self.settingsViewModel = parameters[1];

        self.pollingEnabled = false;
        self.pollingTimeoutId = undefined;

        self.reconnectInProgress = false;
        self.reconnectTimeout = undefined;

        self.enableQualitySorting = ko.observable(false);

        self.hostname = ko.observable();

        self.status = {
            link: ko.observable(),
            connections: {
                ap: ko.observable(),
                wifi: ko.observable(),
                wired: ko.observable()
            },
            wifi: {
                current_ssid: ko.observable(),
                current_address: ko.observable(),
                present: ko.observable()
            },
			wired: {
                current_address: ko.observable(),
                present: ko.observable()
            }
        };
        self.statusCurrentWifi = ko.observable();

        self.editorWifi = undefined;
        self.editorWifiSsid = ko.observable();
        self.editorWifiPassphrase1 = ko.observable();
        self.editorWifiPassphrase2 = ko.observable();
        self.editorWifiPassphraseMismatch = ko.computed(function() {
            return self.editorWifiPassphrase1() != self.editorWifiPassphrase2();
        });

        self.working = ko.observable(false);
        self.error = ko.observable(false);

        self.connectionStateText = ko.computed(function() {
            var text;

            if (self.error()) {
                text = gettext("Error while talking to netconnectd, is the service running?");
            } else if (self.status.connections.ap()) {
                text = gettext("Acting as access point");
            } else if (self.status.link()) {
                if (self.status.connections.wired()) {
                    text = gettext("Connected via wire");
                } else if (self.status.connections.wifi()) {
                    if (self.status.wifi.current_ssid()) {
                        text = _.sprintf(gettext("Connected via wifi (SSID \"%(ssid)s\")"), {ssid: self.status.wifi.current_ssid()});
                    } else {
                        text = gettext("Connected via wifi (unknown SSID)")
                    }
                } else {
                    text = gettext("Connected (unknown connection)");
                }
            } else {
                text = gettext("Not connected to network ");
            }

            if (!self.status.wifi.present()) {
                text += ", " + gettext("no wifi interface present")
            }

            return text;
        });

        // initialize list helper
        self.listHelper = new ItemListHelper(
            "wifis",
            {
                "ssid": function (a, b) {
					if (a["ssid"] && b["ssid"]) {
                    	// sorts ascending
                    	if (a["ssid"].toLocaleLowerCase() < b["ssid"].toLocaleLowerCase()) return -1;
                    	if (a["ssid"].toLocaleLowerCase() > b["ssid"].toLocaleLowerCase()) return 1;
					}
                    return 0;
                },
                "quality": function (a, b) {
                    // sorts descending
					if (a["quality"] && b["quality"]) {
                    	if (a["quality"] > b["quality"]) return -1;
                    	if (a["quality"] < b["quality"]) return 1;
					}
                    return 0;
                }
            },
            {
            },
            "quality",
            [],
            [],
            10
        );

        self.getEntryId = function(data) {
            return "settings_plugin_netconnectd_wifi_" + md5(data.ssid);
        };

        self.refresh = function() {
//            self.requestData();
			self.sendWifiRefresh();
			self.sendHostnameRefresh();
			self.sendSSIDRefresh();
			self.sendAddressRefresh();
			self.sendAddress2Refresh();
        };

        self.fromResponse = function (response) {
            if (response.error !== undefined) {
				self.error(false);
//				self.error(true);  BUGBUG HACKHACK FIXFIX
                return;
            } else {
                self.error(false);
            }

			if (response.hostname)
            	self.hostname(response.hostname);

			if (response.status) {
//				if response.status.link
//	              self.status.link(response.status.link);
//				if response.status.connections
//  	          self.status.connections.ap(response.status.connections.ap);
//      	      self.status.connections.wifi(response.status.connections.wifi);
//          	  self.status.connections.wired(response.status.connections.wired);
				if (response.status.wifi) {
		            self.status.wifi.current_ssid(response.status.wifi.current_ssid);
		            self.status.wifi.current_address(response.status.wifi.current_address);
		            self.status.wifi.present(response.status.wifi.present);

		            self.statusCurrentWifi(undefined);
		            if (response.status.wifi.current_ssid && response.status.wifi.current_address) {
		                _.each(response.wifis, function(wifi) {
		                    if (wifi.current_ssid == response.status.wifi.current_ssid && wifi.current_address.toLowerCase() == response.status.wifi.current_address.toLowerCase()) {
		                        self.statusCurrentWifi(self.getEntryId(wifi));
		                    }
		                });
		            }
				}
			}

			if (response.wifis) {
	            var enableQualitySorting = false;
	            _.each(response.wifis, function(wifi) {
	                if (wifi.quality != undefined) {
	                    enableQualitySorting = true;
	                }
	            });
	            self.enableQualitySorting(enableQualitySorting);

	            var wifis = [];
	            _.each(response.wifis, function(wifi) {
	                var qualityInt = parseInt(wifi.quality);
	                var quality = undefined;
	                if (!isNaN(qualityInt)) {
	                    quality = qualityInt;
	                }

	                wifis.push({
	                    ssid: wifi.ssid,
	                    address: wifi.address,
	                    encrypted: wifi.encrypted,
	                    quality: quality,
	                    qualityText: (quality != undefined) ? "" + quality + " dBm" : undefined
	                });
	            });

	            self.listHelper.updateItems(wifis);
	            if (!enableQualitySorting) {
	                self.listHelper.changeSorting("ssid");
	            }

	            if (self.pollingEnabled) {
	                self.pollingTimeoutId = setTimeout(function() {
	                    self.requestData();
	                }, 30000)
	            }
			}
        };

        self.configureWifi = function(data) {
            if (!self.loginState.isAdmin()) return;

            self.editorWifi = data;
            self.editorWifiSsid(data.ssid);
            self.editorWifiPassphrase1(undefined);
            self.editorWifiPassphrase2(undefined);
            if (data.encrypted) {
                $("#settings_plugin_netconnectd_wificonfig").modal("show");
            } else {
                self.confirmWifiConfiguration();
            }
        };

        self.confirmWifiConfiguration = function() {
            self.sendWifiConfig(self.editorWifiSsid(), self.editorWifiPassphrase1(), function() {
                self.editorWifi = undefined;
                self.editorWifiSsid(undefined);
                self.editorWifiPassphrase1(undefined);
                self.editorWifiPassphrase2(undefined);
                $("#settings_plugin_netconnectd_wificonfig").modal("hide");
            });
        };

		self.reset = function() {
			self.refresh();
		};

		self.save = function() {
				self.saveHostname();
		};

		self.saveButtonEnabled = function() {
				return true;
		};

		self.resetButtonEnabled = function() {
				return true;
		};

		self.sendHostnameRefresh = function(force) {
			if (force === undefined) force = false;
            self._postCommand("get_hostname", {force: force}, function(response) {
				self.hostname(response.hostname);
            });
        };

		self.sendSSIDRefresh = function(force) {
			if (force === undefined) force = false;
            self._postCommand("get_ssid", {force: force}, function(response) {
				self.status.wifi.current_ssid(response.ssid);
            });
        };

		self.sendAddressRefresh = function(force) {
			if (force === undefined) force = false;
            self._postCommand("get_address", {force: force}, function(response) {
				self.status.wifi.current_address(response.address);
            });
        };

		self.sendAddress2Refresh = function(force) {
			if (force === undefined) force = false;
            self._postCommand("get_address2", {force: force}, function(response) {
				self.status.wired.current_address(response.address);
            });
        };

		self.saveHostname = function() {
			self._postCommand("set_hostname", {newname: self.hostname()});
		};

        self.sendWifiRefresh = function(force) {
            if (force === undefined) force = false;
            self._postCommand("list_wifi", {force: force}, function(response) {
                self.fromResponse({"wifis": response});
            });
        };

        self.sendWifiConfig = function(ssid, psk, successCallback, failureCallback) {
            if (!self.loginState.isAdmin()) return;

			self.status.wifi.current_ssid(ssid);
			self.status.wifi.current_address("");
			self.status.wired.current_address("");

            self.working(true);
            self._postCommand("configure_wifi", {ssid: ssid, psk: psk}, successCallback, failureCallback, function() {
                self.working(false);
                if (self.reconnectInProgress) {
//                    self.tryReconnect();
                }
            }, 5000);
        };

/*
		self.sendWifiConfig2 = function(ssid, psk, successCallback, failureCallback) {
            if (!self.loginState.isAdmin()) return;

            self.working(true);
            if (self.status.connections.ap()) {
                self.reconnectInProgress = true;

                var reconnectText = gettext("OctoPrint is now switching to your configured Wifi connection and therefore shutting down the Access Point. I'm continuously trying to reach it at <strong>%(hostname)s</strong> but it might take a while. If you are not reconnected over the next couple of minutes, please try to reconnect to OctoPrint manually because then I was unable to find it myself.");

                showOfflineOverlay(
                    gettext("Reconnecting..."),
                    _.sprintf(reconnectText, {hostname: self.hostname()}),
//                    self.tryReconnect
                );
            }
            self._postCommand("configure_wifi", {ssid: ssid, psk: psk}, successCallback, failureCallback, function() {
                self.working(false);
                if (self.reconnectInProgress) {
//                    self.tryReconnect();
                }
            }, 5000);
        };

        self.sendReset = function() {
            if (!self.loginState.isAdmin()) return;

            self._postCommand("reset", {});
        };


        self.sendForgetWifi = function() {
            if (!self.loginState.isAdmin()) return;
            self._postCommand("forget_wifi", {});
        };
*/

        self._postCommand = function (command, data, successCallback, failureCallback, alwaysCallback, timeout) {
            var payload = _.extend(data, {command: command});

            var params = {
                url: API_BASEURL + "plugin/netconnectd",
                type: "POST",
                dataType: "json",
                data: JSON.stringify(payload),
                contentType: "application/json; charset=UTF-8",
                success: function(response) {
                    if (successCallback) successCallback(response);
                },
                error: function() {
                    if (failureCallback) failureCallback();
                },
                complete: function() {
                    if (alwaysCallback) alwaysCallback();
                }
            };

            if (timeout != undefined) {
                params.timeout = timeout;
            }

            $.ajax(params);
        };

        self.requestData = function () {
            if (self.pollingTimeoutId != undefined) {
                clearTimeout(self.pollingTimeoutId);
                self.pollingTimeoutId = undefined;
            }

            $.ajax({
                url: API_BASEURL + "plugin/netconnectd",
                type: "GET",
                dataType: "json",
                success: self.fromResponse
            });
        };

        self.onUserLoggedIn = function(user) {
            if (user.admin) {
                self.requestData();
            }
        };

        self.onBeforeBinding = function() {
            self.settings = self.settingsViewModel.settings;
        };

		self.onStartup = function() {
			self.pollingEnabled = true;
			self.refresh();
		};

        self.onSettingsShown = function() {
            self.pollingEnabled = true;
            self.requestData();
        };

        self.onSettingsHidden = function() {
            if (self.pollingTimeoutId != undefined) {
                self.pollingTimeoutId = undefined;
            }
            self.pollingEnabled = false;
        };

        self.onServerDisconnect = function() {
            return !self.reconnectInProgress;
        }

    }

    // view model class, parameters for constructor, container to bind to
    ADDITIONAL_VIEWMODELS.push([NetconnectdViewModel, ["loginStateViewModel", "settingsViewModel"], "#tab_plugin_netconnectd"]);
});
