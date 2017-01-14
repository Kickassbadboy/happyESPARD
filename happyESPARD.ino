#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>
#include <WiFiClient.h>

const char* ssid     = "***REMOVED***";
const char* password = "***REMOVED***";
char hostString[16] = {0};

#define PORT 14000
#define NAME "Franks Light Bulb"
#define TYPE ACCESSORY_TYPE_LIGHTBULB
#define VER "1.0"

WiFiServer server(PORT);

#define ACCESSORY_TYPE_UNKNOWN             "0"
#define ACCESSORY_TYPE_OTHER               "1"
#define ACCESSORY_TYPE_BRIDGE              "2"
#define ACCESSORY_TYPE_FAN                 "3"
#define ACCESSORY_TYPE_GARAGEDOOROPENER    "4"
#define ACCESSORY_TYPE_LIGHTBULB           "5"
#define ACCESSORY_TYPE_DOORLOCK            "6"
#define ACCESSORY_TYPE_OUTLET              "7"
#define ACCESSORY_TYPE_SWITCH              "8"
#define ACCESSORY_TYPE_THERMOSTAT          "9"
#define ACCESSORY_TYPE_SENSOR              "10"
#define ACCESSORY_TYPE_ALARMSYSTEM         "11"
#define ACCESSORY_TYPE_DOOR                "12"
#define ACCESSORY_TYPE_WINDOW              "13"
#define ACCESSORY_TYPE_WINDOWCOVERING      "14"
#define ACCESSORY_TYPE_PROGRAMMABLESWITCH  "15"
#define ACCESSORY_TYPE_IPCAMERA            "17"



void setup() {
  Serial.begin(115200);
  delay(100);
  Serial.println("\r\nsetup()");

  sprintf(hostString, "ESP_%06X", ESP.getChipId());
  Serial.print("Hostname: ");
  Serial.println(hostString);
  WiFi.hostname(hostString);

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(250);
    Serial.print(".");
  }
  Serial.println("");
  Serial.print("Connected to ");
  Serial.println(ssid);
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

  if (!MDNS.begin(hostString)) {
    Serial.println("Error setting up MDNS responder!");
  }
  Serial.println("mDNS responder started");

  String mac = WiFi.macAddress();
  Serial.println("mac address is: " + mac);

  setMDNS(PORT, NAME, mac.c_str(), TYPE, VER, "1");

  // Start TCP (HTTP) server
  server.begin();
  Serial.println("TCP server started");

}

void loop() {
  // Check if a client has connected
  WiFiClient client = server.available();
  if (!client) {
    return;
  }
  Serial.println("");
  Serial.println("New client");

  // Wait for data from client to become available
  while (client.connected() && !client.available()) {
    delay(1);
  }

  while (client.available()) {
    String line = client.readStringUntil('\r');
    Serial.print(line);
  }
  client.flush();
  String s = "HTTP/1.1 200 Ok\r\n\r\n";
  client.print(s);
}

void setMDNS(int port, const char *devname, const char *mac, const char *acctype, const char *ver, const char *configver) {

  String DNSname = devname;
  DNSname.replace(" ", "_");

  MDNS.setInstanceName(DNSname.c_str());
  MDNS.addService("hap", "tcp", port);
  MDNS.addServiceTxt("hap", "tcp", "pv", ver);
  MDNS.addServiceTxt("hap", "tcp", "id", mac);
  MDNS.addServiceTxt("hap", "tcp", "c#", configver);
  MDNS.addServiceTxt("hap", "tcp", "s#", "1");
  MDNS.addServiceTxt("hap", "tcp", "ff", "0");
  MDNS.addServiceTxt("hap", "tcp", "sf", "1");
  MDNS.addServiceTxt("hap", "tcp", "md", devname);
  MDNS.addServiceTxt("hap", "tcp", "ci", acctype);

}


