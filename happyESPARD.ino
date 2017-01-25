
#include <ESP8266WiFi.h>
#include <ESP8266mDNS.h>
#include <ESP8266TrueRandom.h>
#include <Crypto.h>
#include <SHA512.h>

const char* ssid     = "guest@fitzsimons.org";
const char* password = "NewZealand";
char hostString[16] = {0};

#define PORT 14000
#define NAME "Franks Light Bulb"
#define TYPE ACCESSORY_TYPE_LIGHTBULB
#define VER "1.0"
#define PASSWORD "11223344"

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

typedef struct {
  uint8_t tag;
  uint8_t len;
  uint8_t *val;
} tlv_t;

typedef struct {
  uint8_t count;
  tlv_t *tlv;
} message_t;

#define MAXTAGS 30
message_t inmsg, outmsg;

const byte srp_username[] = "Pair-Setup";
// RFC and Apple-approved 3072bit prime
const byte modulus[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F, 0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B, 0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10, 0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7, 0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C, 0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31, 0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x3A, 0xD2, 0xCA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const byte modulus_generator[] = { 5 };
byte salt[16];
byte b[32];


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

  inmsg.tlv = (tlv_t*)malloc(sizeof(tlv_t) * MAXTAGS);
  outmsg.tlv = (tlv_t*)malloc(sizeof(tlv_t) * MAXTAGS);

  ESP8266TrueRandom.memfill((char *)salt, sizeof(salt));
  ESP8266TrueRandom.memfill((char *)b, sizeof(b));
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
    yield();
    delay(1);
  }

  //  Serial.printf("Got %d bytes\n", client.getSize());
  String req = getHTTPRequest(client);
  if (req.indexOf("/pair-setup") > 0) {
    handlePairing(client);
  }

  Serial.println("Client disconnected");
}

String getHTTPRequest(WiFiClient client) {
  bool first = true;
  String req, line;
  byte temp[5], count;
  delay(1); // TODO: TIMING HACK.
  do {
    if (!client.connected()) {
      Serial.println("Disconnected...");
      return req;
    }

    if (client.available() < 2) {
      if (client.available() > 0) {
        Serial.print(client.available());
        Serial.println(" bytes available. Waiting for more data....1s");
      }
      delay(5);
      continue;
    }
    Serial.print(client.available());
    /*   count = client.peekBytes(temp, sizeof(temp));
       Serial.print("PEEK:");
       Serial.println(count);
       int i;
       for(i=0;i<count;i++) {
         Serial.printf("0x%02x ", temp[i]);
       } */
    Serial.println(".");

    line = client.readStringUntil('\r');

    //Serial.print("Read len:");
    //Serial.println(line.length());
    //Serial.println("LINE:" + line);

    client.readStringUntil('\n'); // flush the newline
    if (first) {
      req = line;
      first = false;
    } else {
      Serial.println(line);
    }

    if (line.length() == 0) {
      break;
    }
  } while (1);

  Serial.println("REQ:" + req);
  return req;
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

#define PAIRSTEP_WAITING 0
#define PAIRSTEP_STARTREQ 1
#define PAIRSTEP_STARTRES 2
#define PAIRSTEP_VERIFYREQ 3
#define PAIRSTEP_VERIFYRES 4
#define PAIRSTEP_EXCHREQ 5
#define PAIRSTEP_EXCHRES 6

#define TLV_TAG_PAIRINGMETHOD 0x00
#define TLV_TAG_SALT 0x02 // 16 bytes
#define TLV_TAG_PUBKEY 0x03 // 384 for SRP, 32 for ED
#define TLV_TAG_PROOF 0x04 // 64 bytes
#define TLV_TAG_ENCRYPTEDDATA 0x05
#define TLV_TAG_PAIRSEQUENCE 0x06
#define TLV_TAG_SIGNATURE 0x0A // 64 bytes
#define TLV_TAG_ERRCODE 0x07


void handlePairing(WiFiClient client) {
  Serial.println("");
  Serial.println("New client - pair-setup");

  byte buf[1024];
  int res = 0;

  while (1) {
    yield();
    res = client.read(buf, 1024);
    int i;
    Serial.printf("Got %d bytes\n", res);

    client.flush();

    if (res > 0) {
      for (i = 0; i < res; i++) {
        Serial.printf("0x%02x ", buf[i]);
      }
    } else {
      Serial.println("Nothing received, exiting pairing");
      return;
    }

    message_t *msg = decode(buf, res);
    printDecodedTLV8(msg);
    Serial.printf("Pairing stage %d\n", getPairingStage(msg));
    switch (getPairingStage(msg)) {
      case PAIRSTEP_STARTREQ:
        handlePairingStart(client, msg);
        break;
      case PAIRSTEP_VERIFYREQ:
        handlePairingVerify(client, msg);
        break;
      default:
        Serial.println("****Pairing stopped");
        return;
    }

    Serial.println("Waiting for more data");
    delay(5); // TODO: Replace this hack

    if (!client.connected()) {

      Serial.println("Client disconnected unexpectedly");
      return;
    }

    String req = getHTTPRequest(client);
    if (req.indexOf("/pair-setup") <= 0) {
      Serial.println("Unexpected request - pairing failed: " + req);
      return;
    }

  }
}
void handlePairingStart(WiFiClient client, message_t *msg) {
  Serial.println("handlerPairingStart...");
 
  byte hdr[] = "HTTP/1.1 200 OK\r\nContent-Type: application/pairing+tlv8\r\nContent-Length: 409\r\n\r\n";

  byte *finalbuf = (byte *)malloc(1024);

  byte step = PAIRSTEP_STARTRES;
  addTLV8Val(&outmsg, TLV_TAG_PAIRSEQUENCE, 1, &step);
  addTLV8Val(&outmsg, TLV_TAG_SALT, 16, salt);
  addTLV8Val(&outmsg, TLV_TAG_PUBKEY, 384, (byte *)modulus); // TODO change to B

  memcpy(finalbuf, hdr, sizeof(hdr));
  int finalsize = 1024 - (sizeof(hdr) - 1);
  encode(&outmsg, finalbuf + (sizeof(hdr) - 1), &finalsize);

  //  memcpy(finalbuf + sizeof(hdr) - 1, buf2, sizeof(buf2));

  client.write(&finalbuf[0], finalsize + (sizeof(hdr) - 1));
  free(finalbuf);
  Serial.println("...handlePairingStart");
}

void handlePairingVerify(WiFiClient client, message_t *msg) {
  Serial.println("handlerPairingVerify");

  Serial.println("...handlerPairingVerify...");
}


message_t *decode(byte * tlv8, int len) {
  int i = 0;
  byte *start = tlv8;
  while (1) {
    inmsg.tlv[i].tag = *tlv8++;
    inmsg.tlv[i].len = *tlv8++;
    inmsg.tlv[i].val = tlv8;
    tlv8 += inmsg.tlv[i].len;
    if (tlv8 - start >= len) {
      break;
    }
    i++;
  }
  inmsg.count = i;
  return &inmsg;
}

byte getPairingStage(message_t *msg) {
  int i;
  for (i = 0; i <= msg->count; i++) {
    if (msg->tlv[i].tag == TLV_TAG_PAIRSEQUENCE) {
      return *(msg->tlv[i].val);
    }
  }
}

void printDecodedTLV8(message_t *msg) {
  Serial.printf("Message has %d tags\n", msg->count + 1);
  for (int i = 0; i <= msg->count; i++) {
    Serial.printf("Tag:0x%02x, len %d\n", msg->tlv[i].tag, msg->tlv[i].len);
  }
}

byte *encode(message_t *msg, byte *buf, int *size) {
  Serial.println("encode...");
  byte i;
  int bpos, bufsize = *size;
  bpos = 0;
  for (i = 0; i < msg->count; i++) {
    if (bpos + msg->tlv[i].len > bufsize) {
      Serial.printf("Reallocating to size %d\n", bufsize + 512);
      buf = (byte *)realloc((void *)buf, bufsize + 512);
      if (buf == NULL) {
        Serial.println("Failed to reallocate memory, stopping");
        delay(1);
        ESP.restart();
      }
      bufsize += 512;
    }
    buf[bpos] = msg->tlv[i].tag;
    bpos++;
    buf[bpos] = msg->tlv[i].len;
    bpos++;
    memcpy((void *)(buf + bpos), msg->tlv[i].val, msg->tlv[i].len);
    bpos += msg->tlv[i].len;
  }
  *size = bpos;
  Serial.printf("...encode. Final size %d\n", bpos);
  return buf;
}

bool addTLV8Val(message_t *msg, byte tag, int len, byte *buf) {
  Serial.printf("addTLV8Val...%d:%d", tag, len);
  int templen = len;
  while (templen > 0) {
    msg->tlv[msg->count].tag = tag;
    msg->tlv[msg->count].val = buf;
    if (templen > 255) {
      msg->tlv[msg->count].len = 255;
      buf += 255;
      templen -= 255;
    } else {
      msg->tlv[msg->count].len = (byte)templen;
      templen = 0;
    }
    msg->count++;
  }
  Serial.printf("...addTLV8Val. %d TLVs\n", msg->count);
  return false;
}

// k is SHA512(N, g) e.g. SHA512(modulus, modulus_generator) for SRP6a/Homekit
void gen_k(byte *k) {
//  byte k[64];
  SHA512 sha512;
  sha512.reset();
  sha512.update(modulus, sizeof(modulus));
  sha512.update(modulus_generator, sizeof(modulus_generator));
  sha512.finalize(k, sizeof(&k));
}

void gen_B(byte *B) {
 // int slen = (SRP_get_secret_bits(BigIntegerBitLen(srp->modulus)) + 7) / 8;

  /* B = kv + g^b mod n (blinding) */
/*  BigIntegerMul(srp->pubkey, k, srp->verifier, srp->bctx);
  BigIntegerModExp(k, srp->generator, srp->secret, srp->modulus, srp->bctx, srp->accel);
  BigIntegerAdd(k, k, srp->pubkey);
  BigIntegerMod(srp->pubkey, k, srp->modulus, srp->bctx);

    // B = kv + g^b (mod N) 
      var bb = g.ModPow(b, N);
      var kv = v.Multiply(k);
      var B = (kv.Add(bb)).Mod(N);
*/
}

// HomeKit SRP validator -- SHA512(salt[16] || SHA512(username || ":" || password))
void gen_validator(byte *hash, byte *salt, char *username, char *password) { 

  SHA512 sha512;
  sha512.reset();
  sha512.update(username, strlen(username));
  sha512.update(":", 1);
  sha512.update(password, strlen(password));
  sha512.finalize(hash, sizeof(hash));

  sha512.reset();
  sha512.update(salt, 16);
  sha512.update(hash, sizeof(hash));
  sha512.finalize(hash, sizeof(hash));
  
}
  




