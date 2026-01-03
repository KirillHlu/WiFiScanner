#include <WiFi.h>
#include <SPI.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

const int joyX = 34;
const int joyY = 35;
const int buttonPin = 25;

struct NetworkInfo {
  String ssid;
  int rssi;
  String encryption;
  bool isDangerous;
  String threat;
  int dangerLevel;
};

NetworkInfo networks[20];
int networkCount = 0;
int position = 0;
int scrollPos = 0;
int state = 0;
bool scanning = false;
unsigned long scanTime = 0;

const char* dangerousSSIDs[] = {
  "Free_WiFi", "FreeWiFi"
};

void setup(){
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3c)){
    Serial.println("diaplay ini failed");
    while(1);
  }

  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  display.setCursor(0,0);
  display.println("WiFi Security Scan");
  display.display();
  delay(1000);

  pinMode(buttonPin, INPUT_PULLUP);
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
}

String getEncryptionType(wifi_auth_mode_t type){
  switch(type){
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA";
    case WIFI_AUTH_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA2";
    case WIFI_AUTH_WPA3_PSK: return "WPA3";
    default: return "UNKNOWN";
  }
}

void detectThreats(NetworkInfo& net, int index){
  net.dangerLevel = 0;
  net.threat = "";
  wifi_auth_mode_t encType = WiFi.encryptionType(index);
  net.encryption = getEncryptionType(encType);

  if (encType == WIFI_AUTH_OPEN) {
    net.dangerLevel = 2;
    net.threat += "OPEN NETWORK! ";
  }

  for (int i = 0; i < sizeof(dangerousSSIDs)/sizeof(dangerousSSIDs[0]); i++){
    if (net.ssid.indexOf(dangerousSSIDs[i]) >= 0){
      net.dangerLevel = 2;
      net.threat += "FAKE AP! ";
      break;
    }
  }

  for (int i = 0; i < networkCount; i++) {
    if (i != index && networks[i].ssid == net.ssid){
      net.dangerLevel = 2;
      net.threat += "EVIL TWIN ";
      break;
    }
  }

  if(encType == WIFI_AUTH_WEP){
    net.dangerLevel = max(net.dangerLevel, 1);
    net.threat += "WEP(weak) ";
  }

  if ((net.rssi < -85 || net.rssi > -40) && encType == WIFI_AUTH_OPEN){
    net.dangerLevel = max(net.dangerLevel, 1);
    net.threat += (net.rssi < -85) ? "WEAK_SIGNAL ": "TOO_STRONG ";
  }

  net.isDangerous = (net.dangerLevel > 0);
}

void scanNetworks(){
  scanning = true;
  int16_t foundNetworks = WiFi.scanNetworks(false, true);
  networkCount = (foundNetworks > 20) ? 20 : foundNetworks;

  for(int i = 0; i < networkCount; i++){
    networks[i].ssid = WiFi.SSID(i);
    networks[i].rssi = WiFi.RSSI(i);
    detectThreats(networks[i], i);
  }
  scanning = false;
  scanTime = millis();
}

String getDangerSymbol(int level){
  switch(level){
    case 0: return "[OK]";
    case 1: return "[!]";
    case 2: return "[X]";
    default: return "[?]";
  }
}

void drawMenu(){
  display.clearDisplay();
  display.setCursor(0,0);
  display.println("WiFi Security Scan");
  display.println("---------------------");

  const char* menuItems[] = {"Scan Networks", "Show Results", "Security Info"};
  for(int i = 0; i < 3; i++) {
    display.print(position == i ? "> ": " ");
    display.println(menuItems[i]);
  }

  display.println("------------");
  display.print("OK=Safe !=Warn X=Danger");
}

void drawScanning() {
  static int dots = 0;
  display.clearDisplay();
  display.setCursor(0,0);
  display.println("Scanning networks...");
  display.println("Looking for threats:");
  display.println("- Open networks");
  display.println("- Fake AP names");
  display.println("- Evil Twin attacks");
  display.println("- Weak encryption");

  display.setCursor(0, 50);
  display.print("Scanning");
  for(int i = 0; i < dots; i++) {
    display.print(".");
  }
  dots = (dots + 1) % 4;
}

void drawResults() {
  display.clearDisplay();
  display.setCursor(0,0);

  int dangerousCount = 0;
  for(int i = 0; i < networkCount; i++) {
    if(networks[i].isDangerous) dangerousCount++;
  }

  display.print("Nets: ");
  display.print(networkCount);
  display.print(" Danger:");
  display.println(dangerousCount);
  display.println("---------------");

  int startIdx = scrollPos;
  int endIdx = min(startIdx + 4, networkCount);

  for(int i = startIdx; i < endIdx; i++) {
    int linePos = 16 + (i - startIdx) * 12;
    display.setCursor(0, linePos);

    if (i == scrollPos) {
      display.setTextColor(SSD1306_BLACK, SSD1306_WHITE);
    }

    display.print(getDangerSymbol(networks[i].dangerLevel));
    display.print(" ");

    String line = networks[i].ssid.substring(0,8);
    line += " ";
    line += networks[i].rssi;
    line += "dB";
    display.println(line);

    display.setCursor(25, linePos + 8);
    display.print(networks[i].encryption);

    display.setTextColor(SSD1306_WHITE);
  }

  if (networkCount > 4) {
    display.setCursor(110, 0);
    display.print(scrollPos + 1);
    display.print("/");
    display.print(networkCount);
  }
}

void drawSecurityInfo() {
  display.clearDisplay();
  display.setCursor(0,0);
  display.println("[OK] = SAFE");
  display.println("  WPA2/WPA3 enc");
  display.println("[!] = WARNING");
  display.println("  WEP/WEAK enc");
  display.println("  Suspicious RSSI");
  display.println("[X] = DANGER");
  display.println("  Open network");
  display.println("  Fake AP name");
}

void handleInput() {
  int xVal = analogRead(joyX);
  int btn = digitalRead(buttonPin);

  if (state == 0) {
    if(xVal < 100) position = min(position + 1, 2);
    else if(xVal > 3000) position = max(position - 1, 0);
  }
  else if(state == 2) {
    if(xVal < 100) scrollPos = min(scrollPos + 1, max(0, networkCount - 4));
    else if(xVal > 3000) scrollPos = max(scrollPos - 1, 0);
  }

  if(btn == LOW) {
    if(state == 0){
      if(position == 0){
        state = 1;
        scanning = true;
      }
      else if(position == 1){
        state = 2;
        scrollPos = 0;
      }
      else if(position == 2)  state = 3;
    }
    else{
      state = 0;
    }
    delay(300);
  }
}

void loop() {
  handleInput();

  if(state == 1 && scanning) {
    scanNetworks();
  }
  if(state == 1 && millis() - scanTime > 3000) {
    state = 2;
    scrollPos =  0;
  }

  switch(state) {
    case 0: drawMenu(); break;
    case 1: drawScanning(); break;
    case 2: drawResults(); break;
    case 3: drawSecurityInfo(); break;
  }

  display.display();
  delay(100);
}
