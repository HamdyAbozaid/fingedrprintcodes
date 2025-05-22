// hi 
#include <LiquidCrystal.h>
#include <Adafruit_Fingerprint.h>
#include <HardwareSerial.h>
#include <WiFiManager.h>
#include <HTTPClient.h>

// LCD pins
const int rs = 19, en = 23, d4 = 32, d5 = 33, d6 = 25, d7 = 26;
LiquidCrystal lcd(rs, en, d4, d5, d6, d7);

// Fingerprint sensor serial
HardwareSerial mySerial(2);
Adafruit_Fingerprint finger(&mySerial);

// Button pin
const int addButtonPin = 18;
const int wifiConfigButtonPin = 27;  // غير 27 لو عايز, على حسب الزرار اللي انت عايزه يفتح الوايفاي مانيجر

struct FingerprintData {
  uint16_t id;
  String name;
};

FingerprintData fingerprints[128];
uint16_t nextID = 0;
int lastDetectedID = -1;

void setupWiFi();
void displayMainMenu();
bool addFingerprint();
void enrollWithRetry();
void getFingerName(uint16_t id);
void sendToServer(uint16_t id, String name);
void showFingerPositionGuide();
void checkSensorStatus();
void smartDelay(unsigned long ms);
void getFingerprintID();
int getFingerprintImage(const char* scanType);
int waitForFingerRemoval();
void handleImageError(int error);
void handleModelError(int error);

void setup() {
  Serial.begin(115200);
  lcd.begin(16, 2);
  lcd.print("Initializing...");
  pinMode(addButtonPin, INPUT_PULLUP);

  mySerial.begin(57600, SERIAL_8N1, 16, 17);
  finger.begin(57600);

  if (finger.verifyPassword()) {
    lcd.setCursor(0, 1);
    lcd.print("Sensor found!");
  } else {
    lcd.setCursor(0, 1);
    lcd.print("Sensor not found!");
    while (1) delay(1);
  }

  delay(1000);
  lcd.clear();

  if (WiFi.status() != WL_CONNECTED) {
  lcd.clear();
  lcd.print("No WiFi conn.");
  delay(2000);
}

  checkSensorStatus();

  nextID = finger.getTemplateCount();
  Serial.print("Next ID: ");
  Serial.println(nextID);

  displayMainMenu();
}

void loop() {
  if (digitalRead(wifiConfigButtonPin) == LOW) {
    smartDelay(50);
    if (digitalRead(wifiConfigButtonPin) == LOW) {
      setupWiFiManager();
      displayMainMenu();
    }
  }

  if (digitalRead(addButtonPin) == LOW) {
    smartDelay(50);
    if (digitalRead(addButtonPin) == LOW) {
      enrollWithRetry();
      displayMainMenu();
    }
  }

  getFingerprintID();
  delay(100);
}

void setupWiFiManager() {
  WiFiManager wm;

  lcd.clear();
  lcd.print("Starting WiFi AP");
  lcd.setCursor(0, 1);
  lcd.print("Connect to: ESP32");

  bool res = wm.autoConnect("ESP32-Setup", "12345678"); // AP SSID & Password

  lcd.clear();
  if (res) {
    lcd.print("WiFi Connected");
    delay(1500);
  } else {
    lcd.print("WiFi Failed");
    delay(3000);
  }
}


void displayMainMenu() {
  lcd.clear();
  lcd.print("Add: UP");
  lcd.setCursor(0, 1);
  lcd.print("Scan Finger...");
}

void enrollWithRetry() {
  showFingerPositionGuide();
  for (int attempt = 1; attempt <= 3; attempt++) {
    lcd.clear();
    lcd.print("Attempt " + String(attempt) + "/3");
    if (addFingerprint()) {
      lcd.clear();
      lcd.print("Success!");
      delay(2000);
      return;
    }
    delay(2000);
  }
  lcd.clear();
  lcd.print("Failed after 3 tries");
  delay(3000);
}

bool addFingerprint() {
  int p = getFingerprintImage("First scan");
  if (p != FINGERPRINT_OK) return false;

  p = finger.image2Tz(1);
  if (p != FINGERPRINT_OK) {
    handleImageError(p);
    return false;
  }

  lcd.clear();
  lcd.print("Remove finger");
  delay(2000);

  p = waitForFingerRemoval();
  if (p != FINGERPRINT_NOFINGER) return false;

  lcd.clear();
  lcd.print("Place same finger");
  delay(1000);

  p = getFingerprintImage("Second scan");
  if (p != FINGERPRINT_OK) return false;

  p = finger.image2Tz(2);
  if (p != FINGERPRINT_OK) {
    handleImageError(p);
    return false;
  }

  p = finger.createModel();
  if (p == FINGERPRINT_ENROLLMISMATCH) {
    lcd.clear();
    lcd.print("Finger mismatch");
    return false;
  } else if (p != FINGERPRINT_OK) {
    handleModelError(p);
    return false;
  }

  uint16_t id = nextID++;
  p = finger.storeModel(id);
  if (p != FINGERPRINT_OK) {
    lcd.clear();
    lcd.print("Store error: " + String(p));
    return false;
  }

  getFingerName(id);
  
  // هنا بعت البيانات للسيرفر
  sendToServer(id, fingerprints[id].name);

  return true;
}

void getFingerName(uint16_t id) {
  lcd.clear();
  lcd.print("Enter name:");
  String name = "";
  unsigned long start = millis();

  while (millis() - start < 30000) {
    while (Serial.available() > 0) {
      char c = Serial.read();
      if (c == '\n' || c == '\r') {
        if (name.length() > 0) {
          fingerprints[id].id = id;
          fingerprints[id].name = name;
          return;
        }
      } else {
        name += c;
      }
    }
    delay(50);
  }

  fingerprints[id].id = id;
  fingerprints[id].name = "User_" + String(id);
}

void sendToServer(uint16_t id, String name) {
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    String url = "http://192.168.1.40:7069/api/SensorData";  // غير هنا إلى IP وبورت السيرفر عندك
    String payload = "{\"id\":" + String(id) + ",\"name\":\"" + name + "\"}";

    http.begin(url);
    http.addHeader("Content-Type", "application/json");

    Serial.println("POST URL: " + url);
    Serial.println("Payload: " + payload);

    int httpCode = http.POST(payload);
    String response = http.getString();

    Serial.println("HTTP Code: " + String(httpCode));
    Serial.println("Response: " + response);

    lcd.clear();
    if (httpCode > 0) {
      lcd.print("Sent to server");
    } else {
      lcd.print("Send failed");
    }
    delay(2000);

    http.end();
  } else {
    Serial.println("WiFi not connected");
    lcd.clear();
    lcd.print("WiFi not connected");
    delay(2000);
  }
}

int getFingerprintImage(const char* scanType) {
  int p = -1;
  unsigned long start = millis();
  while (p != FINGERPRINT_OK && millis() - start < 10000) {
    p = finger.getImage();
    if (p == FINGERPRINT_OK) return p;
    else if (p != FINGERPRINT_NOFINGER) {
      handleImageError(p);
      return p;
    }
    delay(100);
  }
  return FINGERPRINT_IMAGEFAIL;
}

int waitForFingerRemoval() {
  int p = 0;
  unsigned long start = millis();
  while (p != FINGERPRINT_NOFINGER && millis() - start < 5000) {
    p = finger.getImage();
    delay(100);
  }
  return p;
}

void handleImageError(int error) {
  lcd.clear();
  lcd.print("Scan error:");
  lcd.setCursor(0, 1);
  switch (error) {
    case FINGERPRINT_IMAGEFAIL: lcd.print("Poor image"); break;
    case FINGERPRINT_PACKETRECIEVEERR: lcd.print("Comm error"); break;
    default: lcd.print("Code: " + String(error));
  }
  delay(2000);
}

void handleModelError(int error) {
  lcd.clear();
  lcd.print("Model error:");
  lcd.setCursor(0, 1);
  switch (error) {
    case FINGERPRINT_ENROLLMISMATCH: lcd.print("Mismatch"); break;
    default: lcd.print("Code: " + String(error));
  }
  delay(2000);
}

void showFingerPositionGuide() {
  lcd.clear();
  lcd.print("Place flat");
  lcd.setCursor(0, 1);
  lcd.print("& center finger");
  delay(2000);
}

void checkSensorStatus() {
  lcd.clear();
  lcd.print("Checking sensor...");
  int p = finger.getImage();
  lcd.clear();
  lcd.print("Sensor status:");
  lcd.setCursor(0, 1);
  lcd.print((p == FINGERPRINT_OK) ? "Working fine" : "Problem");
  delay(2000);
  // لا تمسح قاعدة البيانات هنا للحفاظ على البيانات
}

void smartDelay(unsigned long ms) {
  unsigned long start = millis();
  while (millis() - start < ms) {
    delay(50);
  }
}

void getFingerprintID() {
  int p = finger.getImage();
  if (p != FINGERPRINT_OK) return;

  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) return;

  p = finger.fingerSearch();
  if (p == FINGERPRINT_OK) {
    lcd.clear();
    lcd.print("Detected ID:");
    lcd.setCursor(0, 1);
    lcd.print(finger.fingerID);
    delay(2000);  // خليها تظهر شوية
  } else {
    lcd.clear();
    lcd.print("No Match");
    delay(1000);
  }
  displayMainMenu();
}


