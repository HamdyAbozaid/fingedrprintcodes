#include <WiFiManager.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <Adafruit_Fingerprint.h>
#include <Bounce2.h>
#include <ArduinoOTA.h>
#include <SPIFFS.h>
#include <LiquidCrystal.h>
#include <esp_sleep.h>
#include <driver/rtc_io.h>
#include <WiFiClientSecure.h>
#include <Update.h>
#include <mbedtls/md.h>
#include <ArduinoJson.h>
#include <time.h>
#include <sntp.h>

// --- Forward Declarations ---
// These declarations tell the compiler about functions defined later in the code.
// This is crucial in Arduino sketches where setup() and loop() might call functions
// that haven't been fully defined yet.
void setupOTA();
void checkForUpdates();
void processUpdateResponse(String payload);
void startDownloadWithVerification();
void enterRecoveryMode();
void displayOTAProgress(size_t progress, size_t total, const char* label);
void handleOTAError(ota_error_t error);
bool confirmUpdate(String newVersion, int firmwareSize);
void startSecureRecoveryUpdate(String updateInfo);
void initSystem();
bool isBatterySufficient();
String getDeviceID();
float getBatteryLevel();
bool autoConnectWiFi();
void startWiFiManager(bool forceConfig);
void verifyFingerprint();
void enterDeepSleep();
void powerDownPeripherals();
void manageLCDPower();
void recordLCDActivity();
void showFingerprintPrompt();
void showAttendanceResult(bool success, int userId);
void showOfflineWarning();
void logAttendanceOffline(int userId, const char* timestamp);
void syncOfflineLogs();
void timeSyncNotificationCallback(struct timeval *tv);
void setupNTP();
String getTimestamp();
bool sendToBackend(int userId, String timestamp);
// --- End Forward Declarations ---


// Hardware Pins
#define BUTTON_PIN 0
#define SENSOR_PWR_PIN 4
#define LCD_BACKLIGHT_PIN 27
#define BATTERY_PIN 35
const int rs = 19, en = 23, d4 = 32, d5 = 33, d6 = 25, d7 = 26;

// OTA Configuration
#define OTA_PASSWORD "f1ng3rpr1nt$ecure"
#define OTA_PORT 3232
#define FIRMWARE_VERSION "1.2.0"
#define PUBLIC_KEY "-----BEGIN PUBLIC KEY-----\nYOUR_PUBLIC_KEY_HERE\n-----END PUBLIC KEY-----" // Unused if not implementing full signature verification
#define BATTERY_MIN_VOLTAGE 3.6
#define UPDATE_CHECK_INTERVAL 21600000 // 6 hours (6 * 60 * 60 * 1000 ms)

// LCD Instance
LiquidCrystal lcd(rs, en, d4, d5, d6, d7);

// Fingerprint Sensor
HardwareSerial mySerial(2); // Using UART2 on pins 16 (RX) and 17 (TX)
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&mySerial);

// Power Management
RTC_DATA_ATTR int bootCount = 0; // Persists across deep sleeps
bool isOffline = false; // Flag to indicate if device is operating offline
unsigned long lastActivity = 0; // Tracks last user/system activity for LCD backlight
const unsigned long INACTIVITY_TIMEOUT = 30000; // 30 seconds LCD timeout
unsigned long lastSyncAttempt = 0; // Tracks last attempt to sync offline logs

// OTA Status tracking
enum OTAState { OTA_IDLE, OTA_DOWNLOADING, OTA_VERIFYING, OTA_UPDATING };
OTAState otaState = OTA_IDLE;
unsigned long otaStartTime = 0;
String pendingFirmwareURL = "";
String expectedHash = ""; // Expected SHA256 hash for firmware integrity

// Bounce for button debounce
Bounce debouncer = Bounce();

// Backend Configuration
const char* BACKEND_ATTENDANCE_URL = "https://your_backend_domain:port/api/attendance";
const char* BACKEND_UPDATE_URL = "https://your_backend_domain:port/api/check-update";

// NTP Configuration
const char* NTP_SERVER1 = "pool.ntp.org";
const char* NTP_SERVER2 = "time.nist.gov";
const long GMT_OFFSET_SEC = 2 * 3600; // Egypt is GMT+2
const int DAYLIGHT_OFFSET_SEC = 0; // No daylight saving currently in Egypt

// Root CA Certificate
// IMPORTANT: Replace this with the actual Root CA Certificate from your backend server.
// Without this, your HTTPS connections are insecure.
const char* ROOT_CA_CERTIFICATE = R"EOF(
-----BEGIN CERTIFICATE-----
MIIFazCCA3OgAwIBAgIRAIIQz7svqnVUchfG6iPWCmYwDQYJKoZIhvcNAQELBQAw
// This is an example, you MUST replace this with your actual cert content.
// It will be a long string of base64 encoded characters.
// For example, if using Let's Encrypt, you'd put the ISRG Root X1 certificate here.
-----END CERTIFICATE-----
)EOF";

void setup() {
  Serial.begin(115200);

  // Initialize hardware pins
  pinMode(SENSOR_PWR_PIN, OUTPUT);
  digitalWrite(SENSOR_PWR_PIN, HIGH); // Ensure sensor is powered
  pinMode(LCD_BACKLIGHT_PIN, OUTPUT);
  digitalWrite(LCD_BACKLIGHT_PIN, HIGH); // Turn on LCD backlight initially
  pinMode(BATTERY_PIN, INPUT); // Configure battery monitoring pin

  // Initialize LCD
  lcd.begin(16, 2); // Set up 16x2 LCD
  lcd.print("System Booting");

  // Button setup with debouncing
  pinMode(BUTTON_PIN, INPUT_PULLUP); // Button connected to GND, so use PULLUP
  debouncer.attach(BUTTON_PIN);
  debouncer.interval(25); // Debounce delay

  // Check for recovery mode (button held down during boot)
  if (digitalRead(BUTTON_PIN) == LOW) {
    enterRecoveryMode(); // This is a blocking function
  }

  // Initialize SPIFFS (flash file system)
  if (!SPIFFS.begin(true)) { // `true` formats SPIFFS if it fails to mount
    Serial.println("SPIFFS mount failed! Please reboot or check flash.");
    lcd.clear();
    lcd.print("Storage Error!");
    delay(2000);
    while(1); // Halt if SPIFFS is critical and failed
  }
  Serial.println("SPIFFS mounted successfully.");

  // Initialize fingerprint sensor
  mySerial.begin(57600, SERIAL_8N1, 16, 17); // Start UART2
  if (!finger.begin(57600)) { // Pass baud rate to sensor
    Serial.println("Did not find fingerprint sensor :(");
    lcd.clear();
    lcd.print("Sensor Error!");
    while(1); // Halt if sensor fails to initialize
  }
  Serial.println("Found fingerprint sensor!");
  finger.setSecurityLevel(FINGERPRINT_SECURITY_LOW); // Adjust as needed

  // Configure wake sources for deep sleep
  // Wake up on external signal from GPIO_NUM_0 (BUTTON_PIN) when it goes LOW
  esp_sleep_enable_ext0_wakeup(GPIO_NUM_0, LOW);

  // Determine the cause of wakeup
  esp_sleep_wakeup_cause_t wakeup_reason = esp_sleep_get_wakeup_cause();
  if (wakeup_reason == ESP_SLEEP_WAKEUP_UNDEFINED || wakeup_reason == ESP_SLEEP_WAKEUP_EXT0) {
    // This is a fresh boot or wake from button press
    bootCount++; // Increment boot counter (persists in RTC memory)
    Serial.printf("Boot count: %d\n", bootCount);
    initSystem(); // Initialize WiFi, NTP, OTA services
  } else {
    // Woke up by other means (e.g., timer, touch - if configured)
    Serial.printf("Wakeup cause: %d. Entering deep sleep.\n", wakeup_reason);
    enterDeepSleep(); // Go back to sleep if not a normal wakeup cause
  }
}

void loop() {
  ArduinoOTA.handle(); // Service local OTA updates
  debouncer.update(); // Update button state for debouncing
  manageLCDPower(); // Control LCD backlight based on activity

  // If an OTA download is in progress, pause other operations
  if (otaState == OTA_DOWNLOADING) {
    return; // Yield to startDownloadWithVerification()
  }

  // Check for button press: 3-second hold to force WiFi Manager config portal
  if (debouncer.fell() && debouncer.currentDuration() >= 3000) {
    Serial.println("Button held for 3s. Forcing WiFiManager configuration.");
    startWiFiManager(true); // Force config mode
    recordLCDActivity(); // Keep LCD on
  } else if (debouncer.fell()) {
    // A short button press (e.g., to wake up LCD)
    recordLCDActivity();
  }

  // Normal system operation (only if system initialized after boot/wakeup)
  if (bootCount > 0) {
    verifyFingerprint(); // Continuously scan for fingerprints

    // Check for backend updates periodically
    static unsigned long lastUpdateCheck = 0;
    if (millis() - lastUpdateCheck > UPDATE_CHECK_INTERVAL) {
      Serial.println("Checking for firmware updates from backend...");
      checkForUpdates();
      lastUpdateCheck = millis();
    }

    // Attempt to sync offline logs if in offline mode
    // Checks every 30 seconds, or immediately if lastSyncAttempt is 0 (first check)
    if (isOffline && (millis() - lastSyncAttempt > 30000 || lastSyncAttempt == 0)) {
      Serial.println("Attempting to sync offline logs.");
      syncOfflineLogs();
      lastSyncAttempt = millis();
    }

    // Enter deep sleep after a period of inactivity if not in offline mode
    // (Offline mode keeps the device awake to allow continuous logging)
    if (millis() > INACTIVITY_TIMEOUT && !isOffline) {
      Serial.println("Inactivity timeout reached. Entering deep sleep.");
      enterDeepSleep();
    }
  }

  delay(10); // Small delay to yield CPU to other tasks and prevent watchdog resets
}

// ==================== System Initialization and Utilities ====================

// Initializes core system components after boot/wakeup
void initSystem() {
  Serial.println("Initializing System...");
  lcd.clear();
  lcd.print("Initializing...");
  recordLCDActivity(); // Keep LCD on during initialization

  // Attempt to connect to saved WiFi credentials
  if (!autoConnectWiFi()) {
    Serial.println("AutoConnect failed. Starting WiFiManager for configuration.");
    startWiFiManager(false); // Do not force config, let it try saved creds first
  } else {
    // If WiFi connected, set up time synchronization and local OTA
    setupNTP();
    setupOTA();
  }
}

// Checks if battery voltage is above a minimum threshold for safe operation/updates
bool isBatterySufficient() {
  // Read raw ADC value from battery pin and convert to voltage.
  // Assumes a voltage divider where the measured voltage is half the battery voltage.
  // (e.g., two equal resistors dividing the battery voltage before feeding to ADC).
  // ADC range 0-4095 corresponds to 0-3.3V (internal reference).
  float voltage = analogRead(BATTERY_PIN) * (3.3 / 4095.0) * 2.0;
  Serial.printf("Battery Voltage: %.2fV\n", voltage);
  return voltage >= BATTERY_MIN_VOLTAGE;
}

// Returns a unique device ID based on the ESP32's eFuse MAC address
String getDeviceID() {
  uint64_t chipid = ESP.getEfuseMac(); // Get unique MAC address
  // Format as "ESP32-XXXXXXXX" using the upper 32 bits of the MAC
  return "ESP32-" + String((uint32_t)(chipid >> 32), HEX);
}

// Returns the current battery voltage
float getBatteryLevel() {
  // Same calculation as isBatterySufficient()
  return analogRead(BATTERY_PIN) * (3.3 / 4095.0) * 2.0;
}

// ==================== WiFi Management Functions ====================

// Attempts to automatically connect to previously saved WiFi credentials
bool autoConnectWiFi() {
  WiFi.mode(WIFI_STA); // Set WiFi to Station mode (client)
  WiFiManager wm;
  wm.setTitle("Fingerprint System"); // Title for the configuration portal
  wm.setConnectTimeout(60); // Timeout for connecting to WiFi (in seconds)
  wm.setDebugOutput(true); // Enable debug output for WiFiManager messages

  lcd.clear();
  lcd.print("Connecting WiFi");
  lcd.setCursor(0,1);
  lcd.print("AutoConnect...");
  recordLCDActivity(); // Keep LCD on during connection attempt

  if (wm.autoConnect("ESP32-Fingerprint")) { // Auto-connect with fallback AP "ESP32-Fingerprint"
    lcd.clear();
    lcd.print("WiFi Connected!");
    lcd.setCursor(0, 1);
    lcd.print(WiFi.localIP()); // Display assigned IP address
    Serial.print("WiFi Connected! IP: ");
    Serial.println(WiFi.localIP());
    delay(1500); // Display message briefly
    return true;
  }
  Serial.println("WiFi AutoConnect Failed.");
  return false;
}

// Starts the WiFiManager configuration portal, allowing user to set WiFi credentials
void startWiFiManager(bool forceConfig) {
  Serial.println("Starting WiFiManager config portal.");
  digitalWrite(LCD_BACKLIGHT_PIN, HIGH); // Ensure backlight is on for user interaction
  lcd.clear();
  lcd.print("Config Mode");
  lcd.setCursor(0,1);
  lcd.print("AP: ESP32-FP"); // Inform user about the access point name

  WiFiManager wm;
  wm.setConfigPortalTimeout(180); // 3 minutes timeout for the config portal (seconds)
  wm.setDebugOutput(true);

  if (forceConfig || !wm.autoConnect()) { // If forced or autoConnect fails
    Serial.println("Entering blocking config portal.");
    // This is a blocking call; the code execution will pause here until the portal
    // is configured or the timeout is reached.
    wm.startConfigPortal("ESP32-Fingerprint");
  }

  Serial.println("WiFiManager finished. Restarting...");
  // Restart after exiting config portal, regardless of success, to apply new settings
  ESP.restart();
}

// ==================== Fingerprint Sensor Functions ====================

// Manages the fingerprint scanning and attendance logging process
void verifyFingerprint() {
  showFingerprintPrompt(); // Display "Scan Fingerprint" on LCD
  recordLCDActivity(); // Keep LCD on while waiting for fingerprint

  // Step 1: Get fingerprint image
  int p = finger.getImage();
  if (p != FINGERPRINT_OK) {
    if (p == FINGERPRINT_NOFINGER) return; // No finger detected, just return and try again
    Serial.printf("getImage error: %d\n", p);
    lcd.clear();
    lcd.print("Image Error");
    delay(1000);
    return;
  }

  // Step 2: Convert image to template
  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) {
    Serial.printf("image2Tz error: %d\n", p);
    lcd.clear();
    lcd.print("Convert Error");
    delay(1000);
    return;
  }

  // Step 3: Search for fingerprint in stored templates
  p = finger.fingerFastSearch(); // Searches the database for a match
  if (p == FINGERPRINT_OK) {
    int userId = finger.fingerID; // This is the ID of the matched fingerprint!
    Serial.printf("Found ID #%d with confidence %d\n", userId, finger.confidence);

    String timestamp = getTimestamp(); // Get current timestamp (NTP synchronized)
    Serial.printf("Attendance attempt for ID %d at %s\n", userId, timestamp.c_str());

    // Try sending attendance to backend first if connected
    if (WiFi.status() == WL_CONNECTED) {
      if (sendToBackend(userId, timestamp)) { // Pass the actual userId and timestamp
        showAttendanceResult(true, userId); // Show success on LCD
        isOffline = false; // Successfully sent online, clear offline flag
        return; // Done with this attendance event
      } else {
        Serial.println("Failed to send to backend, falling back to offline logging.");
      }
    } else {
      Serial.println("WiFi not connected, logging offline.");
    }

    // Fallback to offline logging if WiFi not connected or backend send failed
    isOffline = true; // Set offline flag
    logAttendanceOffline(userId, timestamp.c_str()); // Store attendance locally
    showOfflineWarning(); // Inform user about offline mode

  } else if (p == FINGERPRINT_NOFINGER) {
    // If getImage() returned OK but fingerFastSearch() returned NOFINGER,
    // it means an image was acquired but no match was found.
    showAttendanceResult(false, 0); // User ID 0 for "Not Recognized"
  } else {
    // Other errors during fingerprint search
    Serial.printf("Fingerprint search error: %d\n", p);
    showAttendanceResult(false, 0); // Show general failure
  }
}

// ==================== Power Management Functions ====================

// Puts the ESP32 into deep sleep mode to conserve power
void enterDeepSleep() {
  Serial.println("Entering Deep Sleep...");
  lcd.clear();
  lcd.print("Entering Sleep");
  delay(500); // Give time for message to display

  powerDownPeripherals(); // Turn off peripherals before sleeping

  Serial.printf("Going to sleep now (Boot count: %d)\n", bootCount);
  Serial.println("Wake up by EXT0 (GPIO_NUM_0 LOW)."); // Or other configured wakeup sources

  Serial.flush(); // Ensure all serial output is sent before sleeping
  esp_deep_sleep_start(); // Enter deep sleep
}

// Powers down non-essential peripherals to save power
void powerDownPeripherals() {
  Serial.println("Powering down peripherals...");
  // Hold GPIO_NUM_4 (SENSOR_PWR_PIN) low during deep sleep
  digitalWrite(SENSOR_PWR_PIN, LOW); // Turn off power to sensor
  rtc_gpio_hold_en(GPIO_NUM_4); // Hold the pin state (low) during sleep

  WiFi.mode(WIFI_OFF); // Turn off WiFi radio to save power
  btStop(); // Turn off Bluetooth radio

  lcd.noDisplay(); // Turn off LCD display content
  digitalWrite(LCD_BACKLIGHT_PIN, LOW); // Turn off LCD backlight

  setCpuFrequencyMhz(80); // Set CPU frequency to a lower value (if not already done by sleep mode)
}

// Manages the LCD backlight based on user/system activity
void manageLCDPower() {
  if (millis() - lastActivity > INACTIVITY_TIMEOUT) {
    digitalWrite(LCD_BACKLIGHT_PIN, LOW); // Turn off backlight
    lcd.noDisplay(); // Turn off display content
  }
}

// Records activity to keep the LCD backlight on and reset the inactivity timer
void recordLCDActivity() {
  lcd.display(); // Turn on display content
  digitalWrite(LCD_BACKLIGHT_PIN, HIGH); // Turn on backlight
  lastActivity = millis(); // Reset activity timer
}

// ==================== LCD Display Functions ====================

// Displays a prompt for fingerprint scanning on the LCD
void showFingerprintPrompt() {
  lcd.clear();
  lcd.print("Scan Fingerprint");
  lcd.setCursor(0, 1);
  lcd.print("Waiting...");
}

// Displays the result of an attendance attempt on the LCD
void showAttendanceResult(bool success, int userId) {
  lcd.clear();
  if (success) {
    lcd.print("Attendance OK");
    lcd.setCursor(0, 1);
    lcd.print("ID: ");
    lcd.print(userId);
  } else {
    lcd.print("Not Recognized");
    lcd.setCursor(0, 1);
    lcd.print("Try Again");
  }
  recordLCDActivity(); // Keep LCD on to show result
  delay(2000); // Display result for 2 seconds
}

// Displays a warning about offline mode on the LCD
void showOfflineWarning() {
  lcd.clear();
  lcd.print("OFFLINE MODE");
  lcd.setCursor(0, 1);
  lcd.print("Data Stored Loc."); // "Loc." for Locally
  recordLCDActivity();
  delay(2000);
}

// ==================== Offline Mode Functions ====================

// Logs attendance records to SPIFFS when the device is offline
void logAttendanceOffline(int userId, const char* timestamp) {
  Serial.printf("Logging offline: ID %d, Time %s\n", userId, timestamp);
  // Open file in append mode, create if it doesn't exist
  File file = SPIFFS.open("/offline_logs.txt", FILE_APPEND);
  if (file) {
    file.printf("%d,%s\n", userId, timestamp); // Format: userId,timestamp
    file.close();
    Serial.println("Offline log saved.");
  } else {
    Serial.println("Failed to open offline_logs.txt for writing.");
    lcd.clear();
    lcd.print("Log Error!");
    delay(1000);
  }
}

// Attempts to synchronize stored offline logs with the backend when online
void syncOfflineLogs() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Cannot sync offline logs: WiFi not connected.");
    return;
  }

  Serial.println("Attempting to sync offline logs...");
  lcd.clear();
  lcd.print("Syncing Logs...");
  recordLCDActivity();

  File file = SPIFFS.open("/offline_logs.txt", FILE_READ);
  if (!file) {
    Serial.println("No offline logs file found.");
    isOffline = false; // No logs to sync, so not in offline mode regarding logs
    lcd.print("No logs to sync");
    delay(1500);
    return;
  }

  String logLine;
  bool allSynced = true;
  String remainingLogs = ""; // To store logs that failed to sync for the next attempt

  // Read logs line by line and attempt to send them to the backend
  while (file.available()) {
    logLine = file.readStringUntil('\n');
    logLine.trim(); // Remove newline character and any leading/trailing whitespace

    if (logLine.length() == 0) continue; // Skip empty lines

    int commaIndex = logLine.indexOf(',');
    if (commaIndex == -1) {
      Serial.printf("Invalid log line format: %s\n", logLine.c_str());
      remainingLogs += logLine + "\n"; // Keep malformed logs to avoid data loss
      allSynced = false;
      continue;
    }

    int userId = logLine.substring(0, commaIndex).toInt();
    String timestamp = logLine.substring(commaIndex + 1);

    Serial.printf("Sending offline log: ID %d, Time %s\n", userId, timestamp.c_str());
    if (sendToBackend(userId, timestamp)) { // Try sending to backend
      Serial.println("Offline log sent successfully.");
    } else {
      Serial.printf("Failed to send offline log: %s\n", logLine.c_str());
      remainingLogs += logLine + "\n"; // Keep failed logs for next attempt
      allSynced = false;
    }
  }

  file.close(); // Close the read file

  // Rewrite the file with only unsynced logs, or delete it if all logs were synced
  if (allSynced) {
    Serial.println("All offline logs synced. Deleting file.");
    SPIFFS.remove("/offline_logs.txt"); // Delete the file if empty
    isOffline = false; // No more pending logs
    lcd.clear();
    lcd.print("Logs Synced!");
  } else {
    Serial.println("Some offline logs failed to sync. Rewriting file.");
    File outFile = SPIFFS.open("/offline_logs.txt", FILE_WRITE); // Open in write mode to truncate/overwrite
    if (outFile) {
      outFile.print(remainingLogs); // Write back only the unsynced logs
      outFile.close();
      lcd.clear();
      lcd.print("Sync Partial!");
    } else {
      Serial.println("ERROR: Could not rewrite offline logs file!");
      lcd.clear();
      lcd.print("Sync Error!");
    }
  }
  delay(1500); // Display message briefly
}

// ==================== NTP Time Synchronization ====================

// Callback function for NTP time synchronization events
void timeSyncNotificationCallback(struct timeval *tv) {
  Serial.printf("NTP time synchronized: %ld.%06ld\n", tv->tv_sec, tv->tv_usec);
  struct tm timeinfo;
  getLocalTime(&timeinfo); // Update local time info struct
  Serial.printf("Current time: %s", asctime(&timeinfo)); // Print human-readable time
  lcd.clear();
  lcd.print("Time Synced!");
  lcd.setCursor(0, 1);
  char time_buf[16];
  strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &timeinfo); // Format time for LCD
  lcd.print(time_buf);
  delay(1500); // Display briefly
}

// Sets up the NTP client for time synchronization
void setupNTP() {
  Serial.println("Setting up NTP...");
  // Configure time with GMT offset, daylight offset, and NTP servers
  configTime(GMT_OFFSET_SEC, DAYLIGHT_OFFSET_SEC, NTP_SERVER1, NTP_SERVER2);
  // Set callback for when time is successfully synchronized
  sntp_set_time_sync_notification_cb(timeSyncNotificationCallback);

  // Perform an initial check for time immediately
  struct tm timeinfo;
  if (!getLocalTime(&timeinfo)) {
    Serial.println("Failed to obtain time (initial check). NTP client will retry.");
    lcd.clear();
    lcd.print("Time Sync Fail");
    delay(1500);
  } else {
    Serial.println("Initial time fetch successful.");
    timeSyncNotificationCallback(nullptr); // Call callback to update LCD with current time
  }
}

// Retrieves the current timestamp in ISO 8601 format (e.g., "YYYY-MM-DDTHH:MM:SSZ")
String getTimestamp() {
  struct tm timeinfo;
  // Get local time. If not available (e.g., NTP not synced yet), return a placeholder.
  if (!getLocalTime(&timeinfo)) {
    Serial.println("Failed to obtain time for timestamp, returning placeholder.");
    return "2000-01-01T00:00:00Z"; // Fallback to a default
  }

  char timestamp_buf[30]; // Buffer for "YYYY-MM-DDTHH:MM:SSZ" + null terminator
  strftime(timestamp_buf, sizeof(timestamp_buf), "%Y-%m-%dT%H:%M:%SZ", &timeinfo);
  return String(timestamp_buf);
}

// ==================== Backend Communication Functions ====================

// Sends attendance data to the backend server via HTTP POST
bool sendToBackend(int userId, String timestamp) {
  Serial.printf("Sending to backend: User ID %d, Timestamp %s\n", userId, timestamp.c_str());

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("sendToBackend: WiFi not connected.");
    return false;
  }

  WiFiClientSecure client;
  // IMPORTANT: This line is crucial for HTTPS security.
  // It ensures your device trusts the server's certificate.
  client.setCACert(ROOT_CA_CERTIFICATE);

  HTTPClient http;
  if (!http.begin(client, BACKEND_ATTENDANCE_URL)) {
    Serial.println("HTTP begin failed for attendance URL.");
    return false;
  }

  http.addHeader("Content-Type", "application/json");
  // Add custom headers to send device info to the backend
  http.addHeader("X-Device-ID", getDeviceID());
  // You can also add an API key/token here if your backend requires it for authentication:
  // http.addHeader("Authorization", "Bearer your_api_key_here");

  // Create JSON payload for the attendance record
  StaticJsonDocument<128> doc; // Adjust size based on your JSON structure
  doc["userId"] = userId;
  doc["timestamp"] = timestamp;
  doc["batteryLevel"] = getBatteryLevel(); // Include battery level

  String requestBody;
  serializeJson(doc, requestBody); // Serialize JSON object to a String

  Serial.print("Sending JSON: ");
  Serial.println(requestBody);

  int httpResponseCode = http.POST(requestBody); // Send the HTTP POST request

  if (httpResponseCode > 0) {
    Serial.printf("HTTP Response code: %d\n", httpResponseCode);
    String payload = http.getString(); // Get response payload from server
    Serial.println("HTTP Response payload: " + payload);

    // Assuming 200 OK or 201 Created signifies success from the backend
    bool success = (httpResponseCode == HTTP_CODE_OK || httpResponseCode == HTTP_CODE_CREATED);
    http.end(); // Close connection
    return success;
  } else {
    Serial.printf("HTTP Error: %s\n", http.errorToString(httpResponseCode).c_str());
  }

  http.end(); // Close connection
  return false; // Failed to send or received an error response
}

// ==================== Enhanced OTA Functions ====================

// Sets up ArduinoOTA for local firmware updates (e.g., via WiFi LAN)
void setupOTA() {
  ArduinoOTA.setPort(OTA_PORT); // Port for OTA service
  ArduinoOTA.setHostname("esp32-fingerprint"); // Hostname for mDNS discovery
  ArduinoOTA.setPassword(OTA_PASSWORD); // Password for OTA authentication
  ArduinoOTA.setRebootOnSuccess(true); // Automatically reboot after successful update
  ArduinoOTA.setMdnsEnabled(true); // Enable mDNS for easier discovery on local network

  ArduinoOTA.onStart([]() {
    otaState = OTA_UPDATING; // Set OTA state to indicate update in progress
    otaStartTime = millis();
    String type = (ArduinoOTA.getCommand() == U_FLASH) ? "firmware" : "filesystem";
    Serial.println("OTA Start: " + type);
    lcd.clear();
    lcd.print("OTA: " + type);
    lcd.setCursor(0, 1);
    lcd.print("Starting...");
    digitalWrite(SENSOR_PWR_PIN, LOW); // Power down sensor during OTA to prevent interference
  });

  ArduinoOTA.onProgress([](unsigned int progress, unsigned int total) {
    displayOTAProgress(progress, total, "Local Update"); // Update LCD with progress
  });

  ArduinoOTA.onError(handleOTAError); // Set custom error handler for OTA failures
  ArduinoOTA.begin(); // Start the OTA service
  Serial.println("Local OTA service initialized.");
}

// Checks the backend server for available firmware updates
void checkForUpdates() {
  // Only check for updates if battery is sufficient, WiFi is connected, and no OTA is currently in progress
  if (!isBatterySufficient() || WiFi.status() != WL_CONNECTED || otaState != OTA_IDLE) {
    if (!isBatterySufficient()) Serial.println("OTA Check: Battery not sufficient.");
    if (WiFi.status() != WL_CONNECTED) Serial.println("OTA Check: WiFi not connected.");
    if (otaState != OTA_IDLE) Serial.println("OTA Check: Already in OTA process.");
    return;
  }
  Serial.println("Checking backend for updates...");

  WiFiClientSecure client;
  // IMPORTANT: This line validates the server's SSL certificate.
  client.setCACert(ROOT_CA_CERTIFICATE);

  HTTPClient https;
  if (https.begin(client, BACKEND_UPDATE_URL)) {
    // Add custom headers to send device information to the backend
    https.addHeader("X-Device-ID", getDeviceID());
    https.addHeader("X-Firmware-Version", FIRMWARE_VERSION);
    https.addHeader("X-Battery-Level", String(getBatteryLevel()));

    int httpCode = https.GET(); // Send GET request to the update check URL
    if (httpCode == HTTP_CODE_OK) {
      Serial.println("Update check response received.");
      processUpdateResponse(https.getString()); // Process the JSON response
    } else {
      Serial.printf("Update check HTTP Error: %d - %s\n", httpCode, https.errorToString(httpCode).c_str());
      lcd.clear();
      lcd.print("Update Check Err");
      lcd.setCursor(0,1);
      lcd.print("Code: " + String(httpCode));
      delay(2000);
    }
    https.end(); // Close connection
  } else {
    Serial.println("HTTP begin failed for update URL.");
    lcd.clear();
    lcd.print("Update URL Err");
    delay(2000);
  }
}

// Processes the JSON response received from the backend update check
void processUpdateResponse(String payload) {
  DynamicJsonDocument doc(512); // ArduinoJson document for parsing JSON payload
  DeserializationError error = deserializeJson(doc, payload);

  if (error) {
    Serial.print(F("deserializeJson() failed: "));
    Serial.println(error.f_str());
    lcd.clear();
    lcd.print("Update JSON Err");
    lcd.setCursor(0,1);
    lcd.print(error.f_str());
    delay(2000);
    return;
  }

  if (doc["update_available"] == true) {
    String firmwareUrl = doc["firmware_url"].as<String>();
    String firmwareHash = doc["firmware_hash"].as<String>();
    int firmwareSize = doc["firmware_size"].as<int>();
    String newVersion = doc["version"].as<String>();

    Serial.printf("Update available: v%s, URL: %s, Hash: %s, Size: %d\n",
                  newVersion.c_str(), firmwareUrl.c_str(), firmwareHash.c_str(), firmwareSize);

    // Ask for user confirmation before starting the download
    if (confirmUpdate(newVersion, firmwareSize)) {
      pendingFirmwareURL = firmwareUrl; // Store URL for download
      expectedHash = firmwareHash; // Store expected hash for verification
      otaState = OTA_DOWNLOADING; // Change state to indicate download in progress
      startDownloadWithVerification(); // Initiate the secure download process
    } else {
      Serial.println("Firmware update declined by user.");
    }
  } else {
    Serial.println("No firmware update available or update_available is false.");
    lcd.clear();
    lcd.print("No new update");
    delay(1500);
  }
}

// Initiates the firmware download process with SHA256 integrity verification
void startDownloadWithVerification() {
  Serial.printf("Starting firmware download from: %s\n", pendingFirmwareURL.c_str());
  WiFiClientSecure client;
  // IMPORTANT: This line validates the server's SSL certificate.
  client.setCACert(ROOT_CA_CERTIFICATE);

  HTTPClient https;
  if (https.begin(client, pendingFirmwareURL)) {
    int httpCode = https.GET(); // Send GET request to download firmware binary

    if (httpCode == HTTP_CODE_OK) {
      int contentLength = https.getSize(); // Get expected file size from HTTP headers
      if (contentLength > 0 && Update.begin(contentLength)) { // Prepare Update library for the download
        // Initialize mbedTLS SHA256 context for hashing the downloaded data
        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);
        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
        mbedtls_md_starts(&ctx); // Start hash calculation

        WiFiClient *stream = https.getStreamPtr(); // Get pointer to the data stream
        uint8_t buffer[1024]; // Buffer for reading data in chunks
        size_t totalRead = 0;

        lcd.clear();
        lcd.print("Downloading...");
        digitalWrite(SENSOR_PWR_PIN, LOW); // Power down sensor during critical update for stability

        // Read data in chunks, write to flash, and update hash
        while (https.connected() && totalRead < contentLength) {
          size_t read = stream->readBytes(buffer, sizeof(buffer));
          if (read > 0) {
            mbedtls_md_update(&ctx, buffer, read); // Update SHA256 hash with current chunk

            if (Update.write(buffer, read) != read) { // Write chunk to flash via Update library
              Serial.println("Update.write failed!");
              handleOTAError(Update.getError()); // Handle update error
              mbedtls_md_free(&ctx); // Free mbedTLS context
              https.end();
              otaState = OTA_IDLE; // Reset OTA state
              return;
            }
            totalRead += read;
            displayOTAProgress(totalRead, contentLength, "Downloading"); // Update progress on LCD
          }
        }

        // Finalize SHA256 hash calculation
        uint8_t actualHash[32]; // 32 bytes for SHA256 hash
        mbedtls_md_finish(&ctx, actualHash); // Get final hash value
        mbedtls_md_free(&ctx); // Free mbedTLS context

        String actualHashStr;
        for (int i = 0; i < 32; i++) {
          // Convert byte array hash to hexadecimal string for comparison
          if (actualHash[i] < 0x10) actualHashStr += "0"; // Pad with leading zero for single hex digits
          actualHashStr += String(actualHash[i], HEX);
        }
        Serial.printf("Download complete. Actual hash: %s\n", actualHashStr.c_str());
        Serial.printf("Expected hash: %s\n", expectedHash.c_str());

        // Compare calculated hash with expected hash and finalize the update
        if (actualHashStr.equals(expectedHash) && Update.end(true)) { // `true` commits the update
          lcd.clear();
          lcd.print("Verification OK");
          lcd.setCursor(0, 1);
          lcd.print("Rebooting...");
          delay(2000);
          ESP.restart(); // Reboot into the new firmware
        } else {
          Serial.println("Firmware hash mismatch or Update.end failed!");
          lcd.clear();
          lcd.print("Invalid firmware!");
          Update.end(false); // `false` discards/rolls back the update
        }
      } else {
        Serial.printf("Update.begin failed (Error: %d) or content length is 0.\n", Update.getError());
        lcd.clear();
        lcd.print("Update Start Err!");
        lcd.setCursor(0,1);
        lcd.print(String(Update.getError()));
        delay(2000);
      }
    } else {
      Serial.printf("Firmware download HTTP Error: %d - %s\n", httpCode, https.errorToString(httpCode).c_str());
      lcd.clear();
      lcd.print("Download Err!");
      lcd.setCursor(0,1);
      lcd.print("Code: " + String(httpCode));
      delay(2000);
    }
    https.end(); // Close connection
  } else {
    Serial.println("HTTP begin failed for firmware URL.");
    lcd.clear();
    lcd.print("Firmware URL Err");
    delay(2000);
  }
  otaState = OTA_IDLE; // Reset OTA state after attempt
  digitalWrite(SENSOR_PWR_PIN, HIGH); // Ensure sensor is powered back on
}

// Enters a special recovery mode, allowing serial-triggered updates
void enterRecoveryMode() {
  Serial.println("Entering Recovery Mode...");
  lcd.clear();
  lcd.print("Recovery Mode");
  lcd.setCursor(0, 1);
  lcd.print("5 min timeout");

  WiFiClientSecure client; // Needed for secure updates in recovery
  client.setCACert(ROOT_CA_CERTIFICATE); // IMPORTANT: Validate certs in recovery too

  setupOTA(); // Enable local OTA in recovery mode as well
  Serial.println("Recovery Mode: Local OTA service enabled.");

  unsigned long recoveryStart = millis();
  // Recovery mode lasts for 5 minutes, or until an update is initiated
  while (millis() - recoveryStart < 300000) { // 300000 ms = 5 minutes
    ArduinoOTA.handle(); // Allow local OTA in recovery
    
    // Check for serial commands for recovery update
    if (Serial.available()) {
      String cmd = Serial.readStringUntil('\n');
      cmd.trim(); // Remove any whitespace
      if (cmd.startsWith("RECOVERY_UPDATE:")) {
        Serial.println("Received RECOVERY_UPDATE command.");
        startSecureRecoveryUpdate(cmd.substring(16)); // Pass the URL,HASH part
        return; // Exit recovery loop after starting update
      }
    }
    delay(100); // Small delay to avoid busy-waiting
  }

  // If timeout, exit recovery and reboot
  Serial.println("Recovery mode timeout. Rebooting.");
  lcd.clear();
  lcd.print("Recovery timeout");
  delay(2000);
  ESP.restart();
}

// Displays OTA progress on the LCD screen
void displayOTAProgress(size_t progress, size_t total, const char* label) {
  int percent = (progress * 100) / total;
  static int lastPercent = -1; // Static to track changes and only update when necessary

  if (percent != lastPercent) { // Only update LCD if percentage has changed
    lastPercent = percent;
    lcd.clear();
    lcd.print(label);
    lcd.print(": ");
    lcd.print(percent);
    lcd.print("%");

    lcd.setCursor(0, 1);
    int bars = map(percent, 0, 100, 0, 16); // Map percentage to 0-16 characters for progress bar
    for (int i = 0; i < 16; i++) {
      lcd.print(i < bars ? "=" : " "); // Display progress bar with '=' characters
    }
  }
}

// Handles various OTA error conditions and displays them on the LCD
void handleOTAError(ota_error_t error) {
  otaState = OTA_IDLE; // Reset OTA state to idle
  digitalWrite(SENSOR_PWR_PIN, HIGH); // Ensure sensor is powered back on after error

  String errorMsg;
  switch (error) {
    case OTA_AUTH_ERROR:    errorMsg = "Auth Failed"; break;
    case OTA_BEGIN_ERROR:   errorMsg = "Begin Failed"; break;
    case OTA_CONNECT_ERROR: errorMsg = "Connect Failed"; break;
    case OTA_RECEIVE_ERROR: errorMsg = "Receive Failed"; break;
    case OTA_END_ERROR:     errorMsg = "End Failed"; break;
    default:                errorMsg = "Error: " + String(error); // Generic error
  }
  Serial.printf("OTA Error: %s\n", errorMsg.c_str());

  lcd.clear();
  lcd.print("Update Failed");
  lcd.setCursor(0, 1);
  lcd.print(errorMsg);
  delay(5000); // Display error message for 5 seconds
}

// Prompts the user for confirmation to start a firmware update.
// Returns true if confirmed (button pressed within timeout), false otherwise.
bool confirmUpdate(String newVersion, int firmwareSize) {
  Serial.printf("New firmware available: v%s, Size: %d bytes. Confirm update?\n", newVersion.c_str(), firmwareSize);
  lcd.clear();
  lcd.print("New FW v" + newVersion); // Display new firmware version
  lcd.setCursor(0, 1);
  lcd.print("Press button to conf."); // Instruct user to press the button
  recordLCDActivity(); // Keep LCD on for user to read the prompt

  unsigned long confirmTimeout = millis() + 15000; // 15 seconds to confirm
  while (millis() < confirmTimeout) {
    debouncer.update(); // Update debouncer for button state
    if (debouncer.fell()) { // If the button is pressed (short press)
      Serial.println("Update confirmed by user.");
      lcd.clear();
      lcd.print("Update Confirmed");
      delay(1000);
      return true; // User confirmed
    }
    delay(50); // Small delay to prevent tight loop and allow other tasks
  }

  Serial.println("Update not confirmed by user (timeout).");
  lcd.clear();
  lcd.print("Update Cancelled");
  delay(1500);
  return false; // User did not confirm within timeout
}

// Initiates a secure firmware update from a URL and hash provided via serial.
// Primarily used in recovery mode for forced updates.
void startSecureRecoveryUpdate(String updateInfo) {
  // Expected format for updateInfo: "URL,HASH"
  // Example: "https://your_server.com/firmware.bin,a1b2c3d4e5f6..."
  int commaIndex = updateInfo.indexOf(',');
  if (commaIndex == -1) {
    Serial.println("RECOVERY_UPDATE: Invalid format. Expected URL,HASH");
    lcd.clear();
    lcd.print("Recovery Error");
    lcd.setCursor(0,1);
    lcd.print("Bad CMD Format");
    delay(2000);
    return;
  }

  pendingFirmwareURL = updateInfo.substring(0, commaIndex); // Extract URL
  expectedHash = updateInfo.substring(commaIndex + 1); // Extract SHA256 hash

  Serial.printf("RECOVERY_UPDATE: URL: %s, Hash: %s\n", pendingFirmwareURL.c_str(), expectedHash.c_str());
  lcd.clear();
  lcd.print("Recov. Updating");
  lcd.setCursor(0,1);
  lcd.print("Downloading...");

  otaState = OTA_DOWNLOADING; // Set state to downloading
  startDownloadWithVerification(); // Reuse the existing download and verification logic
}