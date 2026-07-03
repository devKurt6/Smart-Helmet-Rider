#include <WiFi.h>
#include <HTTPClient.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>

// -------- WiFi Info --------
// const char* ssid = "Print_budz";
// const char* password = "DecenaPrinter123!";
const char* ssid = "";
const char* password = "";

// -------- Flask Server URL --------
// Local:      http://192.168.x.x:2000/api/gps
// Production: https://smart-helmet-rider.onrender.com/api/gps
const char* serverURL = "http://192.168.x.x:2000/api/gps";  // <-- update your IP here

// -------- Helmet Identity --------
// ⚠️ CHANGE THIS for each ESP32 you flash!
// Use format: HELMET_001, HELMET_002, HELMET_003 ...
const char* HELMET_ID = "HELMET_001";
const char* HELMET_NAME = "Rider 1";  // optional friendly name

// -------- GPS Setup --------
TinyGPSPlus gps;
#define GPS_RX 16
#define GPS_TX 17
#define gpsSerial Serial2
// -------- MQ-3 Alcohol Sensor --------
#define ALCOHOL_SENSOR_PIN 34

int alcoholBaseline = 0;

HardwareSerial sim900(1);

#define GSM_RX 32
#define GSM_TX 33

String phoneNumber = "+639509898109";

bool smsSent = false;
bool networkReady = false;
bool simReady = false;
unsigned long lastGSMCheck = 0;
void setup() {
  Serial.begin(115200);

  // Start GPS
  gpsSerial.begin(9600, SERIAL_8N1, GPS_RX, GPS_TX);
  Serial.println("Waiting for GPS fix and satellites...");

  // Connect WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");
  Serial.print("ESP32 IP: ");
  Serial.println(WiFi.localIP());


  // Seed random generator
  randomSeed(analogRead(0));

  // -------- MQ-3 Warm-up & Calibration --------
  Serial.println("🔥 MQ-3 warming up...");
  delay(30000);  // 30 seconds warm-up

  Serial.println("📏 Calibrating alcohol baseline (clean air)...");
  alcoholBaseline = calibrateAlcoholBaseline();

  Serial.print("✅ Alcohol baseline: ");
  Serial.println(alcoholBaseline);


  // Start GSM
  sim900.begin(9600, SERIAL_8N1, GSM_RX, GSM_TX);
  delay(2000);
  Serial.println("Initializing SIM900...");

  // checkSIM();

  // waitForNetwork();

  // sendSMS();
}

float alcoholFiltered = 0;  // global, initial value

void loop() {
  unsigned long lastGPSSend = 0;
  // Read GPS data
  while (gpsSerial.available() > 0) {
    gps.encode(gpsSerial.read());
  }
  if (millis() - lastGPSSend > 5000) {
    sendGPSData();
    lastGPSSend = millis();
  }
  // sendGPSData();
  displayLocationInfo();
  // Alcohol sensor
  // int alcoholRaw = analogRead(ALCOHOL_SENSOR_PIN);
  // alcoholFiltered = alcoholFiltered * 0.3 + alcoholRaw * 0.7;  // low-pass filter
  // String alcoholStatus = getAlcoholStatus((int)alcoholFiltered);
  // // Print alcohol info
  // Serial.print("Alcohol Raw: ");
  // Serial.print(alcoholRaw);
  // Serial.print(" | Status: ");
  // Serial.println(alcoholStatus);
  int alcoholRaw = analogRead(ALCOHOL_SENSOR_PIN);
  alcoholFiltered = alcoholFiltered * 0.3 + alcoholRaw * 0.7;  // low-pass filter
  String alcoholStatus = getAlcoholStatus((int)alcoholFiltered);
  float alcoholPPM = alcoholRawToPPM((int)alcoholFiltered);

  // Print alcohol info
  Serial.print("Alcohol Raw: ");
  Serial.print(alcoholRaw);
  Serial.print(" | PPM: ");
  Serial.print(alcoholPPM, 2);
  Serial.print(" | Status: ");
  Serial.println(alcoholStatus);


  // Send SMS if strong alcohol detected
  if ((alcoholStatus == "ALCOHOL_PRESENT" || alcoholStatus == "STRONG_ALCOHOL") && !smsSent) {

    float lat = gps.location.isValid() ? gps.location.lat() : 14.5995;
    float lng = gps.location.isValid() ? gps.location.lng() : 120.9842;

    sendAlcoholWarning(lat, lng);

    smsSent = true;  // prevent repeated SMS
  }

  // Reset SMS flag if alcohol back to normal
  if (alcoholStatus == "NORMAL") {
    smsSent = false;
  }

  if (millis() - lastGSMCheck > 10000) { // every 10 sec

  if (!simReady) {
    checkSIM();
  }
  else if (!networkReady) {
    checkNetwork();
  }

  lastGSMCheck = millis();
}


  delay(1000);  // every 2 seconds
}




float alcoholRawToPPM(int raw) {
  float rs = ((4095.0 / raw) - 1) * alcoholBaseline;
  float ratio = rs / alcoholBaseline;

  float ppm = 200 * pow(ratio, -1.5);  // <- reduced from 2000 to 200
  if (ppm < 0) ppm = 0;
  return ppm;
}

//mq-3 sensor
int calibrateAlcoholBaseline() {
  const int samples = 50;
  long sum = 0;

  for (int i = 0; i < samples; i++) {
    sum += analogRead(ALCOHOL_SENSOR_PIN);
    delay(100);
  }

  return sum / samples;
}

String getAlcoholStatus(int alcoholRaw) {
  if (alcoholRaw <= alcoholBaseline + 400) {
    return "NORMAL";
  } else if (alcoholRaw <= alcoholBaseline + 900) {
    return "ALCOHOL_PRESENT";
  } else {
    return "STRONG_ALCOHOL";
  }
}


void sendGPSData() {
  if (WiFi.status() == WL_CONNECTED) {
    HTTPClient http;
    http.begin(serverURL);
    http.addHeader("Content-Type", "application/json");

    float lat, lng, speed, alt;
    int sat;

    if (gps.location.isValid()) {
      // Use real GPS
      lat = gps.location.lat();
      lng = gps.location.lng();
      speed = gps.speed.kmph();
      sat = gps.satellites.value();
      alt = gps.altitude.meters();
    } else {
      // Generate random values for testing
      // lat = random(1400000, 1410000) / 100000.0;    // approx 14.xxxx
      // lng = random(12100000, 12110000) / 100000.0;  // approx 121.xxxx
      // speed = random(0, 50);                        // 0-50 km/h
      // sat = random(0, 12);                          // 0-12 satellites
      // alt = random(0, 1000);                        // 0-1000 m
    }

    // PH Time
    int hour = gps.time.isValid() ? gps.time.hour() + 8 : random(0, 24);
    int minute = gps.time.isValid() ? gps.time.minute() : random(0, 60);
    int second = gps.time.isValid() ? gps.time.second() : random(0, 60);
    int day = gps.date.isValid() ? gps.date.day() : random(1, 28);
    int month = gps.date.isValid() ? gps.date.month() : random(1, 12);
    int year = gps.date.isValid() ? gps.date.year() : 2026;

    if (hour >= 24) {
      hour -= 24;
      day += 1;
    }

    int alcoholRaw = analogRead(ALCOHOL_SENSOR_PIN);
    String alcoholStatus = getAlcoholStatus(alcoholRaw);
    float alcoholPPM = alcoholRawToPPM(alcoholRaw);


    // JSON payload
    String json = "{";
    json += "\"lat\":" + String(lat, 6) + ",";
    json += "\"lng\":" + String(lng, 6) + ",";
    json += "\"speed\":" + String(speed, 1) + ",";
    json += "\"sat\":" + String(sat) + ",";
    json += "\"alt\":" + String(alt, 1) + ",";

    json += "\"hour\":" + String(hour) + ",";
    json += "\"minute\":" + String(minute) + ",";
    json += "\"second\":" + String(second) + ",";
    json += "\"day\":" + String(day) + ",";
    json += "\"month\":" + String(month) + ",";
    json += "\"year\":" + String(year) + ",";

    json += "\"alcohol_ppm\":" + String(alcoholRaw) + ",";     //raw
    json += "\"alcohol_raw\":" + String(alcoholPPM, 2) + ",";  //ppm
    json += "\"alcohol_status\":\"" + alcoholStatus + "\",";
    json += "\"helmet_id\":\"" + String(HELMET_ID) + "\"";

    json += "}";



    int httpResponseCode = http.POST(json);
    // Serial.print("HTTP Response: ");
    // Serial.println(httpResponseCode);
    // Serial.println("Sent JSON: " + json);

    http.end();
  }
}

void displayLocationInfo() {
  // Serial.println(F("-------------------------------------"));

  float lat, lng, speed, alt;
  int sat;

  if (gps.location.isValid()) {
    lat = gps.location.lat();
    lng = gps.location.lng();
    speed = gps.speed.kmph();
    sat = gps.satellites.value();
    alt = gps.altitude.meters();
  } else {
    lat = random(1400000, 1410000) / 100000.0;
    lng = random(12100000, 12110000) / 100000.0;
    speed = random(0, 50);
    sat = random(0, 12);
    alt = random(0, 1000);
  }

  // Serial.print("Latitude:  ");
  // Serial.println(lat, 6);
  // Serial.print("Longitude: ");
  // Serial.println(lng, 6);
  // Serial.print("Speed:      ");
  // Serial.print(speed);
  // Serial.println(" km/h");
  // Serial.print("Satellites: ");
  // Serial.println(sat);
  // Serial.print("Altitude:   ");
  // Serial.print(alt);
  // Serial.println(" m");

  // Serial.println(F("-------------------------------------"));
}

void checkNetwork() {

  sim900.println("AT+CREG?");
  delay(500);

  String response = "";

  while (sim900.available()) {
    response += char(sim900.read());
  }

  if (response.indexOf("0,1") != -1 || response.indexOf("0,5") != -1) {
    networkReady = true;
    Serial.println("GSM network connected");
  } else {
    Serial.println("Still searching network...");
  }
}

void sendAlcoholWarning(float lat, float lng) {

  // while (sim900.available()) sim900.read();  // clear buffer

  Serial.println("Sending Alcohol Warning SMS...");

  sim900.println("AT+CMGF=1");
  delay(1000);

  sim900.print("AT+CMGS=\"");
  sim900.print(phoneNumber);
  sim900.println("\"");

  delay(2000);

  String message = "WARNING: Alcohol detected! Lattitude:"+ String(lat, 6) + ", Longtitude:" + String(lng, 6);
  String message2 = "WARNING: Alcohol detected! Smart Helmet Rider";

  sim900.print(message);
  Serial.println(message);
  delay(500);

  sim900.write(26);

  Serial.println("SMS command sent");
}

/* CHECK SIM CARD */


void checkSIM() {

  sim900.println("AT+CPIN?");
  delay(500);

  String response = "";

  while (sim900.available()) {
    response += char(sim900.read());
  }

  if (response.indexOf("READY") != -1) {
    simReady = true;
    Serial.println("SIM card ready");
  } else {
    Serial.println("SIM not ready yet");
  }
}
/* SEND SMS */

void sendSMS() {

  Serial.println("Sending SMS...");

  sim900.println("AT+CMGF=1");
  delay(1000);

  sim900.print("AT+CMGS=\"");
  sim900.print(phoneNumber);
  sim900.println("\"");

  delay(2000);

  String message = "WARNING: Alcohol detected!\n";


  sim900.print(message);

  delay(500);

  sim900.write(26);  // CTRL+Z

  Serial.println("SMS command sent");
}