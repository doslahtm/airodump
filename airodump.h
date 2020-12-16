#include <stdint.h>
#include <map>
#include <cstring>
#include "mac.h"
#include <iostream>
#include <unistd.h>

using namespace std;

struct ieee80211_radiotap_header {
        uint8_t        it_version;     /* set to 0 */
        uint8_t        it_pad;
        uint16_t       it_len;         /* entire length */
        uint32_t TSTF:1,
                FLAGS:1,
                Rate:1,
                Channel:1,
                FHSS:1,
                dbmAntSig:1,
                unused:25,
                Ext:1;    /* fields present */
} __attribute__((__packed__));

#define MgmtFrame 0
#define DataFrame 2
#define Beacon 8
#define ProbeRes 0x5
#define ProbeReq 0x4
#define MACSIZE 6

#define TagSSID 0

struct dot11mac {
        uint8_t ver:2,
                type:2,
                subtype:4;
        uint8_t ToDS:1,
                FromDS:1,
                unused:6;
        uint16_t duration;
        uint8_t addr1[6];
        uint8_t addr2[6];
        uint8_t bssid[6];
        uint16_t seq;
} __attribute__((__packed__));

class BeaconInfo
{
private:
    /* data */
    uint32_t    beacons;
    int32_t     PWR;
    string      essid;
    // Mac         bssid;
public:
    BeaconInfo() {}
    BeaconInfo(char* essid_) { essid = string(essid_); beacons = 0; };
    void AddBeacons() { beacons += 1; };
    void UpdatePWR(int8_t PWR_) { PWR = (int32_t)PWR_; };
    int32_t PrintPWR() { return PWR; };
    int32_t PrintBeacons()  { return beacons; };
    string PrintEssid() { return essid; };
};



void AnalyzePkt(char* packet);

int8_t GetPwr(char* packet);






