#include "airodump.h"

map<Mac, BeaconInfo> ApInfo;

clock_t from = clock(), now;

int8_t GetPwr(char* packet)
{
    char* Radiotap = packet;
    if ( ((struct ieee80211_radiotap_header*)Radiotap) -> dbmAntSig == 0x1 )
    {
        uint32_t SigOffset = sizeof(ieee80211_radiotap_header);
        for (Radiotap = packet; ((struct ieee80211_radiotap_header*)Radiotap) -> Ext; Radiotap += 8 )
        {
            SigOffset += 8;
        }
        SigOffset += ((struct ieee80211_radiotap_header*)packet) -> TSTF * 8;
        SigOffset += ((struct ieee80211_radiotap_header*)packet) -> FLAGS * 1;
        SigOffset += ((struct ieee80211_radiotap_header*)packet) -> Rate * 1;
        SigOffset += ((struct ieee80211_radiotap_header*)packet) -> Channel * 4;
        SigOffset += ((struct ieee80211_radiotap_header*)packet) -> FHSS * 2;
        Radiotap = packet + SigOffset;
        return (int8_t)*Radiotap;
    }
    else
    {
        return 0;
    }
    
}

void AnalyzePkt(char* packet)
{
    if (*packet) // filter non radiotap....
    {
        return ;
    }
    uint16_t RdtapLen = ((struct ieee80211_radiotap_header*)packet) -> it_len;
    int8_t Pwr = GetPwr(packet);
    char* dot11 = packet + RdtapLen; // dot11 frame
    if ( ((struct dot11mac*)dot11) -> ver == 0 
        && ((struct dot11mac*)dot11) -> type == MgmtFrame
        && ((struct dot11mac*)dot11) -> subtype == Beacon
        && !(((struct dot11mac*)dot11) -> ToDS)
        && !(((struct dot11mac*)dot11) -> FromDS) 
    )
    {
        // beacon frame catch!!
       // dump((uint8_t*)dot11, 50);
        uint8_t tmpBssid[6];
        char tmpEssid[33];
        memcpy(tmpBssid , ((struct dot11mac*)dot11) -> bssid, MACSIZE);
        dot11 = dot11 + sizeof(dot11mac) + 12;
        if (*dot11 == TagSSID)
        // ESSID 처리하는 부분
        {
            uint32_t EssIdLen = (uint32_t)(*(dot11 + 1));
            //printf("%u\n", EssIdLen);
            if ( EssIdLen == 0 )
            {
                strcpy(tmpEssid, "<length:  0>");
            }
            else
            {
                if ( *(dot11 + 2) == '\0' )
                {
                    snprintf(tmpEssid, sizeof(tmpEssid), "<length:  %d>", EssIdLen);
                }
                else
                {
                    strncpy(tmpEssid, dot11 + 2, EssIdLen);
                    tmpEssid[EssIdLen] = '\0';
                    //printf("%s\n", tmpEssid);
                }
            }
        }
        auto it = ApInfo.find(Mac(tmpBssid));
        if ( it == ApInfo.end() )
        {
            auto ret = ApInfo.insert( make_pair(Mac(tmpBssid), BeaconInfo(tmpEssid)) );
            if (ret.second)
            {
                ret.first->second.AddBeacons();
                ret.first->second.UpdatePWR(Pwr);
            }
            else
            {
                printf("error!\n");
            }
            
            //printf("%s %d %d %s\n", string(Mac(tmpBssid)).c_str(), ApInfo[Mac(tmpBssid)].PrintPWR(), ApInfo[Mac(tmpBssid)].PrintBeacons(), ApInfo[Mac(tmpBssid)].PrintEssid().c_str() );
        }
        else
        {
            
            it->second.AddBeacons();
            it->second.UpdatePWR(Pwr);
        }
    }
    now = clock();
    
    cout << "BSSID                      PWR   Beacons   ESSID" << endl;
    for (auto it = ApInfo.begin(); it != ApInfo.end(); it++) {
        cout << string(it->first) << "          " << it->second.PrintPWR() << "        " <<it ->second.PrintBeacons() << "   " << it->second.PrintEssid() << endl;
    }
    puts("");
    from = clock();
    return ;
    
}

