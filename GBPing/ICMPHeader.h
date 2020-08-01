//
//  ICMPHeader.h
//  GBPing
//
//  Created by Luka Mirosevic on 15/11/2012.
//  Copyright (c) 2012 Goonbee. All rights reserved.
//

#ifndef GBPing_ICMPHeader_h
#define GBPing_ICMPHeader_h

#include <AssertMacros.h>

#pragma mark - IP and ICMP On-The-Wire Format

// The following declarations specify the structure of ping packets on the wire.

// IP header structure:

struct GBIPHeader {
    uint8_t     versionAndHeaderLength;
    uint8_t     differentiatedServices;
    uint16_t    totalLength;
    uint16_t    identification;
    uint16_t    flagsAndFragmentOffset;
    uint8_t     timeToLive;
    uint8_t     protocol;
    uint16_t    headerChecksum;
    uint8_t     sourceAddress[4];
    uint8_t     destinationAddress[4];
    // options...
    // data...
};
typedef struct GBIPHeader GBIPHeader;

__Check_Compile_Time(sizeof(GBIPHeader) == 20);
__Check_Compile_Time(offsetof(GBIPHeader, versionAndHeaderLength) == 0);
__Check_Compile_Time(offsetof(GBIPHeader, differentiatedServices) == 1);
__Check_Compile_Time(offsetof(GBIPHeader, totalLength) == 2);
__Check_Compile_Time(offsetof(GBIPHeader, identification) == 4);
__Check_Compile_Time(offsetof(GBIPHeader, flagsAndFragmentOffset) == 6);
__Check_Compile_Time(offsetof(GBIPHeader, timeToLive) == 8);
__Check_Compile_Time(offsetof(GBIPHeader, protocol) == 9);
__Check_Compile_Time(offsetof(GBIPHeader, headerChecksum) == 10);
__Check_Compile_Time(offsetof(GBIPHeader, sourceAddress) == 12);
__Check_Compile_Time(offsetof(GBIPHeader, destinationAddress) == 16);

// ICMP type and code combinations:

enum {
    kICMPv4TypeEchoRequest = 8,
    kICMPv4TypeEchoReply   = 0
};

enum {
    kICMPv6TypeEchoRequest = 128,
    kICMPv6TypeEchoReply   = 129
};

// ICMP header structure:

struct GBICMPHeader {
    uint8_t     type;
    uint8_t     code;
    uint16_t    checksum;
    uint16_t    identifier;
    uint16_t    sequenceNumber;
    // data...
};
typedef struct GBICMPHeader GBICMPHeader;

__Check_Compile_Time(sizeof(GBICMPHeader) == 8);
__Check_Compile_Time(offsetof(GBICMPHeader, type) == 0);
__Check_Compile_Time(offsetof(GBICMPHeader, code) == 1);
__Check_Compile_Time(offsetof(GBICMPHeader, checksum) == 2);
__Check_Compile_Time(offsetof(GBICMPHeader, identifier) == 4);
__Check_Compile_Time(offsetof(GBICMPHeader, sequenceNumber) == 6);


#endif
