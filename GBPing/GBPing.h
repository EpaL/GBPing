//
//  GBPing.h
//  GBPing
//
//  Created by Luka Mirosevic on 05/11/2012.
//  Copyright (c) 2012 Goonbee. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "GBPingSummary.h"

@class GBPingSummary;
@protocol GBPingDelegate;

NS_ASSUME_NONNULL_BEGIN

typedef void(^StartupCallback)(BOOL success, NSError * _Nullable error);

@interface GBPing : NSObject

@property (weak, nonatomic, nullable) id<GBPingDelegate>      delegate;

@property (copy, nonatomic, nullable) NSString                *host;
@property (assign, atomic) NSTimeInterval           pingPeriod;
@property (assign, atomic) NSTimeInterval           timeout;
@property (assign, atomic) NSUInteger               payloadSize;
@property (assign, atomic) NSUInteger               ttl;
/// The name of the interface that the socket must use, for example "en0", or nil
/// for the route that the system picks. A full-tunnel VPN routes even a LAN
/// address into the tunnel. A socket bound to the Wi-Fi or Ethernet interface
/// still reaches the router directly. Takes effect at the next setup.
@property (copy, atomic, nullable) NSString         *boundInterfaceName;
/// When YES, -startPinging starts only the listener, and each ping leaves when the
/// caller calls -sendPingNow. Two pingers can then send at one moment, so a caller that
/// subtracts one round trip from the other cancels the delay that both share. With the
/// default NO, a send thread pings every pingPeriod, at a phase of its own.
@property (assign, atomic) BOOL                     sendsOnDemand;
@property (assign, atomic, readonly) BOOL           isPinging;
@property (assign, atomic, readonly) BOOL           isReady;
@property (assign, atomic, readonly) BOOL           isStopped;

@property (assign, atomic) BOOL                     debug;

-(void)setupWithBlock:(StartupCallback)callback;
-(void)startPinging;
/// Sends one ping now, on the calling thread. Only for a pinger with sendsOnDemand set,
/// after -startPinging. The reply or the timeout goes to the delegate, as for any ping.
-(void)sendPingNow NS_SWIFT_NAME(sendPingNow());
-(void)stop;

@end

@protocol GBPingDelegate <NSObject>

@optional

-(void)ping:(GBPing *)pinger didFailWithError:(NSError *)error;

-(void)ping:(GBPing *)pinger didSendPingWithSummary:(GBPingSummary *)summary;
-(void)ping:(GBPing *)pinger didFailToSendPingWithSummary:(GBPingSummary *)summary error:(NSError *)error;
-(void)ping:(GBPing *)pinger didTimeoutWithSummary:(GBPingSummary *)summary;
-(void)ping:(GBPing *)pinger didReceiveReplyWithSummary:(GBPingSummary *)summary;
-(void)ping:(GBPing *)pinger didReceiveUnexpectedReplyWithSummary:(GBPingSummary *)summary;

@end

NS_ASSUME_NONNULL_END
