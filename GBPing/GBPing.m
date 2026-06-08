//
//  GBPing.m
//  GBPing
//
//  Created by Luka Mirosevic on 05/11/2012.
//  Copyright (c) 2012 Goonbee. All rights reserved.
//

#import "GBPing.h"

#if TARGET_OS_EMBEDDED || TARGET_IPHONE_SIMULATOR
#import <CFNetwork/CFNetwork.h>
#else
#import <CoreServices/CoreServices.h>
#endif

#import "ICMPHeader.h"

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static NSTimeInterval const kPendingPingsCleanupGrace = 1.0;

// Grace period after setup to ignore sequence number mismatches from stale ICMP
// packets This prevents spurious errors after wake from sleep when old
// responses arrive for previous sessions
static NSTimeInterval const kTransitionGracePeriod = 5.0;

static NSUInteger const kDefaultPayloadSize = 56;
static NSUInteger const kDefaultTTL = 49;
static NSTimeInterval const kDefaultPingPeriod = 1.0;
static NSTimeInterval const kDefaultTimeout = 2.0;

@interface GBPing ()

@property(assign, atomic) int socket;
@property(strong, nonatomic) NSData *hostAddress;
@property(strong, nonatomic) NSString *hostAddressString;
@property(assign, nonatomic) uint16_t identifier;

@property(assign, atomic, readwrite) BOOL isPinging;
@property(assign, atomic, readwrite) BOOL isReady;
@property(assign, atomic) NSUInteger nextSequenceNumber;
@property(strong, atomic) NSMutableDictionary *pendingPings;
@property(strong, nonatomic) NSMutableDictionary *timeoutTimers;
@property(strong, atomic) NSData *payloadTemplate;
@property(strong, nonatomic) NSMutableData *receiveBuffer;
@property(strong, nonatomic) NSLock *timeoutTimersLock;

@property(strong, nonatomic) dispatch_queue_t setupQueue;

@property(assign, atomic) BOOL isStopped;

// Track when setup completed to implement transition grace period
@property(strong, atomic) NSDate *setupCompletionTime;

// Count of stale packets suppressed during transition grace period
@property(assign, nonatomic) NSUInteger stalePacketsSuppressed;

@end

@implementation GBPing {
  NSUInteger _payloadSize;
  NSUInteger _ttl;
  NSTimeInterval _timeout;
  NSTimeInterval _pingPeriod;
  NSLock *_pendingPingsLock;
  sa_family_t hostAddressFamily;
}

#pragma mark - custom acc

- (void)setTimeout:(NSTimeInterval)timeout {
  @synchronized(self) {
    if (self.isPinging) {
      if (self.debug) {
        NSLog(@"GBPing: can't set timeout while pinger is running.");
      }
    } else {
      _timeout = timeout;
    }
  }
}

- (NSTimeInterval)timeout {
  @synchronized(self) {
    if (!_timeout) {
      return kDefaultTimeout;
    } else {
      return _timeout;
    }
  }
}

- (void)setTtl:(NSUInteger)ttl {
  @synchronized(self) {
    if (self.isPinging) {
      if (self.debug) {
        NSLog(@"GBPing: can't set ttl while pinger is running.");
      }
    } else {
      _ttl = ttl;
    }
  }
}

- (NSUInteger)ttl {
  @synchronized(self) {
    if (!_ttl) {
      return kDefaultTTL;
    } else {
      return _ttl;
    }
  }
}

- (void)setPayloadSize:(NSUInteger)payloadSize {
  @synchronized(self) {
    if (self.isPinging) {
      if (self.debug) {
        NSLog(@"GBPing: can't set payload size while pinger is running.");
      }
    } else {
      _payloadSize = payloadSize;
      self.payloadTemplate = nil;
    }
  }
}

- (NSUInteger)payloadSize {
  @synchronized(self) {
    if (!_payloadSize) {
      return kDefaultPayloadSize;
    } else {
      return _payloadSize;
    }
  }
}

- (void)setPingPeriod:(NSTimeInterval)pingPeriod {
  @synchronized(self) {
    if (self.isPinging) {
      if (self.debug) {
        NSLog(@"GBPing: can't set pingPeriod while pinger is running.");
      }
    } else {
      _pingPeriod = pingPeriod;
    }
  }
}

- (NSTimeInterval)pingPeriod {
  @synchronized(self) {
    if (!_pingPeriod) {
      return (NSTimeInterval)kDefaultPingPeriod;
    } else {
      return _pingPeriod;
    }
  }
}

#pragma mark - core pinging methods

- (void)setupWithBlock:(StartupCallback)callback {
  // error out of its already setup
  if (self.isReady == YES) {
    if (self.debug) {
      NSLog(@"GBPing: Can't setup, already setup.");
    }

    // notify about error and return
    dispatch_async(dispatch_get_main_queue(), ^{
      callback(NO, nil);
    });
    return;
  }

  // error out if no host is set
  if (!self.host) {
    if (self.debug) {
      NSLog(@"GBPing: set host before attempting to start.");
    }

    // notify about error and return
    dispatch_async(dispatch_get_main_queue(), ^{
      callback(NO, nil);
    });
    return;
  }

  // set up data structs
  self.nextSequenceNumber = 0;
  self.pendingPings = [[NSMutableDictionary alloc] init];
  self.timeoutTimers = [[NSMutableDictionary alloc] init];
  _pendingPingsLock = [[NSLock alloc] init];
  hostAddressFamily = AF_UNSPEC;

  dispatch_async(self.setupQueue, ^{
    CFStreamError streamError;
    BOOL success;

    CFHostRef hostRef =
        CFHostCreateWithName(NULL, (__bridge CFStringRef)self.host);

    /*
     * CFHostCreateWithName will return a null result in certain cases.
     * CFHostStartInfoResolution will return YES if _hostRef is null.
     */
    if (hostRef) {
      success =
          CFHostStartInfoResolution(hostRef, kCFHostAddresses, &streamError);
    } else {
      success = NO;
    }

    if (!success) {
      // construct an error
      NSDictionary *userInfo;
      NSError *error;

      if (hostRef && streamError.domain == kCFStreamErrorDomainNetDB) {
        userInfo = [NSDictionary
            dictionaryWithObjectsAndKeys:[NSNumber
                                             numberWithInteger:streamError
                                                                   .error],
                                         kCFGetAddrInfoFailureKey, nil];
      } else {
        userInfo = nil;
      }
      error = [NSError errorWithDomain:(NSString *)kCFErrorDomainCFNetwork
                                  code:kCFHostErrorUnknown
                              userInfo:userInfo];

      // clean up so far
      [self stop];

      // notify about error and return
      dispatch_async(dispatch_get_main_queue(), ^{
        callback(NO, error);
      });

      // just incase
      if (hostRef) {
        CFRelease(hostRef);
      }
      return;
    }

    // get the first IPv4 or IPv6 address
    Boolean resolved;
    NSArray *addresses =
        (__bridge NSArray *)CFHostGetAddressing(hostRef, &resolved);
    if (resolved && (addresses != nil)) {
      resolved = false;
      for (NSData *address in addresses) {
        const struct sockaddr *anAddrPtr =
            (const struct sockaddr *)[address bytes];

        if ([address length] >= sizeof(struct sockaddr) &&
            (anAddrPtr->sa_family == AF_INET ||
             anAddrPtr->sa_family == AF_INET6)) {

          self.hostAddress = address;
          self->hostAddressFamily = anAddrPtr->sa_family;
          resolved = true;
          self.hostAddressString = [self stringFromSockaddrData:address];
          break;
        }
      }
    }

    // we can stop host resolution now
    if (hostRef) {
      CFRelease(hostRef);
    }

    // if an error occurred during resolution
    if (!resolved) {
      // stop
      [self stop];

      // notify about error and return
      dispatch_async(dispatch_get_main_queue(), ^{
        callback(NO,
                 [NSError errorWithDomain:(NSString *)kCFErrorDomainCFNetwork
                                     code:kCFHostErrorHostNotFound
                                 userInfo:nil]);
      });
      return;
    }

    // set up socket
    int err = 0;
    switch (self->hostAddressFamily) {
    case AF_INET: {
      self.socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
      if (self.socket < 0) {
        err = errno;
      }
    } break;
    case AF_INET6: {
      self.socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
      if (self.socket < 0) {
        err = errno;
      }
    } break;
    default: {
      err = EPROTONOSUPPORT;
    } break;
    }

    // couldnt setup socket
    if (err) {
      // clean up so far
      [self stop];

      // notify about error and close
      dispatch_async(dispatch_get_main_queue(), ^{
        callback(NO, [NSError errorWithDomain:NSPOSIXErrorDomain
                                         code:err
                                     userInfo:nil]);
      });
      return;
    }

    // set ttl on the socket
    if (self.ttl && self.socket > 0) {
      int result = 0;
      int savedErrno = 0;
      switch (self->hostAddressFamily) {
      case AF_INET: {
        u_char ttlForSockOpt = (u_char)self.ttl;
        result = setsockopt(self.socket, IPPROTO_IP, IP_TTL, &ttlForSockOpt,
                            sizeof(ttlForSockOpt));
        if (result < 0)
          savedErrno = errno;
      } break;
      case AF_INET6: {
        int hops = (int)self.ttl;
        result = setsockopt(self.socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops,
                            sizeof(hops));
        if (result < 0)
          savedErrno = errno;
      } break;
      default:
        break;
      }

      if (result < 0 && self.debug) {
        // EINVAL (22) can occur if socket is not in proper state, which can
        // happen during rapid reinit cycles. This is non-fatal as default TTL
        // will be used.
        NSLog(@"GBPing: Failed to set TTL with error code: %d (ttl=%lu, "
              @"socket=%d, family=%d)",
              savedErrno, (unsigned long)self.ttl, self.socket,
              self->hostAddressFamily);
      }
    }

    // we are ready now
    self.setupCompletionTime = [NSDate date];
    self.isReady = YES;

    // notify that we are ready
    dispatch_async(dispatch_get_main_queue(), ^{
      callback(YES, nil);
    });
  });

  self.isStopped = NO;
}

- (void)startPinging {
  if (self.isReady && !self.isPinging) {
    // go into infinite listenloop on a new thread (listenThread)
    NSThread *listenThread =
        [[NSThread alloc] initWithTarget:self
                                selector:@selector(listenLoop)
                                  object:nil];
    listenThread.name = @"listenThread";

    // set up loop that sends packets on a new thread (sendThread)
    NSThread *sendThread = [[NSThread alloc] initWithTarget:self
                                                   selector:@selector(sendLoop)
                                                     object:nil];
    sendThread.name = @"sendThread";

    // we're pinging now
    self.isPinging = YES;
    [listenThread start];
    [sendThread start];
  }
}

- (void)listenLoop {
  @autoreleasepool {
    while (self.isPinging) {
      [self listenOnce];
    }
  }
}

- (void)listenOnce {
  int err;
  struct sockaddr_storage addr;
  socklen_t addrLen;
  ssize_t bytesRead;
  BOOL fatalError = NO;
  enum { kBufferSize = 65535 };

  if (self.receiveBuffer == nil || self.receiveBuffer.length < kBufferSize) {
    self.receiveBuffer = [NSMutableData dataWithLength:kBufferSize];
  }

  // read the data.
  addrLen = sizeof(addr);
  bytesRead = recvfrom(self.socket, self.receiveBuffer.mutableBytes,
                       kBufferSize, 0, (struct sockaddr *)&addr, &addrLen);
  err = 0;
  if (bytesRead < 0) {
    err = errno;
  }

  // process the data we read.
  if (bytesRead > 0) {
    BOOL isExpectedHost = [self address:&addr matchesHostData:self.hostAddress];

    if (isExpectedHost) { // only make sense where received packet comes from
                          // expected source
      NSDate *receiveDate = [NSDate date];
      NSMutableData *packet;

      packet = [NSMutableData dataWithBytes:self.receiveBuffer.bytes
                                     length:(NSUInteger)bytesRead];
      assert(packet);

      // complete the ping summary
      const struct GBICMPHeader *headerPointer;

      if (addr.ss_family == AF_INET) {
        headerPointer = [[self class] icmp4InPacket:packet];
      } else {
        headerPointer = (const struct GBICMPHeader *)[packet bytes];
      }

      if (headerPointer == NULL) {
        if (self.debug) {
          NSLog(@"GBPing: Could not extract ICMP header from received packet.");
        }
        return;
      }

      NSUInteger seqNo =
          (NSUInteger)OSSwapBigToHostInt16(headerPointer->sequenceNumber);
      NSNumber *key = @(seqNo);
      [_pendingPingsLock lock];
      GBPingSummary *storedSummary = self.pendingPings[key];
      [_pendingPingsLock unlock];
      GBPingSummary *pingSummary = [storedSummary copy];

      if (pingSummary != nil) {
        if ([self isValidPingResponsePacket:packet] == YES) {
          // override the source address (we might have sent to google.com and
          // 172.123.213.192 replied)
          pingSummary.receiveDate = receiveDate;
          NSString *host = [self stringForAddress:&addr];
          pingSummary.host = host ?: pingSummary.host;
          // IP can't be read from header for ICMPv6
          if (addr.ss_family == AF_INET) {
            NSString *source = [[self class] sourceAddressInPacket:packet];
            if (source) {
              pingSummary.host = source;
            }

            // set ttl from response (different servers may respond with
            // different ttls)
            const struct GBIPHeader *ipPtr;
            if ([packet length] >= sizeof(GBIPHeader)) {
              ipPtr = (const GBIPHeader *)[packet bytes];
              pingSummary.ttl = ipPtr->timeToLive;
            }
          }

          pingSummary.status = GBPingStatusSuccess;

          // invalidate the timeouttimer
          [self.timeoutTimersLock lock];
          NSTimer *timer = self.timeoutTimers[key];
          [timer invalidate];
          [self.timeoutTimers removeObjectForKey:key];
          [self.timeoutTimersLock unlock];

          [_pendingPingsLock lock];
          [self.pendingPings removeObjectForKey:key];
          [_pendingPingsLock unlock];

          if (self.delegate &&
              [self.delegate respondsToSelector:@selector
                             (ping:didReceiveReplyWithSummary:)]) {
            dispatch_async(dispatch_get_main_queue(), ^{
              // notify delegate
              [self.delegate ping:self
                  didReceiveReplyWithSummary:[pingSummary copy]];
            });
          }
        }
      } else {
        // Check if we're in the transition grace period after setup
        // During this time, we silently suppress stale packets entirely
        // (both logging AND delegate callbacks) to prevent ICMP storms
        BOOL inTransitionGracePeriod = NO;
        if (self.setupCompletionTime != nil) {
          NSTimeInterval timeSinceSetup =
              [[NSDate date] timeIntervalSinceDate:self.setupCompletionTime];
          inTransitionGracePeriod = (timeSinceSetup < kTransitionGracePeriod);
        }

        if (inTransitionGracePeriod) {
          // Silently suppress all stale/unexpected packets during grace period
          self.stalePacketsSuppressed++;
        } else {
          // Log summary of suppressed packets when grace period ends
          if (self.stalePacketsSuppressed > 0) {
            NSLog(@"GBPing: Transition grace period ended for '%@' - suppressed %lu stale packet(s)",
                  self.hostAddressString, (unsigned long)self.stalePacketsSuppressed);
            self.stalePacketsSuppressed = 0;
          }

          if ([self isValidPingResponsePacket:packet] == YES) {
            NSLog(@"GBPing: Hostname '%@' matched but GBPingSummary with "
                  @"sequence number (%lu) not found.",
                  self.hostAddressString, (unsigned long)seqNo);
            // Create a dummy GBPingSummary (since we won't have one in
            // self.pendingPings).
            GBPingSummary *pingSummary = [GBPingSummary new];

            // construct ping summary, as much as it can
            pingSummary.sequenceNumber = seqNo;
            NSString *host = [self stringForAddress:&addr];
            pingSummary.host = host ?: self.hostAddressString;
            pingSummary.sendDate = [NSDate date];
            pingSummary.ttl = 0;
            pingSummary.payloadSize = 0;
            pingSummary.status = GBPingStatusFail;

            if (self.delegate &&
                [self.delegate respondsToSelector:@selector
                               (ping:didReceiveUnexpectedReplyWithSummary:)]) {
              dispatch_async(dispatch_get_main_queue(), ^{
                [self.delegate ping:self
                    didReceiveUnexpectedReplyWithSummary:[pingSummary copy]];
              });
            }
          } else {
            if (self.debug) {
            NSLog(
                @"GBPing: Received ICMP packet from '%@' that didn't match the "
                @"next sequence number (%lu) but packet was not valid ICMP "
                @"Ping Response packet so ignoring.",
                self.hostAddressString, (unsigned long)seqNo);
            }
          }
        }
      }
    } else {
      // The hostname of the reply packet didn't match the expected hostname.
      if (self.debug) {
        //        NSString *host = [self stringForAddress:&addr];
        //        NSLog(@"GBPing: Host didn't match: expected %@, received %@",
        //        self.hostAddressString, host ?: @"(unknown)");
      }
    }
  } else if (bytesRead == 0) {
    // Zero-length packets are valid but contain no useful information. Just
    // ignore them.
    return;
  } else {
    fatalError = YES;
  }

  // If we recieved a fatal error above, shut everything down.
  if (fatalError == YES) {

    NSLog(@"GBPing: listen: fatal error: %d", err);

    if (err == 0) {
      err = EPIPE;
    }

    @synchronized(self) {
      if (!self.isStopped) {
        if (self.delegate && [self.delegate respondsToSelector:@selector
                                            (ping:didFailWithError:)]) {
          dispatch_async(dispatch_get_main_queue(), ^{
            [self.delegate ping:self
                didFailWithError:[NSError errorWithDomain:NSPOSIXErrorDomain
                                                     code:err
                                                 userInfo:nil]];
          });
        }
      }
    }

    // stop the whole thing
    [self stop];

    // Small delay before returning to prevent tight spin loop
    // This gives stop() time to set isPinging = NO and break the listenLoop
    [NSThread sleepForTimeInterval:0.1];
  }
}

- (void)sendLoop {
  @autoreleasepool {
    while (self.isPinging) {
      [self sendPing];

      NSTimeInterval period = self.pingPeriod;
      if (period <= 0) {
        period = kDefaultPingPeriod;
      }

      [NSThread sleepForTimeInterval:period];
    }
  }
}

- (void)sendPing {
  if (self.isPinging) {

    int err;
    NSData *packet;
    ssize_t bytesSent;

    // Construct the ping packet.
    NSData *payload = [self currentPayloadData];

    switch (hostAddressFamily) {
    case AF_INET: {
      packet = [self pingPacketWithType:kICMPv4TypeEchoRequest
                                payload:payload
                       requiresChecksum:YES];
    } break;
    case AF_INET6: {
      packet = [self pingPacketWithType:kICMPv6TypeEchoRequest
                                payload:payload
                       requiresChecksum:NO];
    } break;
    default: {
    } break;
    }

    // this is our ping summary
    GBPingSummary *newPingSummary = [GBPingSummary new];

    // Send the packet.
    if (self.socket == 0) {
      bytesSent = -1;
      err = EBADF;
    } else {
      // record the send date
      NSDate *sendDate = [NSDate date];

      // construct ping summary, as much as it can
      newPingSummary.sequenceNumber = self.nextSequenceNumber;
      newPingSummary.host = self.host;
      newPingSummary.sendDate = sendDate;
      newPingSummary.ttl = self.ttl;
      newPingSummary.payloadSize = self.payloadSize;
      newPingSummary.status = GBPingStatusPending;

      // add it to pending pings
      NSNumber *key = @(self.nextSequenceNumber);
      [_pendingPingsLock lock];
      self.pendingPings[key] = newPingSummary;
      [_pendingPingsLock unlock];

      // increment sequence number
      self.nextSequenceNumber += 1;
      // Prevent the sequence number from overrunning
      if (self.nextSequenceNumber >= UINT16_MAX) {
        self.nextSequenceNumber = 0;
      }

      // we create a copy, this one will be passed out to other threads
      GBPingSummary *pingSummaryCopy = [newPingSummary copy];

      // we need to clean up our list of pending pings, and we do that after the
      // timeout has elapsed (+ some grace period)
      dispatch_after(
          dispatch_time(DISPATCH_TIME_NOW,
                        (int64_t)((self.timeout + kPendingPingsCleanupGrace) *
                                  NSEC_PER_SEC)),
          dispatch_get_main_queue(), ^{
            // remove the ping from the pending list
            [self->_pendingPingsLock lock];
            [self.pendingPings removeObjectForKey:key];
            [self->_pendingPingsLock unlock];
          });

      // add a timeout timer
      dispatch_block_t timeoutBlock = [^{
        newPingSummary.status = GBPingStatusFail;

        if (self.delegate && [self.delegate respondsToSelector:@selector
                                            (ping:didTimeoutWithSummary:)]) {
          dispatch_async(dispatch_get_main_queue(), ^{
            [self.delegate ping:self didTimeoutWithSummary:pingSummaryCopy];
          });
        }

        [self.timeoutTimersLock lock];
        [self.timeoutTimers removeObjectForKey:key];
        [self.timeoutTimersLock unlock];
      } copy];

      NSTimer *timeoutTimer =
          [NSTimer timerWithTimeInterval:self.timeout
                                  target:self
                                selector:@selector(_invokeTimeoutCallback:)
                                userInfo:timeoutBlock
                                 repeats:NO];
      [[NSRunLoop mainRunLoop] addTimer:timeoutTimer
                                forMode:NSRunLoopCommonModes];

      // keep a local ref to it
      if (self.timeoutTimers) {
        [self.timeoutTimersLock lock];
        self.timeoutTimers[key] = timeoutTimer;
        [self.timeoutTimersLock unlock];
      }

      // notify delegate about this
      if (self.delegate && [self.delegate respondsToSelector:@selector
                                          (ping:didSendPingWithSummary:)]) {
        dispatch_async(dispatch_get_main_queue(), ^{
          [self.delegate ping:self didSendPingWithSummary:pingSummaryCopy];
        });
      }

      bytesSent = sendto(self.socket, [packet bytes], [packet length], 0,
                         (struct sockaddr *)[self.hostAddress bytes],
                         (socklen_t)[self.hostAddress length]);
      err = 0;
      if (bytesSent < 0) {
        err = errno;
      }
    }

    // This is after the sending

    // successfully sent
    if ((bytesSent > 0) && (((NSUInteger)bytesSent) == [packet length])) {
      // noop, we already notified delegate about sending of the ping
    }
    // failed to send
    else {
      // complete the error
      if (err == 0) {
        err = ENOBUFS; // This is not a hugely descriptor error, alas.
      }

      // little log
      if (self.debug) {
        NSLog(@"GBPing: failed to send packet with error code: %d", err);
      }

      // change status
      newPingSummary.status = GBPingStatusFail;

      GBPingSummary *pingSummaryCopyAfterFailure = [newPingSummary copy];

      [self stop];

      // notify delegate
      if (self.delegate &&
          [self.delegate respondsToSelector:@selector
                         (ping:didFailToSendPingWithSummary:error:)]) {
        dispatch_async(dispatch_get_main_queue(), ^{
          [self.delegate ping:self
              didFailToSendPingWithSummary:pingSummaryCopyAfterFailure
                                     error:[NSError errorWithDomain:
                                                        NSPOSIXErrorDomain
                                                               code:err
                                                           userInfo:nil]];
        });
      }
    }
  }
}

- (void)stop {
  @synchronized(self) {
    if (self.isStopped == NO) {
      self.isPinging = NO;
      self.isReady = NO;

      // destroy listenThread by closing socket (listenThread)
      if (self.socket) {
        close(self.socket);
        self.socket = 0;
      }

      // destroy host
      self.hostAddress = nil;
      self.hostAddressString = nil;
      hostAddressFamily = AF_UNSPEC;

      // clean up pendingpings

      if (self.pendingPings != nil) {
        [_pendingPingsLock lock];
        [self.pendingPings removeAllObjects];
        [_pendingPingsLock unlock];
      }
      self.pendingPings = nil;

      if (self.timeoutTimers != nil) {
        [self.timeoutTimersLock lock];
        NSDictionary *timersSnapshot = [self.timeoutTimers copy];
        for (NSNumber *key in timersSnapshot) {
          NSTimer *timer = timersSnapshot[key];
          [timer invalidate];
        }

        [self.timeoutTimers removeAllObjects];
        self.timeoutTimers = nil;
        [self.timeoutTimersLock unlock];
      }

      self.payloadTemplate = nil;

      // reset seq number
      self.nextSequenceNumber = 0;

      // Clear setup completion time to ensure fresh grace period on next setup
      self.setupCompletionTime = nil;

      self.isStopped = YES;
    }
  }
}

#pragma mark - util

- (BOOL)address:(const struct sockaddr_storage *)address
    matchesHostData:(NSData *)hostData {
  if (address == NULL || hostData == nil ||
      hostData.length < sizeof(struct sockaddr)) {
    return NO;
  }

  const struct sockaddr *expectedSockAddr = hostData.bytes;
  if (expectedSockAddr == NULL ||
      expectedSockAddr->sa_family != address->ss_family) {
    return NO;
  }

  switch (address->ss_family) {
  case AF_INET: {
    if (hostData.length < sizeof(struct sockaddr_in)) {
      return NO;
    }
    const struct sockaddr_in *received = (const struct sockaddr_in *)address;
    const struct sockaddr_in *expected =
        (const struct sockaddr_in *)expectedSockAddr;
    return (memcmp(&received->sin_addr, &expected->sin_addr,
                   sizeof(struct in_addr)) == 0);
  } break;
  case AF_INET6: {
    if (hostData.length < sizeof(struct sockaddr_in6)) {
      return NO;
    }
    const struct sockaddr_in6 *received = (const struct sockaddr_in6 *)address;
    const struct sockaddr_in6 *expected =
        (const struct sockaddr_in6 *)expectedSockAddr;
    return (memcmp(&received->sin6_addr, &expected->sin6_addr,
                   sizeof(struct in6_addr)) == 0);
  } break;
  default:
    return NO;
  }
}

- (NSString *)stringForAddress:(const struct sockaddr_storage *)address {
  if (address == NULL) {
    return nil;
  }

  char buffer[INET6_ADDRSTRLEN] = {0};
  const void *source = NULL;

  switch (address->ss_family) {
  case AF_INET: {
    const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
    source = &ipv4->sin_addr;
  } break;
  case AF_INET6: {
    const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;
    source = &ipv6->sin6_addr;
  } break;
  default:
    return nil;
  }

  if (inet_ntop(address->ss_family, source, buffer, sizeof(buffer)) == NULL) {
    return nil;
  }

  return [NSString stringWithUTF8String:buffer];
}

- (NSString *)stringFromSockaddrData:(NSData *)addressData {
  if (addressData == nil || addressData.length < sizeof(struct sockaddr)) {
    return nil;
  }

  struct sockaddr_storage storage;
  memset(&storage, 0, sizeof(storage));
  memcpy(&storage, addressData.bytes, MIN(sizeof(storage), addressData.length));

  return [self stringForAddress:&storage];
}

static uint16_t in_cksum(const void *buffer, size_t bufferLen)
// This is the standard BSD checksum code, modified to use modern types.
{
  size_t bytesLeft;
  int32_t sum;
  const uint16_t *cursor;
  union {
    uint16_t us;
    uint8_t uc[2];
  } last;
  uint16_t answer;

  bytesLeft = bufferLen;
  sum = 0;
  cursor = buffer;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (bytesLeft > 1) {
    sum += *cursor;
    cursor += 1;
    bytesLeft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (bytesLeft == 1) {
    last.uc[0] = *(const uint8_t *)cursor;
    last.uc[1] = 0;
    sum += last.us;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = (uint16_t)~sum;            /* truncate to 16 bits */

  return answer;
}

+ (NSString *)sourceAddressInPacket:(NSData *)packet {
  // Returns the source address of the IP packet

  const struct GBIPHeader *ipPtr;
  const uint8_t *sourceAddress;

  if ([packet length] >= sizeof(GBIPHeader)) {
    ipPtr = (const GBIPHeader *)[packet bytes];

    sourceAddress =
        ipPtr->sourceAddress; // dont need to swap byte order those cuz theyre
                              // the smallest atomic unit (1 byte)
    NSString *ipString = [NSString
        stringWithFormat:@"%d.%d.%d.%d", sourceAddress[0], sourceAddress[1],
                         sourceAddress[2], sourceAddress[3]];

    return ipString;
  } else {
    return nil;
  }
}

+ (NSUInteger)icmp4HeaderOffsetInPacket:(NSData *)packet
// Returns the offset of the ICMPHeader within an IP packet.
{
  NSUInteger result;
  const struct GBIPHeader *ipPtr;
  size_t ipHeaderLength;

  result = NSNotFound;
  if ([packet length] >= (sizeof(GBIPHeader) + sizeof(GBICMPHeader))) {
    ipPtr = (const GBIPHeader *)[packet bytes];
    assert((ipPtr->versionAndHeaderLength & 0xF0) == 0x40); // IPv4
    assert(ipPtr->protocol == 1);                           // ICMP
    ipHeaderLength = (ipPtr->versionAndHeaderLength & 0x0F) * sizeof(uint32_t);
    if ([packet length] >= (ipHeaderLength + sizeof(GBICMPHeader))) {
      result = ipHeaderLength;
    }
  }
  return result;
}

+ (const struct GBICMPHeader *)icmp4InPacket:(NSData *)packet
// See comment in header.
{
  const struct GBICMPHeader *result;
  NSUInteger icmpHeaderOffset;

  result = nil;
  icmpHeaderOffset = [self icmp4HeaderOffsetInPacket:packet];
  if (icmpHeaderOffset != NSNotFound) {
    result = (const struct GBICMPHeader *)(((const uint8_t *)[packet bytes]) +
                                           icmpHeaderOffset);
  }
  return result;
}

- (BOOL)isValidPingResponsePacket:(NSMutableData *)packet {
  BOOL result = NO;

  if (packet != nil && self.isReady == YES) {
    switch (hostAddressFamily) {
    case AF_INET: {
      result = [self isValidPing4ResponsePacket:packet];
    } break;
    case AF_INET6: {
      result = [self isValidPing6ResponsePacket:packet];
    } break;
    default: {
      // There are reasons why we might receive an invalid Ping packet. Handle
      // this condition gracefully instead of crashing. assert(NO);
      result = NO;
    } break;
    }
  }
  return result;
}

// Returns true if the packet looks like a valid ping response packet destined
// for us.
- (BOOL)isValidPing4ResponsePacket:(NSMutableData *)packet {
  BOOL result;
  NSUInteger icmpHeaderOffset;
  GBICMPHeader *icmpPtr;
  uint16_t receivedChecksum;
  uint16_t calculatedChecksum;

  result = NO;

  icmpHeaderOffset = [[self class] icmp4HeaderOffsetInPacket:packet];
  if (icmpHeaderOffset != NSNotFound) {
    icmpPtr = (struct GBICMPHeader *)(((uint8_t *)[packet mutableBytes]) +
                                      icmpHeaderOffset);

    receivedChecksum = icmpPtr->checksum;
    icmpPtr->checksum = 0;
    calculatedChecksum = in_cksum(icmpPtr, [packet length] - icmpHeaderOffset);
    icmpPtr->checksum = receivedChecksum;

    uint16_t packetIdentifier = OSSwapBigToHostInt16(icmpPtr->identifier);
    uint16_t packetSeqNo = OSSwapBigToHostInt16(icmpPtr->sequenceNumber);

    if (receivedChecksum == calculatedChecksum) {
      if ((icmpPtr->type == kICMPv4TypeEchoReply) && (icmpPtr->code == 0)) {
        if (packetIdentifier == self.identifier) {
          if (packetSeqNo < self.nextSequenceNumber) {
            result = YES;
          } else if (self.debug) {
            // Sequence number is >= nextSequenceNumber (shouldn't happen during
            // normal operation)
            NSLog(@"GBPing: Packet seq %u >= nextSeq %lu (future packet?)",
                  packetSeqNo, (unsigned long)self.nextSequenceNumber);
          }
        } else if (self.debug) {
          // Identifier mismatch - likely from a previous GBPing instance
          NSLog(@"GBPing: Identifier mismatch - packet: %u, expected: %u "
                @"(stale packet from previous session)",
                packetIdentifier, self.identifier);
        }
      } else if (self.debug && icmpPtr->type != kICMPv4TypeEchoRequest) {
        // Not an echo reply - might be TTL exceeded or other ICMP type
        NSLog(@"GBPing: Non-reply ICMP type %d code %d received", icmpPtr->type,
              icmpPtr->code);
      }
    } else if (self.debug) {
      NSLog(@"GBPing: Checksum mismatch - received: %u, calculated: %u",
            receivedChecksum, calculatedChecksum);
    }
  } else {
    NSLog(@"GBPing error: ICMP header not found.");
  }

  return result;
}

// Returns true if the IPv6 packet looks like a valid ping response packet
// destined for us.
- (BOOL)isValidPing6ResponsePacket:(NSMutableData *)packet {
  BOOL result;
  const GBICMPHeader *icmpPtr;

  result = NO;

  if (packet.length >= sizeof(*icmpPtr)) {
    icmpPtr = packet.bytes;

    if ((icmpPtr->type == kICMPv6TypeEchoReply) && (icmpPtr->code == 0)) {
      if (OSSwapBigToHostInt16(icmpPtr->identifier) == self.identifier) {
        if (OSSwapBigToHostInt16(icmpPtr->sequenceNumber) <
            self.nextSequenceNumber) {
          result = YES;
        }
      }
    }
  }

  return result;
}

- (NSData *)generateDataWithLength:(NSUInteger)length {
  NSMutableData *data = [NSMutableData dataWithLength:length];
  if (length > 0) {
    memset(data.mutableBytes, 7, length);
  }

  return data;
}

- (NSData *)currentPayloadData {
  NSUInteger size = self.payloadSize;

  @synchronized(self) {
    if (self.payloadTemplate == nil || self.payloadTemplate.length != size) {
      self.payloadTemplate = [self generateDataWithLength:size];
    }

    return self.payloadTemplate;
  }
}

- (void)_invokeTimeoutCallback:(NSTimer *)timer {
  dispatch_block_t callback = timer.userInfo;
  if (callback) {
    callback();
  }
}

- (NSData *)pingPacketWithType:(uint8_t)type
                       payload:(NSData *)payload
              requiresChecksum:(BOOL)requiresChecksum {
  NSMutableData *packet;
  GBICMPHeader *icmpPtr;

  packet = [NSMutableData dataWithLength:sizeof(*icmpPtr) + payload.length];
  assert(packet != nil);

  icmpPtr = packet.mutableBytes;
  icmpPtr->type = type;
  icmpPtr->code = 0;
  icmpPtr->checksum = 0;
  icmpPtr->identifier = OSSwapHostToBigInt16(self.identifier);
  icmpPtr->sequenceNumber = OSSwapHostToBigInt16(self.nextSequenceNumber);
  memcpy(&icmpPtr[1], [payload bytes], [payload length]);

  if (requiresChecksum) {
    // The IP checksum routine returns a 16-bit number that's already in correct
    // byte order (due to wacky 1's complement maths), so we just put it into
    // the packet as a 16-bit unit.

    icmpPtr->checksum = in_cksum(packet.bytes, packet.length);
  }

  return packet;
}

//- (sa_family_t)hostAddressFamily {
//  sa_family_t result;
//
//  result = AF_UNSPEC;
//  if (self.hostAddress != nil &&
//      self.hostAddress.bytes != nil &&
//      self.hostAddress.length >= sizeof(struct sockaddr)) {
//    result = ((const struct sockaddr *)self.hostAddress.bytes)->sa_family;
//  }
//  return result;
//}

#pragma mark - memory

- (id)init {
  if (self = [super init]) {
    dispatch_queue_attr_t attr = dispatch_queue_attr_make_with_qos_class(
        DISPATCH_QUEUE_SERIAL, QOS_CLASS_UTILITY, 0);
    self.setupQueue = dispatch_queue_create("GBPing setup queue", attr);
    self.isStopped = YES;
    self.identifier = arc4random();
    self.timeoutTimersLock = [[NSLock alloc] init];
    self.receiveBuffer = [NSMutableData dataWithLength:65535];
  }

  return self;
}

- (void)dealloc {
  self.delegate = nil;
  self.host = nil;
  self.timeoutTimers = nil;
  [_pendingPingsLock lock];
  self.pendingPings = nil;
  [_pendingPingsLock unlock];
  self.hostAddress = nil;
  hostAddressFamily = AF_UNSPEC;
  _pendingPingsLock = nil;
  self.timeoutTimersLock = nil;
  self.payloadTemplate = nil;
  self.receiveBuffer = nil;

  // clean up socket to be sure
  if (self.socket) {
    close(self.socket);
    self.socket = 0;
  }
}

@end
